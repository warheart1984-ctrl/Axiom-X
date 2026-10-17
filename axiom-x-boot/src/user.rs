//! Ring-3 bring-up: embedded user programs, their address-space mapping, and
//! what runs when each one ends.
//!
//! Two programs run in sequence as separate processes:
//!
//! 1. `hello`: `write(1, "hello from ring 3\n")`, then `write(1, <kernel
//!    pointer>, 8)`, which must return `-EFAULT`; reports the result and
//!    `exit(0)` (exit 1 if the kernel accepted the pointer).
//! 2. `probe`: loads from a kernel address directly. The supervisor-only
//!    mapping must page-fault in ring 3, and the kernel must kill the process
//!    (code 139) instead of panicking. Its `exit(2)` must never run.
//!
//! Both share the kernel PML4 (no per-process address spaces yet); user pages
//! live at `USER_CODE_VA`/`USER_STACK_VA` in PML4 slot 1, away from the
//! supervisor-only identity map in slot 0.
//!
//! Status: `partial` — ring-3 entry, `int 0x80`, pointer validation and
//! fault isolation are exercised in QEMU; programs are embedded blobs, not ELF.

use core::arch::global_asm;
use core::ptr::addr_of;

use axiom_x_arch::process::{
    context_switch, init_user_process, restore_context, set_current_pid, CpuContext, ProcessState,
};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

use crate::{alloc_boot_frame, map_4kib_page, serial_puts, IDLE_STACK_TOP, KERNEL_PML4};

/// User code page (PML4 index 1: 512 GiB, outside the boot identity map).
const USER_CODE_VA: u64 = 0x0000_0080_0000_0000;
/// User stack page, 1 MiB above the code; stack grows down from page end.
const USER_STACK_VA: u64 = 0x0000_0080_0010_0000;

// Position-independent programs: data is addressed RIP-relatively, so the
// bytes can be copied anywhere.
global_asm!(
    ".section .rodata.user_programs, \"a\"",
    ".global user_hello_start",
    ".global user_hello_end",
    ".global user_probe_start",
    ".global user_probe_end",
    "user_hello_start:",
    // write(1, msg, len)
    "    mov eax, 1",
    "    mov edi, 1",
    "    lea rsi, [rip + uh_msg]",
    "    lea rdx, [rip + uh_msg_end]",
    "    sub rdx, rsi",
    "    int 0x80",
    // write(1, kernel image, 8) must be refused with -EFAULT (-14)
    "    mov eax, 1",
    "    mov edi, 1",
    "    movabs rsi, 0xFFFF800000100000",
    "    mov edx, 8",
    "    int 0x80",
    "    cmp rax, -14",
    "    jne uh_fail",
    "    mov eax, 1",
    "    mov edi, 1",
    "    lea rsi, [rip + uh_ok]",
    "    lea rdx, [rip + uh_ok_end]",
    "    sub rdx, rsi",
    "    int 0x80",
    "    xor edi, edi",
    "    jmp uh_exit",
    "uh_fail:",
    "    mov edi, 1",
    "uh_exit:",
    "    mov eax, 60",
    "    int 0x80",
    "uh_hang:",
    "    jmp uh_hang",
    "uh_msg: .ascii \"hello from ring 3\\n\"",
    "uh_msg_end:",
    "uh_ok: .ascii \"ring 3: kernel pointer refused with -EFAULT\\n\"",
    "uh_ok_end:",
    "user_hello_end:",
    "user_probe_start:",
    // Direct load from a supervisor-only kernel page: must #PF from ring 3.
    "    movabs rax, 0xFFFF800000100000",
    "    mov rax, [rax]",
    // Only reached if isolation is broken.
    "    mov eax, 60",
    "    mov edi, 2",
    "    int 0x80",
    "up_hang:",
    "    jmp up_hang",
    "user_probe_end:",
);

extern "C" {
    static user_hello_start: u8;
    static user_hello_end: u8;
    static user_probe_start: u8;
    static user_probe_end: u8;
}

struct UserProgram {
    name: &'static str,
    start: *const u8,
    end: *const u8,
}

fn programs() -> [UserProgram; 2] {
    unsafe {
        [
            UserProgram { name: "hello", start: addr_of!(user_hello_start), end: addr_of!(user_hello_end) },
            UserProgram { name: "probe", start: addr_of!(user_probe_start), end: addr_of!(user_probe_end) },
        ]
    }
}

/// Index of the next program to start (single CPU, only touched with the
/// current process ending or from init, so no lock is needed).
static mut NEXT_PROGRAM: usize = 0;

/// Physical frames backing the user pages, allocated once and reused.
static mut USER_FRAMES: Option<(u64, u64)> = None;

/// Map the user code + stack pages (once) and return their physical frames.
unsafe fn user_frames() -> (u64, u64) {
    if let Some(f) = USER_FRAMES {
        return f;
    }
    let pml4 = KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64()
        as *mut x86_64::structures::paging::PageTable;
    let code = alloc_boot_frame().expect("frame for user code").start_address().as_u64();
    let stack = alloc_boot_frame().expect("frame for user stack").start_address().as_u64();
    // Code: user, read + execute (not writable). Stack: user, RW, no-exec.
    map_4kib_page(pml4, USER_CODE_VA, code, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
    map_4kib_page(
        pml4,
        USER_STACK_VA,
        stack,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
    );
    USER_FRAMES = Some((code, stack));
    (code, stack)
}

/// Load the next program into the user pages and enter it in ring 3.
/// Returns only if every program has already run.
pub fn run_next_program() {
    let table = axiom_x_arch::interrupts::process_table();
    let progs = programs();
    let idx = unsafe { NEXT_PROGRAM };
    let Some(prog) = progs.get(idx) else { return };
    unsafe { NEXT_PROGRAM = idx + 1 };

    let len = prog.end as usize - prog.start as usize;
    assert!(len <= 4096, "user program larger than one page");
    unsafe {
        let (code, stack) = user_frames();
        // Frames are reached through the identity map; code is not
        // user-writable, so the kernel writes it here.
        core::ptr::write_bytes(code as *mut u8, 0xCC, 4096); // int3 filler
        core::ptr::copy_nonoverlapping(prog.start, code as *mut u8, len);
        core::ptr::write_bytes(stack as *mut u8, 0, 4096);
    }

    let pml4 = unsafe { KERNEL_PML4.expect("PML4 not initialized") };
    let pid = init_user_process(
        table,
        USER_CODE_VA,
        VirtAddr::new(USER_STACK_VA + 4096),
        axiom_x_arch::gdt::ring0_stack_top(),
        pml4,
    )
    .expect("create user process");
    serial_print!(
        "[kernel] starting user program '{}' as pid {} ({} bytes at {:#x}, ring 3)\n",
        prog.name, pid, len, USER_CODE_VA
    );
    context_switch(table, pid);
}

/// Process-end hook: report, then start the next program or go idle.
pub fn on_process_end(pid: u32, code: i32) -> ! {
    serial_print!("[kernel] pid {} ended with code {}\n", pid, code);
    run_next_program();

    serial_puts("[kernel] all user programs finished; idling\n");
    let ctx = CpuContext::new_kernel(
        post_user_idle as *const () as u64,
        IDLE_STACK_TOP,
        unsafe { KERNEL_PML4.expect("PML4").start_address().as_u64() },
    );
    set_current_pid(0);
    unsafe { restore_context(&ctx) }
}

/// Mark init as no longer runnable before handing the CPU to user programs:
/// init's context is never saved, so it must not be scheduled again.
pub fn park_init(init_pid: u32) {
    if let Some(mut guard) = axiom_x_arch::interrupts::process_table().get_mut(init_pid) {
        guard.get_mut().state = ProcessState::Blocked;
    }
}

/// Kernel idle thread after the user programs: proves timer interrupts and
/// the kernel keep running once ring 3 is done.
extern "C" fn post_user_idle() -> ! {
    let mut wakes: u64 = 0;
    loop {
        unsafe { core::arch::asm!("hlt") };
        wakes += 1;
        if wakes % 100 == 0 {
            serial_print!("  idle heartbeat: {} timer wakes\n", wakes);
        }
    }
}
