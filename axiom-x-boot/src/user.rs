//! Ring-3 programs: embedded user binaries started as concurrent processes.
//!
//! Each program gets its own address space (private PML4 user slot, shared
//! kernel half), its own guarded kernel stack, and is mapped at the *same*
//! user virtual address, so they can only coexist if address spaces really
//! are per-process. They all run at once under the preemptive scheduler:
//!
//! 1. `hello`: `write(1, "hello from ring 3\n")`, then `write(1, <kernel
//!    pointer>, 8)`, which must return `-EFAULT`; reports it and `exit(0)`.
//! 2. `probe`: loads from a kernel address directly; the supervisor-only
//!    mapping must page-fault in ring 3 and the kernel kills it (code 139).
//! 3. `spin-A`, 4. `spin-B`: busy loops that never yield; each prints a tick
//!    5 times then exits. Interleaved A/B ticks can only come from timer
//!    preemption, since neither ever blocks or yields.
//!
//! Status: `partial` — exercised in QEMU; programs are embedded blobs, not ELF.

use core::arch::global_asm;
use core::ptr::addr_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use x86_64::structures::paging::PageTableFlags;

use crate::{alloc_boot_frame, alloc_kernel_stack, map_page_in, new_address_space, serial_puts};

/// User code page (PML4 slot 1), identical in every process.
const USER_CODE_VA: u64 = 0x0000_0080_0000_0000;
/// User stack page, 1 MiB above the code; stack grows down from page end.
const USER_STACK_VA: u64 = 0x0000_0080_0010_0000;

/// Busy-loop iterations between spinner ticks (several 10 ms slices in QEMU).
macro_rules! spin_program {
    ($tag:literal) => {
        concat!(
            ".global user_spin_", $tag, "_start\n",
            ".global user_spin_", $tag, "_end\n",
            "user_spin_", $tag, "_start:\n",
            "    mov r12d, 5\n",
            "spin_", $tag, "_loop:\n",
            "    mov ecx, 4000000\n",
            "spin_", $tag, "_busy:\n",
            "    dec ecx\n",
            "    jnz spin_", $tag, "_busy\n",
            "    mov eax, 1\n",
            "    mov edi, 1\n",
            "    lea rsi, [rip + spin_", $tag, "_msg]\n",
            "    lea rdx, [rip + spin_", $tag, "_msg_end]\n",
            "    sub rdx, rsi\n",
            "    int 0x80\n",
            "    dec r12d\n",
            "    jnz spin_", $tag, "_loop\n",
            "    mov eax, 60\n",
            "    xor edi, edi\n",
            "    int 0x80\n",
            "spin_", $tag, "_hang:\n",
            "    jmp spin_", $tag, "_hang\n",
            "spin_", $tag, "_msg: .ascii \"[user ", $tag, "] tick\\n\"\n",
            "spin_", $tag, "_msg_end:\n",
            "user_spin_", $tag, "_end:\n",
        )
    };
}

// Position-independent programs: data is addressed RIP-relatively, so the
// bytes can be copied to any page.
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
    spin_program!("A"),
    spin_program!("B"),
);

extern "C" {
    static user_hello_start: u8;
    static user_hello_end: u8;
    static user_probe_start: u8;
    static user_probe_end: u8;
    static user_spin_A_start: u8;
    static user_spin_A_end: u8;
    static user_spin_B_start: u8;
    static user_spin_B_end: u8;
}

struct UserProgram {
    name: &'static str,
    start: *const u8,
    end: *const u8,
}

fn programs() -> [UserProgram; 4] {
    unsafe {
        [
            UserProgram { name: "hello", start: addr_of!(user_hello_start), end: addr_of!(user_hello_end) },
            UserProgram { name: "probe", start: addr_of!(user_probe_start), end: addr_of!(user_probe_end) },
            UserProgram { name: "spin-A", start: addr_of!(user_spin_A_start), end: addr_of!(user_spin_A_end) },
            UserProgram { name: "spin-B", start: addr_of!(user_spin_B_start), end: addr_of!(user_spin_B_end) },
        ]
    }
}

/// User processes that have not ended yet.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Create every program as its own process; the scheduler starts them.
pub fn spawn_all() {
    let progs = programs();
    // Count them all before the first can run (and end) under preemption.
    LIVE.store(progs.len(), Ordering::SeqCst);
    for prog in progs {
        let len = prog.end as usize - prog.start as usize;
        assert!(len <= 4096, "user program larger than one page");

        let root = new_address_space();
        let code = unsafe { alloc_boot_frame() }.expect("frame for user code").start_address().as_u64();
        let stack = unsafe { alloc_boot_frame() }.expect("frame for user stack").start_address().as_u64();
        unsafe {
            // Frames are written through the identity map: the code page is
            // not user-writable, so the kernel fills it before mapping.
            core::ptr::write_bytes(code as *mut u8, 0xCC, 4096); // int3 filler
            core::ptr::copy_nonoverlapping(prog.start, code as *mut u8, len);
            core::ptr::write_bytes(stack as *mut u8, 0, 4096);
        }
        // Code: user, read + execute (not writable). Stack: user, RW, no-exec.
        map_page_in(root, USER_CODE_VA, code, PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
        map_page_in(
            root,
            USER_STACK_VA,
            stack,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE,
        );

        let kstack = alloc_kernel_stack();
        let pid = axiom_x_arch::sched::spawn_user_process(USER_CODE_VA, USER_STACK_VA + 4096, kstack, root)
            .expect("create user process");
        serial_print!(
            "[kernel] spawned '{}' as pid {}: {} bytes at {:#x}, PML4 {:#x}, kstack top {:#x}\n",
            prog.name,
            pid,
            len,
            USER_CODE_VA,
            root.start_address().as_u64(),
            kstack.as_u64()
        );
    }
}

/// Process-end hook (runs with interrupts off, in the ending process's
/// syscall or fault context); the scheduler picks what runs next.
pub fn on_process_end(pid: u32, code: i32) {
    serial_print!("[kernel] pid {} ended with code {}\n", pid, code);
    if LIVE.fetch_sub(1, Ordering::SeqCst) == 1 {
        serial_puts("[kernel] all user programs finished\n");
    }
}
