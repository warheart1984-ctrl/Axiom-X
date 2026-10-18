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

use x86_64::structures::paging::PageTableFlags;

use axiom_x_arch::process::{Process, ProcessState};

use crate::{alloc_boot_frame, alloc_kernel_stack, frames_in_use, map_page_in, new_address_space, serial_puts};

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

/// Top of every ELF program's user stack (stack grows down; the page below
/// the lowest mapped stack page is left unmapped).
const ELF_STACK_TOP: u64 = 0x0000_0080_4000_0000;
const ELF_STACK_PAGES: u64 = 4;

/// The user-space init program the kernel starts each round; it spawns the
/// other boot modules itself through `AX_SPAWN_MODULE` and reaps them with
/// `wait4`.
const USER_INIT_MODULE: &str = "elf-init";

/// Map an embedded blob (one code page + one stack page) into a new
/// address space and start it.
fn spawn_embedded(prog: &UserProgram) {
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
    map_page_in(root, USER_STACK_VA, stack, user_rw());

    let kstack = alloc_kernel_stack();
    let pid = axiom_x_arch::sched::spawn_user_process(USER_CODE_VA, USER_STACK_VA + 4096, kstack, root)
        .expect("create user process");
    serial_print!(
        "[kernel] spawned '{}' as pid {}: {} bytes embedded, PML4 {:#x}\n",
        prog.name, pid, len, root.start_address().as_u64()
    );
}

fn user_rw() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE
}

/// Validate, load and start an ELF image as a child of `parent` (`None` =
/// the kernel). Returns the PID or a negative errno; a rejected image never
/// becomes a process and leaves nothing allocated.
fn spawn_elf(name: &str, bytes: &[u8], parent: Option<u32>) -> Result<u32, i64> {
    use axiom_x_arch::syscall::ENOEXEC;
    const ENOMEM: i64 = 12;
    let image = crate::elf::parse(bytes).map_err(|why| {
        serial_print!("[kernel] ELF '{}' rejected: {}\n", name, why);
        -ENOEXEC
    })?;
    let root = new_address_space();
    let pages = match crate::elf::load(root, bytes, &image) {
        Ok(p) => p,
        Err(why) => {
            serial_print!("[kernel] ELF '{}' failed to load: {}\n", name, why);
            crate::free_address_space(root);
            return Err(-ENOMEM);
        }
    };
    for i in 1..=ELF_STACK_PAGES {
        let f = unsafe { alloc_boot_frame() }.ok_or(-ENOMEM)?.start_address().as_u64();
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, 4096) };
        map_page_in(root, ELF_STACK_TOP - i * 4096, f, user_rw());
    }
    let kstack = alloc_kernel_stack();
    let pid = axiom_x_arch::sched::spawn_user_process(image.entry, ELF_STACK_TOP, kstack, root)
        .map_err(|_| -ENOMEM)?;
    if let Some(mut g) = axiom_x_arch::interrupts::process_table().get_mut(pid) {
        g.get_mut().parent_pid = parent;
    }
    serial_print!(
        "[kernel] loaded ELF '{}' as pid {} (parent {}): {} bytes, {} segments, {} pages, PML4 {:#x}\n",
        name,
        pid,
        parent.map_or(0, |p| p),
        bytes.len(),
        image.segments.len(),
        pages,
        root.start_address().as_u64()
    );
    Ok(pid)
}

/// `AX_SPAWN_MODULE` hook: start the boot module called `name`.
fn spawn_module_hook(name: &str, parent: u32) -> i64 {
    match crate::boot_modules().iter().find(|m| m.name() == name) {
        None => -axiom_x_arch::syscall::ENOENT,
        Some(m) => match spawn_elf(name, m.bytes(), Some(parent)) {
            Ok(pid) => pid as i64,
            Err(e) => e,
        },
    }
}

/// Release hook: free a reaped process's address space and kernel stack.
/// Called from `wait4` (parent's context) or the kernel reaper, never on
/// the dying thread itself, which is standing on both.
fn release_process(p: &Process) -> u64 {
    crate::free_address_space(p.page_table_root) + crate::free_kernel_stack(p.kernel_stack_top)
}

/// Install the hooks the syscall layer needs from the boot crate.
pub fn install_hooks() {
    axiom_x_arch::syscall::set_process_end_hook(on_process_end);
    axiom_x_arch::syscall::set_spawn_hook(spawn_module_hook);
    axiom_x_arch::syscall::set_release_hook(release_process);
}

/// Start one round: every embedded program plus the user-space init.
fn spawn_round() -> usize {
    let mut started = 0;
    for prog in &programs() {
        spawn_embedded(prog);
        started += 1;
    }
    match crate::boot_modules().iter().find(|m| m.name() == USER_INIT_MODULE) {
        Some(m) => {
            if spawn_elf(USER_INIT_MODULE, m.bytes(), None).is_ok() {
                started += 1;
            }
        }
        None => serial_print!("[kernel] no '{}' boot module\n", USER_INIT_MODULE),
    }
    started
}

/// True once every process except the caller (kernel init) has ended.
fn all_user_processes_ended() -> bool {
    let me = axiom_x_arch::process::current_pid();
    axiom_x_arch::interrupts::process_table()
        .with_locked(|ps| ps.iter().all(|p| p.pid == me || p.state == ProcessState::Terminated))
}

/// Reap zombies that no user process will `wait4` for: children of the
/// kernel, including orphans re-parented to it when their parent ended.
fn reap() -> (u32, u64) {
    let table = axiom_x_arch::interrupts::process_table();
    let dead: heapless::Vec<u32, 64> = table.with_locked(|ps| {
        ps.iter()
            .filter(|p| p.state == ProcessState::Terminated && p.parent_pid.is_none())
            .map(|p| p.pid)
            .collect()
    });
    let (mut n, mut frames) = (0, 0);
    for pid in dead {
        if let Some(p) = table.remove(pid) {
            frames += release_process(&p);
            n += 1;
        }
    }
    (n, frames)
}

/// Run the whole program set twice, reaping after each round. Equal
/// "frames in use" after both rounds means process teardown, by `wait4`
/// in user space or by the kernel reaper, returns everything allocated.
pub fn run_rounds() {
    let mut after = [0u64; 2];
    for round in 0..2 {
        let before = frames_in_use();
        serial_print!("[kernel] === round {}: frames in use {} ===\n", round + 1, before);
        let started = spawn_round();
        while !all_user_processes_ended() {
            unsafe { core::arch::asm!("hlt") };
        }
        let (n, freed) = reap();
        let left = axiom_x_arch::interrupts::process_table().count();
        after[round] = frames_in_use();
        serial_print!(
            "[kernel] round {}: kernel started {}, kernel reaped {} ({} frames); {} process records left; frames in use {} -> {}\n",
            round + 1, started, n, freed, left, before, after[round]
        );
    }
    if after[0] == after[1] {
        serial_print!("[kernel] reclamation check: PASS (frames in use after each round: {})\n", after[1]);
    } else {
        serial_print!("[kernel] reclamation check: FAIL ({} vs {} frames)\n", after[0], after[1]);
    }
}

/// Process-end hook (runs with interrupts off, in the ending process's
/// syscall or fault context); the scheduler picks what runs next.
pub fn on_process_end(pid: u32, parent: Option<u32>, code: i32) {
    let who = parent.map_or(0, |p| p);
    if code >= 0 {
        serial_print!("[kernel] pid {} (parent {}) exited with code {}\n", pid, who, code);
    } else {
        serial_print!("[kernel] pid {} (parent {}) killed by signal {}\n", pid, who, -code);
    }
}
