//! Preemptive scheduling on trap frames.
//!
//! Every thread that is not running is represented by a `TrapFrame` saved on
//! its own kernel stack, and `Process::saved_rsp` points at it. The timer
//! (and `int 0x80`) entry stubs push the interrupted thread's registers, ask
//! `schedule` which frame to resume, switch RSP to it, and `iretq`. A switch
//! is therefore just "return through a different frame": the interrupted
//! frame is never abandoned, and kernel threads and ring-3 processes are
//! switched the same way.
//!
//! On a switch the scheduler also loads the next thread's address space
//! (CR3) and points TSS.RSP0 at its kernel stack.
//!
//! Policy: round-robin over `Runnable`/`Running` processes, one 10 ms PIT
//! tick per slice. (`axiom_x_math::scheduler_math` is not wired in: its
//! runnable set was never populated, so it always decided "idle".)
//!
//! Status: `partial` — exercised in QEMU with concurrent ring-3 processes
//! in separate address spaces; single CPU.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use crate::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS};
use crate::interrupts::process_table;
use crate::process::{
    current_pid, init_kernel_process, init_user_process, set_current_pid, ProcessState,
};

/// Registers saved by the entry stubs (lowest address first), followed by the
/// frame the CPU pushes on interrupt entry (64-bit mode always pushes SS:RSP).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrapFrame {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

/// RFLAGS for a new thread: IF=1 (bit 1 is reserved-set).
const INITIAL_RFLAGS: u64 = 0x202;

/// Scheduler ticks since boot (local APIC timer, or the PIT; 10 ms each).
pub static TICKS: AtomicU64 = AtomicU64::new(0);
/// Context switches performed.
pub static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Save all GPRs, call `$handler(frame_rsp) -> resume_rsp`, switch to the
/// returned stack, restore, `iretq`. Used by every entry that may switch.
macro_rules! trap_entry {
    ($handler:path) => {
        ::core::arch::naked_asm!(
            "push rax", "push rbx", "push rcx", "push rdx", "push rsi",
            "push rdi", "push rbp", "push r8", "push r9", "push r10",
            "push r11", "push r12", "push r13", "push r14", "push r15",
            "cld",
            "mov rdi, rsp",
            "call {handler}",
            "mov rsp, rax",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop r11",
            "pop r10", "pop r9", "pop r8", "pop rbp", "pop rdi",
            "pop rsi", "pop rdx", "pop rcx", "pop rbx", "pop rax",
            "iretq",
            handler = sym $handler,
        )
    };
}
pub(crate) use trap_entry;

/// IDT entry for IRQ0 (vector 0x20).
#[unsafe(naked)]
pub unsafe extern "C" fn timer_entry() -> ! {
    trap_entry!(timer_dispatch);
}

extern "C" fn timer_dispatch(frame_rsp: u64) -> u64 {
    let t0 = crate::latency::now();
    crate::latency::on_tick(t0);
    // EOI first: the switch below may not come back to this thread soon.
    crate::apic::tick_eoi();
    TICKS.fetch_add(1, Ordering::Relaxed);
    crate::console::poll_keyboard();
    // The interrupted thread was running, so it can always be resumed.
    let rsp = match schedule(frame_rsp) {
        0 => frame_rsp,
        rsp => rsp,
    };
    crate::latency::end_timer(t0);
    rsp
}

/// Save `frame_rsp` as the current thread's state, pick the next thread, and
/// return the RSP of the frame to resume. Interrupts are off (we are in an
/// interrupt gate). If the process table is busy, keep running the current
/// thread for another tick instead of spinning on the lock.
pub fn schedule(frame_rsp: u64) -> u64 {
    let Some(mut procs) = process_table().try_lock_processes() else {
        return frame_rsp;
    };
    // Wake sleepers whose deadline has passed, and console readers when
    // input is waiting (interrupt handlers only queue bytes).
    // Deadlines are TSC time, not PIT ticks: ticks are lost whenever
    // interrupts stay off longer than a period, the TSC never is.
    let now = crate::clock::monotonic_ns();
    let input = crate::console::has_input();
    for p in procs.iter_mut() {
        if p.state == ProcessState::Blocked && p.wake_at_ns != 0 && p.wake_at_ns <= now {
            p.wake_at_ns = 0;
            p.state = ProcessState::Runnable;
        }
        if p.state == ProcessState::Blocked && p.waiting_for == WAIT_CONSOLE && input {
            p.waiting_for = 0;
            p.state = ProcessState::Runnable;
        }
    }

    let cur = current_pid();
    let cur_idx = procs.iter().position(|p| p.pid == cur);
    if let Some(i) = cur_idx {
        let p = &mut procs[i];
        p.saved_rsp = frame_rsp;
        if p.state == ProcessState::Running {
            p.state = ProcessState::Runnable;
        }
    }

    let n = procs.len();
    let start = cur_idx.map_or(0, |i| i + 1);
    let next = (0..n)
        .map(|k| (start + k) % n)
        .find(|&i| procs[i].state == ProcessState::Runnable && procs[i].saved_rsp != 0);
    let Some(ni) = next else {
        // Nothing else can run: keep the current thread if it still may,
        // otherwise report that there is nothing to resume (0).
        return match cur_idx {
            Some(i) if procs[i].state == ProcessState::Runnable => {
                procs[i].state = ProcessState::Running;
                frame_rsp
            }
            _ => 0,
        };
    };

    let p = &mut procs[ni];
    p.state = ProcessState::Running;
    let (pid, rsp, root, kstack) = (p.pid, p.saved_rsp, p.page_table_root, p.kernel_stack_top);
    drop(procs);

    if pid != cur {
        SWITCHES.fetch_add(1, Ordering::Relaxed);
    }
    activate(pid, root, kstack);
    rsp
}

/// Make `pid` current: address space, ring-0 entry stack, current PID.
fn activate(pid: u32, root: PhysFrame<Size4KiB>, kstack_top: VirtAddr) {
    if Cr3::read().0 != root {
        unsafe { Cr3::write(root, Cr3::read().1) };
    }
    crate::gdt::set_kernel_stack(kstack_top);
    set_current_pid(pid);
}

/// Write an initial `TrapFrame` at the top of `kstack_top` and return its
/// address: resuming it starts the thread at `rip` with an empty register set.
fn initial_frame(kstack_top: VirtAddr, rip: u64, cs: u16, rsp: u64, ss: u16) -> u64 {
    let frame_addr = kstack_top.as_u64() - core::mem::size_of::<TrapFrame>() as u64;
    let frame = TrapFrame {
        rip,
        cs: cs as u64,
        rflags: INITIAL_RFLAGS,
        rsp,
        ss: ss as u64,
        ..TrapFrame::default()
    };
    unsafe { core::ptr::write(frame_addr as *mut TrapFrame, frame) };
    frame_addr
}

fn set_saved_rsp(pid: u32, rsp: u64) {
    let mut guard = process_table().get_mut(pid).expect("new process");
    let p = guard.get_mut();
    p.saved_rsp = rsp;
    p.state = ProcessState::Runnable;
}

/// Make a new user process runnable together with its identity: parent and
/// rights are written in the same critical section that sets `Runnable`, so
/// no tick can schedule it before they hold (it would otherwise run with
/// zero rights, or end before its parent is recorded).
fn activate_new(pid: u32, rsp: u64, parent: Option<u32>, rights: u64, name: &str) {
    let mut guard = process_table().get_mut(pid).expect("new process");
    let p = guard.get_mut();
    p.parent_pid = parent;
    p.rights = rights;
    let n = name.len().min(p.name.len());
    p.name = [0; 16];
    p.name[..n].copy_from_slice(&name.as_bytes()[..n]);
    p.saved_rsp = rsp;
    p.state = ProcessState::Runnable;
}

/// Create a ring-0 thread running `entry` on the kernel stack ending at
/// `kstack_top`, in address space `root`.
pub fn spawn_kernel_thread(
    entry: extern "C" fn() -> !,
    kstack_top: VirtAddr,
    root: PhysFrame<Size4KiB>,
) -> Result<u32, &'static str> {
    let pid = init_kernel_process(process_table(), entry as *const () as u64, kstack_top, root)?;
    let rsp = initial_frame(kstack_top, entry as *const () as u64, KERNEL_CS, kstack_top.as_u64(), KERNEL_DS);
    set_saved_rsp(pid, rsp);
    Ok(pid)
}

/// Create a ring-3 process entering at `entry` with user stack `user_rsp`.
/// `kstack_top` is its private kernel stack (TSS.RSP0 while it runs);
/// `parent` (None = kernel) and `rights` hold from its first instruction.
pub fn spawn_user_process(
    entry: u64,
    user_rsp: u64,
    kstack_top: VirtAddr,
    root: PhysFrame<Size4KiB>,
    parent: Option<u32>,
    rights: crate::governance::Rights,
    name: &str,
) -> Result<u32, &'static str> {
    let pid = init_user_process(process_table(), entry, VirtAddr::new(user_rsp), kstack_top, root)?;
    let rsp = initial_frame(kstack_top, entry, USER_CS, user_rsp, USER_DS);
    activate_new(pid, rsp, parent, rights.bits(), name);
    Ok(pid)
}

/// Start running `pid` on this CPU. Never returns: from here on the CPU only
/// leaves a thread through an interrupt entry.
pub fn start(pid: u32) -> ! {
    let (rsp, root, kstack) = {
        let mut guard = process_table().get_mut(pid).expect("start: unknown pid");
        let p = guard.get_mut();
        p.state = ProcessState::Running;
        (p.saved_rsp, p.page_table_root, p.kernel_stack_top)
    };
    activate(pid, root, kstack);
    unsafe { resume_frame(rsp) }
}

/// `waiting_for` marker: blocked in `read(0)` until console input arrives.
pub const WAIT_CONSOLE: i64 = -2;
/// `waiting_for` marker: blocked on the file-system lock (`fsys`).
pub const WAIT_FS: i64 = -3;

/// Software-interrupt vector kernel code uses to give up the CPU in the
/// middle of a system call (DPL 0: ring 3 cannot raise it). It goes through
/// the same trap-frame path as the timer, so the caller is saved exactly
/// where it stands and resumed there later, as a preempted kernel thread is.
pub const YIELD_VECTOR: u8 = 0x81;

/// IDT entry for `YIELD_VECTOR`.
#[unsafe(naked)]
pub unsafe extern "C" fn yield_entry() -> ! {
    trap_entry!(yield_dispatch);
}

extern "C" fn yield_dispatch(frame_rsp: u64) -> u64 {
    // Nothing else can run (0): resume the caller, which re-checks why it
    // blocked. In practice init, a kernel thread, is always runnable.
    match schedule(frame_rsp) {
        0 => frame_rsp,
        rsp => rsp,
    }
}

/// Block the current thread on `reason` and switch away; returns once it
/// runs again (woken by `wake_all(reason)`, or resumed because nothing else
/// could run, so callers re-check their condition in a loop).
///
/// Call with interrupts **off**: the check that decided to block and the
/// block itself must be atomic, or a wake-up could slip in between and be
/// lost. Returns with interrupts off.
pub fn block_current_on(reason: i64) {
    let pid = current_pid();
    if let Some(mut g) = process_table().get_mut(pid) {
        let p = g.get_mut();
        p.state = ProcessState::Blocked;
        p.waiting_for = reason;
    }
    unsafe { core::arch::asm!("int 0x81") };
    if let Some(mut g) = process_table().get_mut(pid) {
        let p = g.get_mut();
        p.state = ProcessState::Running;
        p.waiting_for = 0;
    }
}

/// Make every thread blocked on `reason` runnable.
pub fn wake_all(reason: i64) {
    process_table().with_locked_mut(|procs| {
        for p in procs.iter_mut() {
            if p.state == ProcessState::Blocked && p.waiting_for == reason {
                p.state = ProcessState::Runnable;
                p.waiting_for = 0;
            }
        }
    });
}

/// PIT period: the scheduler's time unit.
pub const TICK_NS: u64 = 10_000_000;

/// Block the current thread for `ticks` scheduler periods (10 ms each),
/// measured on the TSC; it is woken by the first scheduler pass after the
/// deadline. The caller (a syscall) must then switch away with `schedule`.
pub fn block_current_for(ticks: u64) {
    let wake = crate::clock::monotonic_ns() + ticks.max(1) * TICK_NS;
    if let Some(mut g) = process_table().get_mut(current_pid()) {
        let p = g.get_mut();
        p.wake_at_ns = wake;
        p.state = ProcessState::Blocked;
    }
}

/// End the current thread (it must not run again) and switch to the next.
/// Used from contexts that cannot return through their own frame (a fault
/// in ring 3); the dying thread's kernel-stack frames are simply dropped.
pub fn exit_current(code: i32) -> ! {
    crate::syscall::mark_ended(code);
    let rsp = schedule(0);
    if rsp == 0 {
        // Nothing runnable at all: the kernel has no work left. Halting
        // for good: flush buffered console output first.
        crate::console::serial_sync();
        loop {
            unsafe { core::arch::asm!("cli; hlt") };
        }
    }
    unsafe { resume_frame(rsp) }
}

/// Load a saved `TrapFrame` and `iretq` into it.
#[unsafe(naked)]
unsafe extern "C" fn resume_frame(rsp: u64) -> ! {
    naked_asm!(
        "mov rsp, rdi",
        "pop r15", "pop r14", "pop r13", "pop r12", "pop r11",
        "pop r10", "pop r9", "pop r8", "pop rbp", "pop rdi",
        "pop rsi", "pop rdx", "pop rcx", "pop rbx", "pop rax",
        "iretq",
    );
}
