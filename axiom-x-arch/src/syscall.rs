//! `int 0x80` system call path (ring 3 -> ring 0).
//!
//! ABI (Linux x86_64 numbering, legacy-gate transport):
//! RAX = number, RDI/RSI/RDX = args 0-2, result in RAX (negative errno on
//! failure). Implemented: `write` (1) to fd 1/2 (COM1), `exit` (60).
//! Everything else returns `-ENOSYS`.
//!
//! User pointers are validated by walking the active page tables: every page
//! of the buffer must be present and user-accessible at every level, so a
//! kernel or unmapped address gets `-EFAULT` instead of faulting the kernel.
//!
//! Status: `partial` — exercised by the ring-3 programs at boot in QEMU.

use spin::Once;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};

use crate::process::{current_pid, ProcessState, SyscallRecord};
use crate::sched::TrapFrame;

pub const SYS_WRITE: u64 = 1;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
/// Axiom-X: start a boot module (by name) as a child of the caller.
/// Distinct from the declared `AxSpawn` (511), whose `SpawnRequest` ABI
/// (caller-chosen entry/stack) is not implemented.
pub const SYS_AX_SPAWN_MODULE: u64 = 520;
/// Axiom-X (declared in axiom-x-sys as `AxGetEvidence`): read ledger record
/// `seq` into a user buffer; `seq = u64::MAX` returns the record count.
pub const SYS_AX_GET_EVIDENCE: u64 = 501;

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 38;

/// Signal number recorded when the kernel kills a process for a fault.
/// Exit codes are stored as `code >= 0` for `exit(code)` and `-signal`
/// for a kill, and reported by `wait4` in the Linux status encoding.
pub const SIGSEGV: i32 = 11;

/// Longest module name accepted by `AX_SPAWN_MODULE`.
pub const MAX_MODULE_NAME: u64 = 64;

/// Exclusive upper bound of the canonical lower (user) half.
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
/// Largest single `write`; keeps one syscall from monopolising the CPU.
pub const MAX_WRITE_LEN: u64 = 4096;

/// Notified when a user process ends, normally (`exit`) or because the
/// kernel killed it (fault in ring 3). The scheduler then picks what runs.
pub type ProcessEndHook = fn(pid: u32, parent: Option<u32>, code: i32);

/// Creates a process from a named boot module as a child of `parent`
/// holding `rights` (already checked to be a subset of the parent's);
/// returns its PID or a negative errno (`-ENOENT`, `-ENOEXEC`, ...).
pub type SpawnHook = fn(name: &str, parent: u32, rights: axiom_x_capability::Rights) -> i64;

/// Frees what a reaped process owned (address space, kernel stack);
/// returns frames freed. Implemented by the boot crate, which owns memory.
pub type ReleaseHook = fn(&crate::process::Process) -> u64;

static PROCESS_END_HOOK: Once<ProcessEndHook> = Once::new();
static SPAWN_HOOK: Once<SpawnHook> = Once::new();
static RELEASE_HOOK: Once<ReleaseHook> = Once::new();

pub fn set_process_end_hook(hook: ProcessEndHook) {
    PROCESS_END_HOOK.call_once(|| hook);
}

pub fn set_spawn_hook(hook: SpawnHook) {
    SPAWN_HOOK.call_once(|| hook);
}

pub fn set_release_hook(hook: ReleaseHook) {
    RELEASE_HOOK.call_once(|| hook);
}

/// Free a removed process's resources through the release hook.
pub fn release(proc: &crate::process::Process) -> u64 {
    RELEASE_HOOK.get().map_or(0, |h| h(proc))
}

/// Mark the current process terminated and notify the end hook. The caller
/// must then switch away (the thread must never be resumed).
pub fn mark_ended(code: i32) {
    let pid = current_pid();
    // One critical section: become a zombie, hand children to the kernel
    // reaper, and wake a parent blocked in wait4 for us.
    let parent = crate::interrupts::process_table().with_locked_mut(|ps| {
        let mut parent = None;
        if let Some(p) = ps.iter_mut().find(|p| p.pid == pid) {
            p.state = ProcessState::Terminated;
            p.exit_code = Some(code);
            parent = p.parent_pid;
        }
        for child in ps.iter_mut().filter(|c| c.parent_pid == Some(pid)) {
            child.parent_pid = None;
        }
        if let Some(pp) = parent {
            if let Some(w) = ps.iter_mut().find(|q| q.pid == pp) {
                if w.state == ProcessState::Blocked && (w.waiting_for == -1 || w.waiting_for == pid as i64) {
                    w.waiting_for = 0;
                    w.state = ProcessState::Runnable;
                }
            }
        }
        parent
    });
    crate::governance::record_exit(pid, code);
    if let Some(hook) = PROCESS_END_HOOK.get() {
        hook(pid, parent, code);
    }
}

/// Linux `wait4` status word for a stored exit code (see `SIGSEGV`).
pub fn wait_status(code: i32) -> i32 {
    if code >= 0 { (code & 0xff) << 8 } else { (-code) & 0x7f }
}

/// IDT entry for vector 0x80. The gate must have DPL 3 so ring 3 may use it.
/// Same entry/exit path as the timer, so `exit` can switch threads.
#[unsafe(naked)]
pub unsafe extern "C" fn int80_entry() -> ! {
    crate::sched::trap_entry!(syscall_dispatch);
}

/// Returns the RSP of the frame to resume: this one, or another thread's
/// after `exit`.
extern "C" fn syscall_dispatch(frame_rsp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_rsp as *mut TrapFrame) };
    let (nr, a0, a1, a2) = (frame.rax, frame.rdi, frame.rsi, frame.rdx);
    let pid = current_pid();

    // No dispatch without the right it requires.
    if let Some(need) = crate::governance::required_right(nr) {
        if !crate::governance::rights_of(pid).contains(need) {
            crate::governance::record_syscall(pid, nr, a0, -EPERM, false);
            log_syscall(pid, name_of(nr), nr, a0, -EPERM);
            frame.rax = (-EPERM) as u64;
            return frame_rsp;
        }
    }

    let result: i64 = match nr {
        SYS_WRITE => sys_write(a0, a1, a2),
        SYS_EXIT => {
            log_syscall(pid, "exit", nr, a0, 0);
            mark_ended(a0 as i32);
            return switch_away(frame_rsp);
        }
        SYS_GETPID => pid as i64,
        SYS_SCHED_YIELD => {
            frame.rax = 0;
            crate::governance::record_syscall(pid, nr, 0, 0, true);
            return switch_away(frame_rsp);
        }
        SYS_NANOSLEEP => match sleep_ticks(a0) {
            Ok(ticks) => {
                // Result is written now: the frame is resumed after the wake.
                frame.rax = 0;
                log_syscall(pid, "nanosleep", nr, ticks, 0);
                crate::governance::record_block(pid, nr, ticks);
                crate::sched::block_current_for(ticks);
                return switch_away(frame_rsp);
            }
            Err(e) => e,
        },
        SYS_AX_SPAWN_MODULE => sys_spawn_module(pid, a0, a1, a2),
        SYS_AX_GET_EVIDENCE => sys_get_evidence(a0, a1, a2),
        SYS_WAIT4 => match sys_wait4(pid, a0 as i64, a1) {
            WaitOutcome::Done(r) => r,
            WaitOutcome::Block => {
                crate::governance::record_block(pid, nr, a0);
                // Restart semantics: when woken, re-execute the 2-byte
                // `int 0x80` (RAX still holds the syscall number), which
                // then finds the zombie. No half-done state survives a block.
                frame.rip -= 2;
                return switch_away(frame_rsp);
            }
        },
        _ => -ENOSYS,
    };

    if let Some(mut guard) = crate::interrupts::process_table().get_mut(pid) {
        guard.get_mut().last_syscall = Some(SyscallRecord {
            number: nr,
            args: [a0, a1, a2, frame.r10, frame.r8, frame.r9],
            return_value: result,
            timestamp_ns: 0,
        });
    }
    crate::governance::record_syscall(pid, nr, a0, result, true);
    // Evidence reads are ledgered like every call, but not echoed to the
    // console: an audit makes hundreds of them.
    if nr != SYS_AX_GET_EVIDENCE {
        log_syscall(pid, name_of(nr), nr, a0, result);
    }
    frame.rax = result as u64;
    frame_rsp
}

/// Copy a module name from user memory and ask the spawn hook to start it,
/// granting the child `rights_bits`, which must be a subset of the parent's.
fn sys_spawn_module(parent: u32, name_ptr: u64, len: u64, rights_bits: u64) -> i64 {
    use axiom_x_capability::Rights;
    let requested = Rights::new(rights_bits);
    let held = crate::governance::rights_of(parent);
    if !held.contains(requested) {
        // Escalation: asking for rights the parent does not hold.
        crate::governance::record_create(parent, 0, requested, false, -EPERM);
        return -EPERM;
    }
    if len == 0 || len > MAX_MODULE_NAME {
        return -EINVAL;
    }
    if !user_range_accessible(name_ptr, len, false) {
        return -EFAULT;
    }
    let mut buf = [0u8; MAX_MODULE_NAME as usize];
    let n = len as usize;
    unsafe { core::ptr::copy_nonoverlapping(name_ptr as *const u8, buf.as_mut_ptr(), n) };
    let Ok(name) = core::str::from_utf8(&buf[..n]) else {
        return -EINVAL;
    };
    let r = match SPAWN_HOOK.get() {
        Some(hook) => hook(name, parent, requested),
        None => -ENOSYS,
    };
    if r > 0 {
        crate::governance::record_create(parent, r as u32, requested, true, r);
    } else {
        crate::governance::record_create(parent, 0, requested, false, r);
    }
    r
}

/// Size of one record as returned by `AX_GET_EVIDENCE`: encoding + digest.
pub const EVIDENCE_RECORD_BYTES: u64 = axiom_x_ledger::RECORD_LEN as u64 + 32;

/// `AX_GET_EVIDENCE(seq, buf, len)`: copy ledger record `seq` (encoded
/// record, then its SHA-256 digest) to `buf`; returns the record count.
fn sys_get_evidence(seq: u64, buf: u64, len: u64) -> i64 {
    if seq == u64::MAX {
        return crate::governance::ledger_summary().0 as i64;
    }
    if len < EVIDENCE_RECORD_BYTES {
        return -EINVAL;
    }
    if !user_range_accessible(buf, EVIDENCE_RECORD_BYTES, true) {
        return -EFAULT;
    }
    let Some((record, digest)) = crate::governance::ledger_get(seq) else {
        return -ENOENT;
    };
    let enc = record.encode();
    unsafe {
        core::ptr::copy_nonoverlapping(enc.as_ptr(), buf as *mut u8, enc.len());
        core::ptr::copy_nonoverlapping(digest.as_ptr(), (buf + enc.len() as u64) as *mut u8, 32);
    }
    crate::governance::ledger_summary().0 as i64
}

enum WaitOutcome {
    Done(i64),
    Block,
}

/// `wait4(pid, *status, ..)`: `pid` = -1 (any child) or a child PID.
/// Reaps a terminated child (frees it via the release hook), writes the
/// status, returns its PID; blocks if children exist but none has ended;
/// `-ECHILD` if there is nothing to wait for.
fn sys_wait4(me: u32, which: i64, status_ptr: u64) -> WaitOutcome {
    if which == 0 || which < -1 {
        return WaitOutcome::Done(-EINVAL); // process groups are not supported
    }
    if status_ptr != 0 && !user_range_accessible(status_ptr, 4, true) {
        return WaitOutcome::Done(-EFAULT);
    }
    let table = crate::interrupts::process_table();
    let (has_child, zombie) = table.with_locked_mut(|ps| {
        let mut has_child = false;
        let mut zombie = None;
        for c in ps.iter() {
            if c.parent_pid == Some(me) && (which == -1 || c.pid as i64 == which) {
                has_child = true;
                if c.state == ProcessState::Terminated {
                    zombie = Some((c.pid, c.exit_code.unwrap_or(0)));
                    break;
                }
            }
        }
        if has_child && zombie.is_none() {
            // Block in the same critical section, so a child cannot end
            // between the check and the block and miss the wake-up.
            if let Some(w) = ps.iter_mut().find(|p| p.pid == me) {
                w.state = ProcessState::Blocked;
                w.waiting_for = which;
            }
        }
        (has_child, zombie)
    });
    match (has_child, zombie) {
        (false, _) => WaitOutcome::Done(-ECHILD),
        (true, None) => WaitOutcome::Block,
        (true, Some((child, code))) => {
            if let Some(p) = table.remove(child) {
                let frames = release(&p);
                crate::governance::record_reap(me, child, frames);
            }
            if status_ptr != 0 {
                unsafe { (status_ptr as *mut i32).write(wait_status(code)) };
            }
            WaitOutcome::Done(child as i64)
        }
    }
}

/// Leave the current thread (ended, sleeping, or yielding) and return the
/// frame of whatever runs next.
fn switch_away(frame_rsp: u64) -> u64 {
    match crate::sched::schedule(frame_rsp) {
        0 => idle_forever(),
        rsp => rsp,
    }
}

/// Validate a user `struct timespec { i64 tv_sec; i64 tv_nsec; }` and
/// convert it to scheduler ticks (rounded up).
fn sleep_ticks(ts_ptr: u64) -> Result<u64, i64> {
    if !user_range_accessible(ts_ptr, 16, false) {
        return Err(-EFAULT);
    }
    let (sec, nsec) = unsafe { (*(ts_ptr as *const i64), *((ts_ptr + 8) as *const i64)) };
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(-EINVAL);
    }
    let ns = (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
    Ok(ns.div_ceil(crate::sched::TICK_NS))
}

/// No thread is runnable: nothing left for the kernel to do.
fn idle_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}

fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd != 1 && fd != 2 {
        return -EBADF;
    }
    let len = len.min(MAX_WRITE_LEN);
    if !user_range_accessible(buf, len, false) {
        return -EFAULT;
    }
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    for &b in bytes {
        crate::serial_write_byte(b);
    }
    len as i64
}

fn name_of(nr: u64) -> &'static str {
    match nr {
        SYS_WRITE => "write",
        SYS_EXIT => "exit",
        SYS_GETPID => "getpid",
        SYS_SCHED_YIELD => "sched_yield",
        SYS_NANOSLEEP => "nanosleep",
        SYS_WAIT4 => "wait4",
        SYS_AX_SPAWN_MODULE => "ax_spawn_module",
        SYS_AX_GET_EVIDENCE => "ax_get_evidence",
        _ => "unknown",
    }
}

/// One evidence line per decision, on the kernel serial console.
fn log_syscall(pid: u32, name: &str, nr: u64, a0: u64, result: i64) {
    use core::fmt::Write;
    let _ = writeln!(
        crate::SerialPort,
        "[syscall] pid={} {}(nr={}, a0={:#x}) -> {}",
        pid, name, nr, a0, result
    );
}

/// True when every byte of `[start, start + len)` lies in the user half and
/// is mapped present + user-accessible (+ writable if `write`) in the
/// current address space.
pub fn user_range_accessible(start: u64, len: u64, write: bool) -> bool {
    if len == 0 {
        return start < USER_SPACE_END;
    }
    let end = match start.checked_add(len) {
        Some(e) if e <= USER_SPACE_END => e,
        _ => return false,
    };
    let mut page = start & !0xFFF;
    while page < end {
        if !user_page_accessible(page, write) {
            return false;
        }
        page += 0x1000;
    }
    true
}

fn user_page_accessible(virt: u64, write: bool) -> bool {
    let mut need = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if write {
        need |= PageTableFlags::WRITABLE;
    }
    // Page tables are reached through the boot identity map (first 1 GiB).
    let mut table = Cr3::read().0.start_address().as_u64() as *const PageTable;
    let shifts = [39u64, 30, 21, 12];
    for (level, shift) in shifts.iter().enumerate() {
        let table_ref: &PageTable = unsafe { &*table };
        let entry = &table_ref[((virt >> shift) & 0x1FF) as usize];
        if !entry.flags().contains(need) {
            return false;
        }
        let is_leaf = level == 3 || (level > 0 && entry.flags().contains(PageTableFlags::HUGE_PAGE));
        if is_leaf {
            return true;
        }
        table = entry.addr().as_u64() as *const PageTable;
    }
    false
}
