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

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_CLOCK_GETTIME: u64 = 228;
/// Axiom-X: start a boot module (by name) as a child of the caller.
/// Distinct from the declared `AxSpawn` (511), whose `SpawnRequest` ABI
/// (caller-chosen entry/stack) is not implemented.
pub const SYS_AX_SPAWN_MODULE: u64 = 520;
/// Axiom-X: copy process table entries (`PROC_ENTRY_BYTES` each) to a user
/// buffer: pid, parent, state, rights, name. Needs `Rights::EVIDENCE`.
pub const SYS_AX_PROC_LIST: u64 = 521;
/// Axiom-X: interrupt-latency report as text (`latency::report`) into
/// (buf, len); flags bit 0 = reset the counters afterwards. Needs EVIDENCE.
pub const SYS_AX_LATENCY: u64 = 522;
pub const PROC_ENTRY_BYTES: u64 = 48;

/// Axiom-X file system (whole-file operations; see `fsys`):
/// list (READ): entries of `FS_ENTRY_BYTES`: name[48], size u64, version
/// u64, SHA-256[32]
pub const SYS_AX_FS_LIST: u64 = 530;
/// read(name, len, buf, buflen) (READ): copies up to buflen, returns size
pub const SYS_AX_FS_READ: u64 = 531;
/// write(name, len, data, datalen) (WRITE): create or replace atomically
pub const SYS_AX_FS_WRITE: u64 = 532;
/// delete(name, len) (WRITE)
pub const SYS_AX_FS_DELETE: u64 = 533;
/// install(module, len, path, len) (WRITE): copy a boot module into a file
pub const SYS_AX_FS_INSTALL: u64 = 534;
/// info(buf) (READ): root[32], generation u64, files u32, writable u32,
/// free sectors u64
pub const SYS_AX_FS_INFO: u64 = 535;
/// Axiom-X `AxMmap`: grow the caller's private heap by `a0` bytes;
/// returns the base VA of the new (zeroed, RW+NX) region or -errno.
pub const SYS_AX_MMAP: u64 = 536;
/// Axiom-X `AxEgress`: send `a0`/`a1` request bytes over the governed
/// channel and read the response into `a2`/`a3`; gated by `Rights::NET`.
pub const SYS_AX_EGRESS: u64 = 537;
pub const FS_ENTRY_BYTES: u64 = 96;

/// Echo every syscall decision to the console (the ledger records them
/// regardless). On for the boot self-tests; the shell turns it off.
pub static TRACE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
/// Axiom-X (declared in axiom-x-sys as `AxGetEvidence`): read ledger record
/// `seq` into a user buffer; `seq = u64::MAX` returns the record count.
pub const SYS_AX_GET_EVIDENCE: u64 = 501;

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EFAULT: i64 = 14;
pub const EIO: i64 = 5;
pub const ENOMEM: i64 = 12;
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

/// Bytes of a boot module by name (for `AX_FS_INSTALL`); `None` if absent
/// or not installable (e.g. the signing key).
pub type ModuleBytesHook = fn(name: &str) -> Option<&'static [u8]>;

static MODULE_BYTES_HOOK: Once<ModuleBytesHook> = Once::new();

pub fn set_module_bytes_hook(hook: ModuleBytesHook) {
    MODULE_BYTES_HOOK.call_once(|| hook);
}

static PROCESS_END_HOOK: Once<ProcessEndHook> = Once::new();
static SPAWN_HOOK: Once<SpawnHook> = Once::new();
static RELEASE_HOOK: Once<ReleaseHook> = Once::new();

/// `AX_MMAP` backend: map `len` bytes of zeroed RW/NX memory into `pid`'s
/// address space; returns the base VA or a negative errno.
pub type MmapHook = fn(pid: u32, len: u64) -> i64;
static MMAP_HOOK: Once<MmapHook> = Once::new();

pub fn set_mmap_hook(hook: MmapHook) {
    MMAP_HOOK.call_once(|| hook);
}

/// `AX_EGRESS` backend: send `req_len` request bytes from `req_ptr` (user
/// VA) and return the response into `resp_ptr`/`resp_max`; -errno on failure.
pub type EgressHook = fn(pid: u32, req_ptr: u64, req_len: u64, resp_ptr: u64, resp_max: u64) -> i64;
static EGRESS_HOOK: Once<EgressHook> = Once::new();

pub fn set_egress_hook(hook: EgressHook) {
    EGRESS_HOOK.call_once(|| hook);
}

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
/// after `exit`. Shared by the `int 0x80` gate and the `syscall` entry.
pub(crate) extern "C" fn syscall_dispatch(frame_rsp: u64) -> u64 {
    // The whole call runs with interrupts off (int 0x80 is an interrupt
    // gate): time it for the latency table.
    let t0 = crate::latency::now();
    let nr = unsafe { (*(frame_rsp as *const TrapFrame)).rax };
    let mut t0 = t0;
    let rsp = syscall_dispatch_inner(frame_rsp, &mut t0);
    crate::latency::end_syscall(nr, t0);
    rsp
}

/// Run a long system call body with interrupts **on**: file-system calls
/// and spawn, which do disk I/O, hashing and ELF loading. The thread may be
/// preempted inside `f`, like a kernel thread; shared state it touches is
/// protected by preemption-safe locks (the sleeping FS lock, `IrqMutex`,
/// the interrupt-safe process table, `irq_off` ledger appends). Entry
/// (rights check, argument fetch) and exit (result, trace, evidence) stay
/// interrupts-off. For latency accounting the interrupts-off prefix is
/// recorded here and `t0` restarts for the suffix.
fn preemptible(nr: u64, t0: &mut u64, f: impl FnOnce() -> i64) -> i64 {
    crate::latency::end_syscall(nr, *t0);
    x86_64::instructions::interrupts::enable();
    let r = f();
    x86_64::instructions::interrupts::disable();
    *t0 = crate::latency::now();
    r
}

fn syscall_dispatch_inner(frame_rsp: u64, t0: &mut u64) -> u64 {
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
        SYS_READ => match sys_read(a0, a1, a2) {
            Some(r) => r,
            None => {
                // Nothing to read: block until console input arrives, then
                // re-execute the call (same restart scheme as wait4).
                crate::governance::record_block(pid, nr, a0);
                if let Some(mut g) = crate::interrupts::process_table().get_mut(pid) {
                    let p = g.get_mut();
                    p.state = ProcessState::Blocked;
                    p.waiting_for = crate::sched::WAIT_CONSOLE;
                }
                frame.rip -= 2;
                return switch_away(frame_rsp);
            }
        },
        SYS_AX_PROC_LIST => sys_proc_list(a0, a1),
        SYS_AX_LATENCY => sys_latency(a0, a1, a2),
        SYS_AX_FS_LIST => preemptible(nr, t0, || sys_fs_list(a0, a1)),
        SYS_AX_FS_INFO => preemptible(nr, t0, || sys_fs_info(a0)),
        SYS_AX_FS_READ => {
            let a3 = frame.r10;
            preemptible(nr, t0, || sys_fs_read(a0, a1, a2, a3))
        }
        SYS_AX_FS_WRITE => {
            let a3 = frame.r10;
            preemptible(nr, t0, || sys_fs_write(pid, a0, a1, a2, a3))
        }
        SYS_AX_FS_DELETE => preemptible(nr, t0, || sys_fs_delete(pid, a0, a1)),
        SYS_AX_FS_INSTALL => {
            let a3 = frame.r10;
            preemptible(nr, t0, || sys_fs_install(pid, a0, a1, a2, a3))
        }
        SYS_EXIT => {
            log_syscall(pid, "exit", nr, a0, 0);
            mark_ended(a0 as i32);
            return switch_away(frame_rsp);
        }
        SYS_GETPID => pid as i64,
        SYS_CLOCK_GETTIME => sys_clock_gettime(a0, a1),
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
        SYS_AX_SPAWN_MODULE => preemptible(nr, t0, || sys_spawn_module(pid, a0, a1, a2)),
        SYS_AX_GET_EVIDENCE => sys_get_evidence(a0, a1, a2),
        SYS_AX_MMAP => MMAP_HOOK.get().map_or(-ENOSYS, |h| h(pid, a0)),
        SYS_AX_EGRESS => {
            let a3 = frame.r10;
            preemptible(nr, t0, || {
                EGRESS_HOOK.get().map_or(-ENOSYS, |h| h(pid, a0, a1, a2, a3))
            })
        }
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

/// `clock_gettime(clockid, *timespec)`:
/// - 0 CLOCK_REALTIME: RTC-anchored wall clock, advanced by the TSC
/// - 1 CLOCK_MONOTONIC: TSC since the time origin
/// - 5 CLOCK_REALTIME_COARSE: the RTC itself, read now (1 s resolution)
/// - 6 CLOCK_MONOTONIC_COARSE: PIT ticks x 10 ms (shows whether the PIT
///   keeps up with the TSC and RTC; see `clock::timer_check`)
fn sys_clock_gettime(clock: u64, ts: u64) -> i64 {
    let ns = match clock {
        0 => crate::clock::realtime_ns(),
        1 => crate::clock::monotonic_ns(),
        5 => crate::clock::read_rtc().unix_seconds() * 1_000_000_000,
        6 => crate::sched::TICKS.load(core::sync::atomic::Ordering::Relaxed) * crate::sched::TICK_NS,
        _ => return -EINVAL,
    };
    if !user_range_accessible(ts, 16, true) {
        return -EFAULT;
    }
    unsafe {
        (ts as *mut i64).write((ns / 1_000_000_000) as i64);
        ((ts + 8) as *mut i64).write((ns % 1_000_000_000) as i64);
    }
    0
}

/// Copy a module name from user memory and ask the spawn hook to start it,
/// granting the child `rights_bits`, which must be a subset of the parent's.
fn sys_spawn_module(parent: u32, name_ptr: u64, len: u64, rights_bits: u64) -> i64 {
    use axiom_x_capability::Rights;
    let requested = Rights::new(rights_bits);
    let held = crate::governance::rights_of(parent);
    if name_ptr != 0 && len > 0 && user_range_accessible(name_ptr, 1, false)
        && unsafe { *(name_ptr as *const u8) } == b'/' && !held.contains(Rights::READ)
    {
        // Running a file means reading it.
        crate::governance::record_create(parent, 0, requested, false, -EPERM);
        return -EPERM;
    }
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
    let Some((record, digest)) = crate::governance::ledger_get_any(seq) else {
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
    // Halting for good: flush buffered console output first.
    crate::console::serial_sync();
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}

/// `read(0, buf, len)` from the console: copies what is queued (at least
/// one byte). `None` means nothing is queued yet and the caller must block.
fn sys_read(fd: u64, buf: u64, len: u64) -> Option<i64> {
    if fd != 0 {
        return Some(-EBADF);
    }
    let len = len.min(MAX_WRITE_LEN);
    if len == 0 {
        return Some(0);
    }
    if !user_range_accessible(buf, len, true) {
        return Some(-EFAULT);
    }
    let mut tmp = [0u8; 256];
    let want = (len as usize).min(tmp.len());
    let n = crate::console::read_into(&mut tmp[..want]);
    if n == 0 {
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf as *mut u8, n) };
    Some(n as i64)
}

/// Copy a name (module or path) from user memory: 1..=MAX_MODULE_NAME
/// bytes of UTF-8.
fn copy_name(ptr: u64, len: u64, buf: &mut [u8; MAX_MODULE_NAME as usize]) -> Result<&str, i64> {
    if len == 0 || len > MAX_MODULE_NAME {
        return Err(-EINVAL);
    }
    if !user_range_accessible(ptr, len, false) {
        return Err(-EFAULT);
    }
    let n = len as usize;
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), n) };
    core::str::from_utf8(&buf[..n]).map_err(|_| -EINVAL)
}

fn sys_latency(buf: u64, len: u64, flags: u64) -> i64 {
    let len = len.min(8192);
    if len == 0 || !user_range_accessible(buf, len, true) {
        return -EFAULT;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
    let mut w = crate::latency::BufWriter { buf: out, len: 0 };
    crate::latency::report(&mut w);
    if flags & 1 != 0 {
        crate::latency::reset();
    }
    w.len as i64
}

fn sys_fs_list(buf: u64, max: u64) -> i64 {
    let max = max.min(64);
    if max == 0 {
        return 0;
    }
    if !user_range_accessible(buf, max * FS_ENTRY_BYTES, true) {
        return -EFAULT;
    }
    let r = crate::fsys::for_each_entry(max as usize, |i, e| {
        let mut b = [0u8; FS_ENTRY_BYTES as usize];
        b[0..48].copy_from_slice(&e.name);
        b[48..56].copy_from_slice(&e.size.to_le_bytes());
        b[56..64].copy_from_slice(&e.version.to_le_bytes());
        b[64..96].copy_from_slice(&e.digest);
        // Validated above for `max` entries (current CR3).
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), (buf + i as u64 * FS_ENTRY_BYTES) as *mut u8, b.len()) };
    });
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

fn sys_fs_info(buf: u64) -> i64 {
    if !user_range_accessible(buf, 56, true) {
        return -EFAULT;
    }
    let Some((root, generation, files, free, writable)) = crate::fsys::info() else {
        return -crate::fsys::errno::EIO;
    };
    let mut b = [0u8; 56];
    b[0..32].copy_from_slice(&root);
    b[32..40].copy_from_slice(&generation.to_le_bytes());
    b[40..44].copy_from_slice(&files.to_le_bytes());
    b[44..48].copy_from_slice(&(writable as u32).to_le_bytes());
    b[48..56].copy_from_slice(&free.to_le_bytes());
    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), buf as *mut u8, 56) };
    0
}

fn sys_fs_read(name_ptr: u64, name_len: u64, buf: u64, len: u64) -> i64 {
    let mut nb = [0u8; MAX_MODULE_NAME as usize];
    let name = match copy_name(name_ptr, name_len, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let len = len.min(axiom_x_fs::MAX_FILE_SIZE as u64);
    if len > 0 && !user_range_accessible(buf, len, true) {
        return -EFAULT;
    }
    // The destination is the caller's validated buffer (current CR3).
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
    match crate::fsys::read(name, out) {
        Ok(size) => size as i64,
        Err(e) => e,
    }
}

fn sys_fs_write(pid: u32, name_ptr: u64, name_len: u64, data: u64, len: u64) -> i64 {
    let mut nb = [0u8; MAX_MODULE_NAME as usize];
    let name = match copy_name(name_ptr, name_len, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if len > axiom_x_fs::MAX_FILE_SIZE as u64 {
        return -crate::fsys::errno::EFBIG;
    }
    if len > 0 && !user_range_accessible(data, len, false) {
        return -EFAULT;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) };
    match crate::fsys::write(pid, name, bytes) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn sys_fs_delete(pid: u32, name_ptr: u64, name_len: u64) -> i64 {
    let mut nb = [0u8; MAX_MODULE_NAME as usize];
    match copy_name(name_ptr, name_len, &mut nb) {
        Ok(name) => match crate::fsys::delete(pid, name) {
            Ok(()) => 0,
            Err(e) => e,
        },
        Err(e) => e,
    }
}

fn sys_fs_install(pid: u32, mod_ptr: u64, mod_len: u64, path_ptr: u64, path_len: u64) -> i64 {
    let mut mb = [0u8; MAX_MODULE_NAME as usize];
    let mut pb = [0u8; MAX_MODULE_NAME as usize];
    let module = match copy_name(mod_ptr, mod_len, &mut mb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let path = match copy_name(path_ptr, path_len, &mut pb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let Some(bytes) = MODULE_BYTES_HOOK.get().and_then(|h| h(module)) else {
        return -ENOENT;
    };
    match crate::fsys::write(pid, path, bytes) {
        Ok(()) => bytes.len() as i64,
        Err(e) => e,
    }
}

/// `AX_PROC_LIST(buf, max)`: up to `max` entries of `PROC_ENTRY_BYTES`:
/// pid u32, parent u32 (0 = kernel), state u32, pad, rights u64, name[16],
/// pad[8]. Returns the number written.
fn sys_proc_list(buf: u64, max: u64) -> i64 {
    let max = max.min(64);
    if max == 0 {
        return 0;
    }
    if !user_range_accessible(buf, max * PROC_ENTRY_BYTES, true) {
        return -EFAULT;
    }
    let mut entries = [[0u8; PROC_ENTRY_BYTES as usize]; 64];
    let n = crate::interrupts::process_table().with_locked(|ps| {
        let mut n = 0;
        for p in ps.iter().take(max as usize) {
            let e = &mut entries[n];
            e[0..4].copy_from_slice(&p.pid.to_le_bytes());
            e[4..8].copy_from_slice(&p.parent_pid.unwrap_or(0).to_le_bytes());
            e[8..12].copy_from_slice(&(p.state as u32).to_le_bytes());
            e[16..24].copy_from_slice(&p.rights.to_le_bytes());
            e[24..40].copy_from_slice(&p.name);
            n += 1;
        }
        n
    });
    for (i, e) in entries[..n].iter().enumerate() {
        unsafe {
            core::ptr::copy_nonoverlapping(e.as_ptr(), (buf + i as u64 * PROC_ENTRY_BYTES) as *mut u8, e.len())
        };
    }
    n as i64
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
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_AX_PROC_LIST => "ax_proc_list",
        SYS_AX_LATENCY => "ax_latency",
        SYS_AX_FS_LIST => "ax_fs_list",
        SYS_AX_FS_INFO => "ax_fs_info",
        SYS_AX_FS_READ => "ax_fs_read",
        SYS_AX_FS_WRITE => "ax_fs_write",
        SYS_AX_FS_DELETE => "ax_fs_delete",
        SYS_AX_FS_INSTALL => "ax_fs_install",
        SYS_EXIT => "exit",
        SYS_GETPID => "getpid",
        SYS_SCHED_YIELD => "sched_yield",
        SYS_NANOSLEEP => "nanosleep",
        SYS_WAIT4 => "wait4",
        SYS_CLOCK_GETTIME => "clock_gettime",
        SYS_AX_SPAWN_MODULE => "ax_spawn_module",
        SYS_AX_GET_EVIDENCE => "ax_get_evidence",
        SYS_AX_MMAP => "ax_mmap",
        SYS_AX_EGRESS => "ax_egress",
        _ => "unknown",
    }
}

/// One evidence line per decision, on the kernel serial console.
fn log_syscall(pid: u32, name: &str, nr: u64, a0: u64, result: i64) {
    use core::fmt::Write;
    if !TRACE.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
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
