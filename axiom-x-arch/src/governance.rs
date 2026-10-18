//! Kernel governance: capability rights on every syscall, and a hash-chained
//! evidence ledger of every governed decision.
//!
//! - Each process holds `Rights` (from `axiom-x-capability`). A syscall that
//!   needs a right the caller lacks is refused with `-EPERM`.
//! - Rights only flow down: a parent may grant a child a subset of its own
//!   rights (`AX_SPAWN_MODULE`), never more.
//! - Every decision (allow, deny, block, process create/exit/kill, reap)
//!   appends a record to the SHA-256 chain in `axiom-x-ledger`. Holders of
//!   `Rights::EVIDENCE` can read records back (`AX_GET_EVIDENCE`) and verify
//!   the chain themselves.
//!
//! Rights are capability bits, not signed attestations: there is no
//! cryptographic proof of who granted them beyond the ledger's own chain.
//!
//! Status: `partial` — enforced on the syscall path and exercised in QEMU.

pub use axiom_x_capability::Rights;
use axiom_x_ledger::{decision, kind, Digest, Ledger, Record};
use core::sync::atomic::Ordering;
use spin::Mutex;

use crate::syscall::{
    SYS_AX_GET_EVIDENCE, SYS_AX_SPAWN_MODULE, SYS_EXIT, SYS_GETPID, SYS_NANOSLEEP, SYS_SCHED_YIELD,
    SYS_WAIT4, SYS_WRITE,
};

/// Records kept in memory; the chain itself is unbounded.
pub const LEDGER_CAPACITY: usize = 1024;

static LEDGER: Mutex<Ledger<LEDGER_CAPACITY>> = Mutex::new(Ledger::new());

/// The right a syscall requires, or `None` for calls that only act on the
/// caller itself (exit, getpid, yield, sleep, waiting for its own children).
pub fn required_right(nr: u64) -> Option<Rights> {
    match nr {
        // The console is a shared endpoint: writing to it is sending.
        SYS_WRITE => Some(Rights::SEND),
        SYS_AX_SPAWN_MODULE => Some(Rights::SPAWN),
        SYS_AX_GET_EVIDENCE => Some(Rights::EVIDENCE),
        SYS_EXIT | SYS_GETPID | SYS_SCHED_YIELD | SYS_NANOSLEEP | SYS_WAIT4 => None,
        // Unknown calls need no right: they fail with -ENOSYS anyway.
        _ => None,
    }
}

/// Rights held by `pid` (0 for unknown processes).
pub fn rights_of(pid: u32) -> Rights {
    Rights::new(
        crate::interrupts::process_table()
            .with_locked(|ps| ps.iter().find(|p| p.pid == pid).map_or(0, |p| p.rights)),
    )
}

/// Set the rights a process holds (at creation, by its creator).
pub fn set_rights(pid: u32, rights: Rights) {
    if let Some(mut g) = crate::interrupts::process_table().get_mut(pid) {
        g.get_mut().rights = rights.bits();
    }
}

/// Append one decision to the chain. Safe from any context.
pub fn record(kind: u32, decision: u32, pid: u32, subject: u32, nr: u64, arg: u64, result: i64, rights: Rights) -> u64 {
    let r = Record {
        tick: crate::sched::TICKS.load(Ordering::Relaxed),
        kind,
        decision,
        pid,
        subject,
        nr,
        arg,
        result,
        rights: rights.bits(),
        ..Record::default()
    };
    x86_64::instructions::interrupts::without_interrupts(|| LEDGER.lock().append(r))
}

/// Record a syscall decision.
pub fn record_syscall(pid: u32, nr: u64, arg: u64, result: i64, allowed: bool) {
    let d = if allowed { decision::ALLOW } else { decision::DENY };
    let need = required_right(nr).unwrap_or(Rights::NONE);
    record(kind::CONTRACT_ENFORCE, d, pid, pid, nr, arg, result, need);
}

/// Record that a syscall blocked the caller (sleep / wait).
pub fn record_block(pid: u32, nr: u64, arg: u64) {
    record(PROCESS_BLOCK, decision::ALLOW, pid, pid, nr, arg, 0, Rights::NONE);
}

/// `axiom_x_sys::EvidenceType::ProcessBlock`.
pub const PROCESS_BLOCK: u32 = 7;

/// Record a process being created with `rights` by `parent` (0 = kernel).
pub fn record_create(parent: u32, child: u32, rights: Rights, allowed: bool, result: i64) {
    let d = if allowed { decision::ALLOW } else { decision::DENY };
    record(kind::PROCESS_CREATE, d, parent, child, SYS_AX_SPAWN_MODULE, 0, result, rights);
}

/// Record a process ending: `exit(code)` or a kill (`code < 0` = signal).
pub fn record_exit(pid: u32, code: i32) {
    let d = if code < 0 { decision::FAULT } else { decision::ALLOW };
    record(kind::PROCESS_EXIT, d, pid, pid, SYS_EXIT, 0, code as i64, Rights::NONE);
}

/// Record a reap: `by` (0 = kernel) freed `frames` owned by `child`.
pub fn record_reap(by: u32, child: u32, frames: u64) {
    record(kind::MEMORY_FREE, decision::ALLOW, by, child, SYS_WAIT4, frames, 0, Rights::NONE);
}

/// (records ever appended, chain head digest).
pub fn ledger_summary() -> (u64, Digest) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let l = LEDGER.lock();
        (l.total(), l.head())
    })
}

/// Copy record `seq` (encoded + digest) for `AX_GET_EVIDENCE`.
pub fn ledger_get(seq: u64) -> Option<(Record, Digest)> {
    x86_64::instructions::interrupts::without_interrupts(|| LEDGER.lock().get(seq))
}
