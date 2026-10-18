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

// ============================================================================
// Persistence: the chain on disk, verified at boot and continued across boots
// ============================================================================

use crate::ata;
use axiom_x_ledger::ed25519::Keypair;
use axiom_x_ledger::store::{self, SignatureStatus, Superblock, SuperblockError};
use axiom_x_ledger::verify_window;

/// The ledger signing key for this boot (provisioned at boot; never leaves
/// kernel memory; `Keypair` wipes itself on drop).
static SIGNER: Mutex<Option<Keypair>> = Mutex::new(None);

/// Public key a seed would yield (for reporting before `persist_init`).
pub fn signer_public_of(seed: Option<&[u8; 32]>) -> Option<[u8; 32]> {
    seed.map(|s| Keypair::from_seed(s).public)
}

/// Public half of the signing key, if one was provisioned.
pub fn signer_public() -> Option<[u8; 32]> {
    SIGNER.lock().as_ref().map(|k| k.public)
}

/// Sign `sb` with this boot's key, if any.
fn sign_checkpoint(sb: &mut Superblock) {
    if let Some(key) = SIGNER.lock().as_ref() {
        sb.sign(key);
    }
}

struct Persist {
    /// Records are being written to disk.
    enabled: bool,
    /// Records already on disk (the next sequence to write).
    persisted: u64,
    /// This boot's number in the disk ledger's history.
    boots: u64,
    /// Records the disk can hold.
    capacity: u64,
}

static PERSIST: Mutex<Persist> = Mutex::new(Persist { enabled: false, persisted: 0, boots: 0, capacity: 0 });

/// Outcome of attaching the persisted ledger at boot.
#[derive(Clone, Copy, Debug)]
pub enum PersistReport {
    /// No usable disk: the ledger is memory-only for this boot.
    NoDisk(ata::AtaError),
    /// Blank disk: formatted, new chain from genesis.
    Formatted { sectors: u64, signed: bool },
    /// Persisted chain verified from genesis (and its checkpoint signature,
    /// if it had one) and continued.
    Resumed { records: u64, boots: u64, head: Digest, was_signed: bool, signed: bool },
    /// The disk holds something we must not continue or overwrite.
    Refused { reason: &'static str, broken_at: Option<u64> },
}

fn read_slot(seq: u64, cache: &mut (u64, [u8; store::SECTOR])) -> Option<(Record, Digest)> {
    let (sector, off) = store::slot_location(seq);
    if cache.0 != sector {
        ata::read_sector(sector, &mut cache.1).ok()?;
        cache.0 = sector;
    }
    Some(store::decode_slot(&cache.1[off..off + store::SLOT]))
}

/// Attach the disk ledger with this boot's signing key (`None` = unsigned).
/// Must run before the first record of this boot is appended. Appends the
/// BOOT record either way; its `nr` field carries the first 8 bytes of the
/// signer's public key (0 = unsigned).
pub fn persist_init(key_seed: Option<[u8; 32]>) -> PersistReport {
    *SIGNER.lock() = key_seed.map(|seed| Keypair::from_seed(&seed));
    let report = attach_disk();
    let (boot_no, resumed) = match report {
        PersistReport::Formatted { .. } => (1, 0),
        PersistReport::Resumed { records, boots, .. } => (boots, records as i64),
        _ => (0, -1),
    };
    let key_id = signer_public().map_or(0, |p| u64::from_le_bytes(p[..8].try_into().unwrap()));
    record(kind::BOOT, decision::ALLOW, 0, 0, key_id, boot_no, resumed, Rights::NONE);
    report
}

fn attach_disk() -> PersistReport {
    let sectors = match ata::identify() {
        Ok(n) => n,
        Err(e) => return PersistReport::NoDisk(e),
    };
    let capacity = store::capacity(sectors);
    let mut sb_buf = [0u8; store::SECTOR];
    if ata::read_sector(0, &mut sb_buf).is_err() {
        return PersistReport::Refused { reason: "cannot read superblock", broken_at: None };
    }
    match Superblock::decode(&sb_buf) {
        Err(SuperblockError::Blank) => {
            let mut sb = Superblock::unsigned(0, [0; 32], 1);
            sign_checkpoint(&mut sb);
            if ata::write_sector(0, &sb.encode()).and_then(|_| ata::flush()).is_err() {
                return PersistReport::Refused { reason: "cannot format", broken_at: None };
            }
            *PERSIST.lock() = Persist { enabled: true, persisted: 0, boots: 1, capacity };
            PersistReport::Formatted { sectors, signed: sb.signature.is_some() }
        }
        Err(SuperblockError::Foreign) => PersistReport::Refused {
            reason: "disk holds something else; not formatting over it",
            broken_at: None,
        },
        Err(SuperblockError::Corrupt) => {
            PersistReport::Refused { reason: "superblock checksum mismatch", broken_at: None }
        }
        Ok(sb) => {
            if sb.total > capacity {
                return PersistReport::Refused {
                    reason: "superblock claims more records than the disk holds",
                    broken_at: None,
                };
            }
            // Signed history must be continued by the same key: a missing
            // key would silently strip signatures, a different one would
            // let anyone take over the chain.
            let was_signed = sb.signature.is_some();
            match (was_signed, signer_public()) {
                (true, None) => {
                    return PersistReport::Refused {
                        reason: "ledger is signed but no signing key is provisioned",
                        broken_at: None,
                    }
                }
                (true, Some(pk)) => match sb.signature_status(&pk) {
                    SignatureStatus::Valid => {}
                    SignatureStatus::WrongKey => {
                        return PersistReport::Refused {
                            reason: "checkpoint was signed by a different key",
                            broken_at: None,
                        }
                    }
                    _ => {
                        return PersistReport::Refused {
                            reason: "checkpoint signature does not verify",
                            broken_at: None,
                        }
                    }
                },
                (false, _) => {}
            }
            // Re-verify every persisted link from genesis before trusting it.
            let mut cache = (u64::MAX, [0u8; store::SECTOR]);
            match verify_window(0, sb.total, |seq| read_slot(seq, &mut cache)) {
                Err(seq) => PersistReport::Refused { reason: "persisted chain broken", broken_at: Some(seq) },
                Ok(head) if head != sb.head => PersistReport::Refused {
                    reason: "superblock head does not match the chain",
                    broken_at: None,
                },
                Ok(head) => {
                    LEDGER.lock().resume(sb.total, head);
                    let boots = sb.boots + 1;
                    let mut sb2 = Superblock::unsigned(sb.total, head, boots);
                    sign_checkpoint(&mut sb2);
                    if ata::write_sector(0, &sb2.encode()).and_then(|_| ata::flush()).is_err() {
                        return PersistReport::Refused { reason: "cannot update superblock", broken_at: None };
                    }
                    *PERSIST.lock() = Persist { enabled: true, persisted: sb.total, boots, capacity };
                    PersistReport::Resumed {
                        records: sb.total,
                        boots,
                        head,
                        was_signed,
                        signed: sb2.signature.is_some(),
                    }
                }
            }
        }
    }
}

/// Write every record appended since the last flush, then the superblock,
/// then commit the drive cache. Returns records written.
pub fn persist_flush() -> Result<u64, &'static str> {
    let (enabled, from, boots, capacity) = {
        let p = PERSIST.lock();
        (p.enabled, p.persisted, p.boots, p.capacity)
    };
    if !enabled {
        return Ok(0);
    }
    let (total, _) = ledger_summary();
    if total > capacity {
        PERSIST.lock().enabled = false;
        return Err("disk ledger full; persistence stopped");
    }
    let mut sector_buf = [0u8; store::SECTOR];
    let mut cur_sector = u64::MAX;
    let mut last_digest = None;
    for seq in from..total {
        let (sector, off) = store::slot_location(seq);
        if sector != cur_sector {
            if cur_sector != u64::MAX {
                ata::write_sector(cur_sector, &sector_buf).map_err(|_| "write failed")?;
            }
            // Partly filled sector: keep the slots already on disk.
            ata::read_sector(sector, &mut sector_buf).map_err(|_| "read failed")?;
            cur_sector = sector;
        }
        let Some((r, d)) = ledger_get(seq) else {
            PERSIST.lock().enabled = false;
            return Err("records left memory before they were flushed; persistence stopped");
        };
        sector_buf[off..off + store::SLOT].copy_from_slice(&store::encode_slot(&r, &d));
        last_digest = Some(d);
    }
    let Some(head) = last_digest else { return Ok(0) };
    ata::write_sector(cur_sector, &sector_buf).map_err(|_| "write failed")?;
    let mut sb = Superblock::unsigned(total, head, boots);
    sign_checkpoint(&mut sb);
    ata::write_sector(0, &sb.encode()).map_err(|_| "superblock write failed")?;
    ata::flush().map_err(|_| "cache flush failed")?;
    PERSIST.lock().persisted = total;
    Ok(total - from)
}

/// Record `seq` from memory, or from disk if it is persisted but no longer
/// held in memory (e.g. written by an earlier boot).
pub fn ledger_get_any(seq: u64) -> Option<(Record, Digest)> {
    if let Some(r) = ledger_get(seq) {
        return Some(r);
    }
    let (enabled, persisted) = {
        let p = PERSIST.lock();
        (p.enabled, p.persisted)
    };
    if !enabled || seq >= persisted {
        return None;
    }
    let mut cache = (u64::MAX, [0u8; store::SECTOR]);
    read_slot(seq, &mut cache)
}
