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
    SYS_AX_FS_DELETE, SYS_AX_FS_INFO, SYS_AX_FS_INSTALL, SYS_AX_FS_LIST, SYS_AX_FS_READ, SYS_AX_FS_WRITE,
    SYS_AX_EGRESS, SYS_AX_GET_EVIDENCE, SYS_AX_LATENCY, SYS_AX_MMAP, SYS_AX_PROC_LIST, SYS_AX_SPAWN_MODULE, SYS_CLOCK_GETTIME, SYS_EXIT, SYS_GETPID,
    SYS_NANOSLEEP, SYS_READ, SYS_SCHED_YIELD, SYS_WAIT4, SYS_WRITE,
};

/// Records kept in memory; the chain itself is unbounded.
pub const LEDGER_CAPACITY: usize = 4096;

static LEDGER: Mutex<Ledger<LEDGER_CAPACITY>> = Mutex::new(Ledger::new());

/// The right a syscall requires, or `None` for calls that only act on the
/// caller itself (exit, getpid, yield, sleep, waiting for its own children).
pub fn required_right(nr: u64) -> Option<Rights> {
    match nr {
        // The console is a shared endpoint: writing to it is sending.
        SYS_WRITE => Some(Rights::SEND),
        // Reading the console is receiving from it.
        SYS_READ => Some(Rights::RECV),
        // Listing processes observes system state, like reading evidence.
        SYS_AX_PROC_LIST | SYS_AX_LATENCY => Some(Rights::EVIDENCE),
        // Files: observing needs READ, changing needs WRITE.
        SYS_AX_FS_LIST | SYS_AX_FS_INFO | SYS_AX_FS_READ => Some(Rights::READ),
        SYS_AX_FS_WRITE | SYS_AX_FS_DELETE | SYS_AX_FS_INSTALL => Some(Rights::WRITE),
        SYS_AX_SPAWN_MODULE => Some(Rights::SPAWN),
        // Growing your address space allocates frames: gated like any alloc.
        SYS_AX_MMAP => Some(Rights::ALLOC),
        // Talking to the outside world is the most governed action there is.
        SYS_AX_EGRESS => Some(Rights::NET),
        SYS_AX_GET_EVIDENCE => Some(Rights::EVIDENCE),
        SYS_EXIT | SYS_GETPID | SYS_SCHED_YIELD | SYS_NANOSLEEP | SYS_WAIT4 | SYS_CLOCK_GETTIME => None,
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
    crate::latency::irq_off(crate::latency::Site::LedgerAppend, || LEDGER.lock().append(r))
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

fn pack32(d: &[u8]) -> (u64, u64, u64, u64) {
    (
        u64::from_le_bytes(d[0..8].try_into().unwrap()),
        u64::from_le_bytes(d[8..16].try_into().unwrap()),
        u64::from_le_bytes(d[16..24].try_into().unwrap()),
        u64::from_le_bytes(d[24..32].try_into().unwrap()),
    )
}

/// Append a four-record egress attestation: `sig` is the proxy's Ed25519
/// signature over `request_digest || response_digest`, and `egress_seq`
/// links the group back to the syscall record that produced it.
pub fn record_egress_attest(pid: u32, egress_seq: u64, req: &Digest, resp: &Digest, sig: &[u8; 64]) {
    let sub = egress_seq as u32;
    for (kind, d) in [
        (kind::EGRESS_ATTEST_REQ, &req[..]),
        (kind::EGRESS_ATTEST_RESP, &resp[..]),
        (kind::EGRESS_ATTEST_SIG_LO, &sig[..32]),
        (kind::EGRESS_ATTEST_SIG_HI, &sig[32..]),
    ] {
        let (nr, arg, result, bits) = pack32(d);
        record(kind, decision::ALLOW, pid, sub, nr, arg, result as i64, Rights::new(bits));
    }
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
//
// Disk format v3 (see `axiom_x_ledger::store`): A/B superblocks, a one-sector
// write-ahead journal for the only in-place rewrite (the partly filled last
// record sector), and an append-only archive of signed checkpoints.

use crate::ata;
use axiom_x_ledger::ed25519::Keypair;
use axiom_x_ledger::store::{self, Checkpoint, JournalHeader, Pick, SignatureStatus, Superblock, SuperblockError};
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

fn sign_checkpoint(c: &mut Checkpoint) {
    if let Some(key) = SIGNER.lock().as_ref() {
        c.sign(key);
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
    /// Generation of the current superblock copy.
    generation: u64,
    /// Checkpoints archived.
    archived: u64,
}

/// Interrupt-safe: the init thread saves the ledger with interrupts on,
/// while `AX_GET_EVIDENCE` reads `persisted` from inside a system call
/// (interrupts off). With a plain spin lock, init preempted while holding
/// it would leave that system call spinning forever.
static PERSIST: crate::sync::IrqMutex<Persist> =
    crate::sync::IrqMutex::new(Persist { enabled: false, persisted: 0, boots: 0, capacity: 0, generation: 0, archived: 0 });

// ----------------------------------------------------------------------------
// Fault injection (test only)
// ----------------------------------------------------------------------------

/// Points in a save where a test can simulate power loss, selected with the
/// kernel command line `axiom.crash=<name>`. The kernel halts there; the
/// test harness then kills the VM and boots again to check recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    None,
    /// Journal header + data written, target sector not yet rewritten.
    AfterJournal,
    /// Target sector half-written (rest garbage), journal complete.
    TornTarget,
    /// All record sectors written, superblock not.
    BeforeSuperblock,
    /// New superblock copy half-written (rest garbage).
    TornSuperblock,
}

impl CrashPoint {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "after-journal" => Self::AfterJournal,
            "torn-target" => Self::TornTarget,
            "before-superblock" => Self::BeforeSuperblock,
            "torn-superblock" => Self::TornSuperblock,
            _ => return None,
        })
    }
}

static CRASH: Mutex<CrashPoint> = Mutex::new(CrashPoint::None);

pub fn set_crash_point(p: CrashPoint) {
    *CRASH.lock() = p;
}

fn crash_if(point: CrashPoint, what: &str) {
    if *CRASH.lock() == point {
        use core::fmt::Write;
        // About to halt: drain buffered output, then write directly.
        x86_64::instructions::interrupts::disable();
        crate::console::serial_sync();
        let _ = writeln!(
            crate::SerialPort,
            "[ledger] CRASH INJECTION ({:?}): {}; halting now (simulated power loss)",
            point, what
        );
        loop {
            unsafe { core::arch::asm!("cli; hlt") };
        }
    }
}

/// A sector damaged by power loss mid-write: garbage in the first half,
/// the new data in the second. Sector writes are not atomic and may tear
/// anywhere; this is the harsh case, since in a partly filled record
/// sector the already-persisted slots sit at the front.
fn torn(new: &[u8; store::SECTOR]) -> [u8; store::SECTOR] {
    let mut b = [0xAA; store::SECTOR];
    b[store::SECTOR / 2..].copy_from_slice(&new[store::SECTOR / 2..]);
    b
}

// ----------------------------------------------------------------------------
// Boot: recover, choose, verify, resume
// ----------------------------------------------------------------------------

/// What boot-time recovery had to do.
#[derive(Clone, Copy, Debug, Default)]
pub struct Recovery {
    /// A complete journal was replayed into this sector.
    pub journal_replayed: Option<u64>,
    /// An incomplete journal was found and discarded (its target untouched).
    pub torn_journal_discarded: bool,
    /// The newer superblock copy was damaged; the older one was used.
    pub superblock_fallback: bool,
}

/// Outcome of attaching the persisted ledger at boot.
#[derive(Clone, Copy, Debug)]
pub enum PersistReport {
    /// No usable disk: the ledger is memory-only for this boot.
    NoDisk(ata::AtaError),
    /// Blank disk: formatted, new chain from genesis.
    Formatted { sectors: u64, signed: bool },
    /// Persisted chain verified from genesis (and its checkpoint signature,
    /// if it had one) and continued.
    Resumed {
        records: u64,
        boots: u64,
        head: Digest,
        was_signed: bool,
        signed: bool,
        archived: u64,
        recovery: Recovery,
    },
    /// The disk holds something we must not continue or overwrite.
    Refused { reason: &'static str, broken_at: Option<u64>, recovery: Recovery },
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
    record(kind::BOOT, decision::ALLOW, 0, 0, key_id, boot_no, resumed, Rights::new(crate::clock::boot_unix()));
    report
}

/// Replay a complete journal (or discard a torn one) before anything else
/// reads record sectors.
fn recover_journal(sectors: u64, rec: &mut Recovery) -> Result<(), &'static str> {
    let mut hdr = [0u8; store::SECTOR];
    ata::read_sector(store::JOURNAL_HEADER_SECTOR, &mut hdr).map_err(|_| "cannot read journal")?;
    let Some(h) = JournalHeader::decode(&hdr) else {
        return Ok(()); // clear (or never written)
    };
    let mut data = [0u8; store::SECTOR];
    ata::read_sector(store::JOURNAL_DATA_SECTOR, &mut data).map_err(|_| "cannot read journal")?;
    if h.matches(&data) && h.target >= store::RECORD_BASE && h.target < sectors {
        ata::write_sector(h.target, &data).map_err(|_| "journal replay failed")?;
        ata::flush().map_err(|_| "journal replay failed")?;
        rec.journal_replayed = Some(h.target);
    } else {
        // Power was lost while the journal itself was being written: the
        // target was never touched, so dropping the journal is correct.
        rec.torn_journal_discarded = true;
    }
    ata::write_sector(store::JOURNAL_HEADER_SECTOR, &[0; store::SECTOR]).map_err(|_| "cannot clear journal")?;
    ata::flush().map_err(|_| "cannot clear journal")?;
    Ok(())
}

fn attach_disk() -> PersistReport {
    let sectors = match ata::identify() {
        Ok(n) => n,
        Err(e) => return PersistReport::NoDisk(e),
    };
    let capacity = store::capacity(sectors);
    let mut recovery = Recovery::default();
    let refused = |reason, broken_at, recovery| PersistReport::Refused { reason, broken_at, recovery };

    if let Err(why) = recover_journal(sectors, &mut recovery) {
        return refused(why, None, recovery);
    }

    let mut a = [0u8; store::SECTOR];
    let mut b = [0u8; store::SECTOR];
    if ata::read_sector(0, &mut a).and_then(|_| ata::read_sector(1, &mut b)).is_err() {
        return refused("cannot read superblocks", None, recovery);
    }
    let (da, db) = (Superblock::decode(&a), Superblock::decode(&b));
    let sb = match store::pick_superblock(da, db) {
        Pick::Blank => {
            // New disk: generation 1 (sector 1), checkpoint 0 archived.
            let mut c = Checkpoint::unsigned(0, [0; 32], 1);
            sign_checkpoint(&mut c);
            let sb = Superblock { checkpoint: c, generation: 1, archived: 1 };
            let ok = ata::write_sector(store::CHECKPOINT_BASE, &c.encode_archive())
                .and_then(|_| ata::write_sector(store::superblock_sector(1), &sb.encode()))
                .and_then(|_| ata::flush());
            if ok.is_err() {
                return refused("cannot format", None, recovery);
            }
            *PERSIST.lock() = Persist { enabled: true, persisted: 0, boots: 1, capacity, generation: 1, archived: 1 };
            return PersistReport::Formatted { sectors, signed: c.signature.is_some() };
        }
        Pick::Refuse(SuperblockError::Foreign) => {
            return refused("disk holds something else; not formatting over it", None, recovery)
        }
        Pick::Refuse(_) => return refused("no intact superblock copy", None, recovery),
        Pick::Use(sb, which) => {
            let other = if which == 0 { db } else { da };
            // The other copy is damaged (a torn write may garble even the
            // magic, so 'foreign' counts too); a blank one is just unused.
            recovery.superblock_fallback = matches!(other, Err(SuperblockError::Corrupt | SuperblockError::Foreign));
            sb
        }
    };
    let c = sb.checkpoint;
    if c.total > capacity {
        return refused("superblock claims more records than the disk holds", None, recovery);
    }
    if recovery.superblock_fallback {
        // A damaged newest copy fell back to an older superblock — but a
        // hostile one-sector edit looks identical. If the archive holds a
        // *validly signed* checkpoint claiming more records, this superblock
        // is stale: silently dropping signed history must not pass.
        if let Some(pk) = signer_public() {
            for i in sb.archived..store::CHECKPOINT_SECTORS {
                let mut sector = [0u8; store::SECTOR];
                if ata::read_sector(store::CHECKPOINT_BASE + i, &mut sector).is_err() {
                    break;
                }
                let Some(newer) = Checkpoint::decode_archive(&sector) else {
                    break;
                };
                if newer.status(&pk) == SignatureStatus::Valid && newer.total > c.total {
                    return refused(
                        "rollback evidence: archive holds a newer signed checkpoint than the superblock",
                        None,
                        recovery,
                    );
                }
            }
        }
    }
    // Signed history must be continued by the same key: a missing key
    // would silently strip signatures, a different one would let anyone
    // take over the chain.
    let was_signed = c.signature.is_some();
    match (was_signed, signer_public()) {
        (true, None) => return refused("ledger is signed but no signing key is provisioned", None, recovery),
        (true, Some(pk)) => match c.status(&pk) {
            SignatureStatus::Valid => {}
            SignatureStatus::WrongKey => return refused("checkpoint was signed by a different key", None, recovery),
            _ => return refused("checkpoint signature does not verify", None, recovery),
        },
        (false, _) => {}
    }
    // Re-verify every persisted link from genesis before trusting it.
    let mut cache = (u64::MAX, [0u8; store::SECTOR]);
    let head = match verify_window(0, c.total, |seq| read_slot(seq, &mut cache)) {
        Err(seq) => return refused("persisted chain broken", Some(seq), recovery),
        Ok(head) if head != c.head => return refused("superblock head does not match the chain", None, recovery),
        Ok(head) => head,
    };
    LEDGER.lock().resume(c.total, head);
    let boots = c.boots + 1;
    *PERSIST.lock() = Persist {
        enabled: true,
        persisted: c.total,
        boots,
        capacity,
        generation: sb.generation,
        archived: sb.archived,
    };
    // Booting is a save: new boot count, signed by this boot's key.
    if write_checkpoint(c.total, head).is_err() {
        PERSIST.lock().enabled = false;
        return refused("cannot update superblock", None, recovery);
    }
    let (signed, archived) = {
        let p = PERSIST.lock();
        (signer_public().is_some(), p.archived)
    };
    PersistReport::Resumed { records: c.total, boots, head, was_signed, signed, archived, recovery }
}

// ----------------------------------------------------------------------------
// Save
// ----------------------------------------------------------------------------

/// Archive and publish a checkpoint for (total, head): a fresh archive
/// sector, then the superblock copy that is not current, then a cache
/// flush. A torn superblock write leaves the current copy in charge.
fn write_checkpoint(total: u64, head: Digest) -> Result<(), &'static str> {
    let (boots, generation, archived) = {
        let p = PERSIST.lock();
        (p.boots, p.generation, p.archived)
    };
    let mut c = Checkpoint::unsigned(total, head, boots);
    sign_checkpoint(&mut c);
    let archived = if archived < store::CHECKPOINT_SECTORS {
        ata::write_sector(store::CHECKPOINT_BASE + archived, &c.encode_archive()).map_err(|_| "archive write failed")?;
        archived + 1
    } else {
        archived // archive full: the superblock still carries the latest
    };
    let next = generation + 1;
    let sb = Superblock { checkpoint: c, generation: next, archived };
    let image = sb.encode();
    if *CRASH.lock() == CrashPoint::TornSuperblock {
        let _ = ata::write_sector(store::superblock_sector(next), &torn(&image));
        crash_if(CrashPoint::TornSuperblock, "new superblock copy half-written");
    }
    ata::write_sector(store::superblock_sector(next), &image).map_err(|_| "superblock write failed")?;
    ata::flush().map_err(|_| "cache flush failed")?;
    let mut p = PERSIST.lock();
    p.generation = next;
    p.archived = archived;
    Ok(())
}

/// Write every record appended since the last save, then publish a signed
/// checkpoint. Returns records written.
pub fn persist_flush() -> Result<u64, &'static str> {
    let (enabled, from, capacity) = {
        let p = PERSIST.lock();
        (p.enabled, p.persisted, p.capacity)
    };
    if !enabled {
        return Ok(0);
    }
    let (total, _) = ledger_summary();
    if total == from {
        return Ok(0);
    }
    if total > capacity {
        PERSIST.lock().enabled = false;
        return Err("disk ledger full; persistence stopped");
    }
    let fail = |why| {
        PERSIST.lock().enabled = false;
        why
    };
    let mut last_digest = [0u8; 32];
    let mut seq = from;
    while seq < total {
        let (sector, first_off) = store::slot_location(seq);
        // Build this sector's new image. A sector that already holds
        // persisted slots (only possible for the first one) starts from
        // its current contents and must be rewritten through the journal.
        let in_place = first_off != 0;
        let mut image = [0u8; store::SECTOR];
        if in_place {
            ata::read_sector(sector, &mut image).map_err(|_| fail("read failed"))?;
        }
        let mut off = first_off;
        while off < store::SECTOR && seq < total {
            let Some((r, d)) = ledger_get(seq) else {
                return Err(fail("records left memory before they were flushed; persistence stopped"));
            };
            image[off..off + store::SLOT].copy_from_slice(&store::encode_slot(&r, &d));
            last_digest = d;
            off += store::SLOT;
            seq += 1;
        }
        if in_place {
            // Write-ahead: the full new image and a header naming its target,
            // committed before the target is touched.
            let hdr = JournalHeader::for_data(sector, &image);
            ata::write_sector(store::JOURNAL_DATA_SECTOR, &image)
                .and_then(|_| ata::write_sector(store::JOURNAL_HEADER_SECTOR, &hdr.encode()))
                .and_then(|_| ata::flush())
                .map_err(|_| fail("journal write failed"))?;
            crash_if(CrashPoint::AfterJournal, "journal committed, target not yet rewritten");
            if *CRASH.lock() == CrashPoint::TornTarget {
                let _ = ata::write_sector(sector, &torn(&image));
                crash_if(CrashPoint::TornTarget, "target sector half-written over persisted records");
            }
        }
        ata::write_sector(sector, &image).map_err(|_| fail("write failed"))?;
    }
    crash_if(CrashPoint::BeforeSuperblock, "all record sectors written, superblock not");
    write_checkpoint(total, last_digest).map_err(fail)?;
    // The new superblock now covers the rewrite: retire the journal.
    ata::write_sector(store::JOURNAL_HEADER_SECTOR, &[0; store::SECTOR])
        .and_then(|_| ata::flush())
        .map_err(|_| fail("cannot clear journal"))?;
    PERSIST.lock().persisted = total;
    Ok(total - from)
}

/// Records appended but not yet on disk (0 when persistence is off). Save
/// well before this nears `LEDGER_CAPACITY`, or records leave memory
/// unsaved and persistence stops.
pub fn unflushed() -> u64 {
    let (enabled, persisted) = {
        let p = PERSIST.lock();
        (p.enabled, p.persisted)
    };
    if !enabled {
        return 0;
    }
    ledger_summary().0.saturating_sub(persisted)
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
