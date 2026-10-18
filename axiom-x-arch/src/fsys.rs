//! Kernel file system: AXFS (`axiom-x-fs`) on the primary-slave IDE disk,
//! anchored in the signed evidence ledger.
//!
//! - Every committed change (write, delete, install) appends an `FS_COMMIT`
//!   ledger record carrying the new **root hash** (SHA-256 of the file
//!   table, which holds every file's SHA-256), so the signed chain attests
//!   each state of the file system.
//! - At mount, the newest `FS_COMMIT`/`FS_MOUNT` root in the ledger must
//!   equal the disk's root. If it does not, the disk was changed or rolled
//!   back behind the kernel's back: it is mounted **read-only** and the
//!   mismatch is recorded. Every mount appends an `FS_MOUNT` record.
//! - Reads re-verify each file's hash (in `axiom-x-fs`).
//! - Access is serialized by a **sleeping lock** (`FsGuard`): the file-system
//!   system calls run with interrupts on, so the holder can be preempted;
//!   a process that finds the lock taken blocks (`WAIT_FS`) instead of
//!   spinning, and is woken when it is released. Disk commands keep their
//!   own short interrupts-off sections (`ata`).
//!
//! Status: `partial` — exercised in QEMU; whole-file operations only.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use axiom_x_fs::{BlockDev, Entry, Fs, FsError, MountError, MAX_FILE_SIZE, SECTOR};


use axiom_x_ledger::{kind, Digest};
use spin::Mutex;

use crate::ata::{self, Drive};

/// The FS disk: primary slave.
pub struct SlaveDisk;

impl BlockDev for SlaveDisk {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8; SECTOR]) -> Result<(), ()> {
        ata::read_sector_on(Drive::Slave, lba, buf).map_err(|_| ())
    }
    fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR]) -> Result<(), ()> {
        ata::write_sector_on(Drive::Slave, lba, buf).map_err(|_| ())
    }
    fn flush(&mut self) -> Result<(), ()> {
        ata::flush_on(Drive::Slave).map_err(|_| ())
    }
    fn sectors(&self) -> u64 {
        ata::sectors_on(Drive::Slave).unwrap_or(0)
    }
}

struct State {
    /// Built in place (about 24 KiB): never moved through a kernel stack.
    fs: Fs<SlaveDisk>,
    mounted: bool,
    writable: bool,
}

static STATE: Mutex<State> = Mutex::new(State { fs: Fs::new(SlaveDisk), mounted: false, writable: false });

/// How the newest ledger anchor compares with the disk.
#[derive(Clone, Copy, Debug)]
pub enum Anchor {
    /// No file-system record in the ledger yet (first use).
    FirstUse,
    /// The ledger's newest root (record `seq`) matches the disk.
    Matches(u64),
    /// The ledger's newest root (record `seq`) differs: tampered or rolled back.
    Mismatch(u64),
}

#[derive(Clone, Copy, Debug)]
pub enum MountReport {
    NoDisk,
    Formatted { sectors: u64, root: Digest },
    Mounted { files: usize, root: Digest, anchor: Anchor, writable: bool },
    /// The disk has unusable or damaged metadata (never formatted over).
    Refused(MountError),
    /// A file's content does not match its hash: mounted read-only.
    CorruptFile { name: [u8; 48], root: Digest },
}

/// Root hash split into the four 64-bit fields of a ledger record.
fn root_fields(r: &Digest) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(r[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn record_root(kind_: u32, decision: u32, pid: u32, root: &Digest) {
    let f = root_fields(root);
    crate::governance::record(kind_, decision, pid, pid, f[0], f[1], f[3] as i64, crate::governance::Rights::new(f[2]));
}

fn root_of(r: &axiom_x_ledger::Record) -> Digest {
    let mut d = [0u8; 32];
    for (i, v) in [r.nr, r.arg, r.rights, r.result as u64].iter().enumerate() {
        d[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    d
}

/// Newest ledger record about the file system (scanning back from the head).
fn newest_anchor() -> Option<(u64, Digest)> {
    let (total, _) = crate::governance::ledger_summary();
    let mut seq = total;
    while seq > 0 {
        seq -= 1;
        let (r, _) = crate::governance::ledger_get_any(seq)?;
        if r.kind == kind::FS_COMMIT || (r.kind == kind::FS_MOUNT && r.decision == axiom_x_ledger::decision::ALLOW) {
            return Some((seq, root_of(&r)));
        }
    }
    None
}

/// Mount (or format a blank disk), check it against the ledger, record it.
/// Call after the ledger is attached and before user processes run.
pub fn mount() -> MountReport {
    use axiom_x_ledger::decision::{ALLOW, DENY};
    let Ok(sectors) = ata::identify_on(Drive::Slave) else {
        return MountReport::NoDisk;
    };
    let mut guard = STATE.lock();
    let st = &mut *guard;
    match st.fs.mount_in_place() {
        Ok(()) => {}
        Err(MountError::Blank) => {
            if st.fs.format_in_place().is_err() {
                return MountReport::Refused(MountError::Io);
            }
            let root = st.fs.root();
            st.mounted = true;
            st.writable = true;
            drop(guard);
            record_root(kind::FS_MOUNT, ALLOW, 0, &root);
            return MountReport::Formatted { sectors, root };
        }
        Err(e) => return MountReport::Refused(e),
    }
    st.mounted = true;
    let root = st.fs.root();
    if let Err(name) = st.fs.verify_all() {
        st.writable = false;
        drop(guard);
        record_root(kind::FS_MOUNT, DENY, 0, &root);
        return MountReport::CorruptFile { name, root };
    }
    let anchor = match newest_anchor() {
        None => Anchor::FirstUse,
        Some((seq, r)) if r == root => Anchor::Matches(seq),
        Some((seq, _)) => Anchor::Mismatch(seq),
    };
    let writable = !matches!(anchor, Anchor::Mismatch(_));
    st.writable = writable;
    let files = st.fs.entries().count();
    drop(guard);
    record_root(kind::FS_MOUNT, if writable { ALLOW } else { DENY }, 0, &root);
    MountReport::Mounted { files, root, anchor, writable }
}

/// Errors as negative errno values for syscalls.
pub mod errno {
    pub const EIO: i64 = 5;
    pub const EFBIG: i64 = 27;
    pub const ENOSPC: i64 = 28;
    pub const EROFS: i64 = 30;
}

pub fn fs_errno(e: FsError) -> i64 {
    use crate::syscall::{EINVAL, ENOENT};
    -match e {
        FsError::Io | FsError::Corrupt => errno::EIO,
        FsError::NoSpace | FsError::TableFull => errno::ENOSPC,
        FsError::NotFound => ENOENT,
        FsError::BadName => EINVAL,
        FsError::TooLarge => errno::EFBIG,
    }
}

/// PID holding the file-system lock (0 = free).
static FS_OWNER: AtomicU32 = AtomicU32::new(0);
/// Lock acquisitions, and how many of them had to block first.
pub static FS_LOCK_ACQUIRES: AtomicU64 = AtomicU64::new(0);
pub static FS_LOCK_WAITS: AtomicU64 = AtomicU64::new(0);

/// Held file-system lock; released (waking any waiters) on drop.
struct FsGuard;

impl FsGuard {
    fn acquire() -> FsGuard {
        let pid = crate::process::current_pid();
        loop {
            let taken = x86_64::instructions::interrupts::without_interrupts(|| {
                if FS_OWNER.load(Ordering::Relaxed) == 0 {
                    FS_OWNER.store(pid, Ordering::Relaxed);
                    true
                } else {
                    FS_LOCK_WAITS.fetch_add(1, Ordering::Relaxed);
                    crate::sched::block_current_on(crate::sched::WAIT_FS);
                    false
                }
            });
            if taken {
                FS_LOCK_ACQUIRES.fetch_add(1, Ordering::Relaxed);
                return FsGuard;
            }
        }
    }
}

impl Drop for FsGuard {
    fn drop(&mut self) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            FS_OWNER.store(0, Ordering::Relaxed);
            crate::sched::wake_all(crate::sched::WAIT_FS);
        });
    }
}

/// Run `f` with exclusive access to the file system. May block; callers
/// may be preempted inside `f` (interrupts are whatever the caller had).
fn with_fs<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let _g = FsGuard::acquire();
    // Never contended: every path to STATE after boot holds the FS lock.
    let mut st = STATE.lock();
    f(&mut st)
}

fn mounted(st: &mut State) -> Result<&mut Fs<SlaveDisk>, i64> {
    if st.mounted { Ok(&mut st.fs) } else { Err(-errno::EIO) }
}

/// Call `f` for up to `max` entries, in table order; returns the count.
pub fn for_each_entry(max: usize, mut f: impl FnMut(usize, &Entry)) -> Result<usize, i64> {
    with_fs(|st| {
        let fs = mounted(st)?;
        let mut n = 0;
        for e in fs.entries().take(max) {
            f(n, e);
            n += 1;
        }
        Ok(n)
    })
}

/// (root, generation, files, free sectors, writable)
pub fn info() -> Option<(Digest, u64, u32, u64, bool)> {
    with_fs(|st| {
        let writable = st.writable;
        let fs = mounted(st).ok()?;
        let sb = fs.superblock();
        Some((sb.root, sb.generation, sb.files, fs.free_sectors(), writable))
    })
}

pub fn read(name: &str, out: &mut [u8]) -> Result<usize, i64> {
    with_fs(|st| mounted(st)?.read(name, out).map_err(fs_errno))
}

/// Apply a change, then anchor the new root in the ledger as `pid`'s commit.
fn change(pid: u32, op: impl FnOnce(&mut Fs<SlaveDisk>) -> Result<(), FsError>) -> Result<(), i64> {
    with_fs(|st| {
        if !st.writable {
            return Err(-errno::EROFS);
        }
        let fs = mounted(st)?;
        op(fs).map_err(fs_errno)?;
        // Anchor while still holding the FS lock: commits and their ledger
        // records must be in the same order, or a writer preempted between
        // the two would leave an older root as the ledger's newest anchor.
        record_root(kind::FS_COMMIT, axiom_x_ledger::decision::ALLOW, pid, &fs.root());
        Ok(())
    })
}

pub fn write(pid: u32, name: &str, data: &[u8]) -> Result<(), i64> {
    if data.len() > MAX_FILE_SIZE {
        return Err(-errno::EFBIG);
    }
    change(pid, |fs| fs.write(name, data))
}

pub fn delete(pid: u32, name: &str) -> Result<(), i64> {
    change(pid, |fs| fs.delete(name))
}

/// Buffer for loading a program from the file system. Used only inside
/// `with_program`, under the file-system lock, which makes it exclusive.
static mut LOAD_BUF: [u8; MAX_FILE_SIZE] = [0; MAX_FILE_SIZE];

/// Read program `name` (hash-verified) and call `f` with its bytes, holding
/// the file-system lock until `f` returns: the load buffer is shared, so
/// loading and starting the program form one exclusive step.
pub fn with_program<R>(name: &str, f: impl FnOnce(&[u8]) -> R) -> Result<R, i64> {
    let _g = FsGuard::acquire();
    let mut st = STATE.lock();
    if !st.mounted {
        return Err(-errno::EIO);
    }
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(LOAD_BUF) };
    let n = st.fs.read(name, buf).map_err(fs_errno)?;
    if n > buf.len() {
        return Err(-errno::EFBIG);
    }
    drop(st);
    Ok(f(&buf[..n]))
}
