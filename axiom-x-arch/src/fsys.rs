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
//!
//! Status: `partial` — exercised in QEMU; whole-file operations only.

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

fn with_fs<R>(f: impl FnOnce(&mut State) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut STATE.lock()))
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
    let root = with_fs(|st| {
        if !st.writable {
            return Err(-errno::EROFS);
        }
        let fs = mounted(st)?;
        op(fs).map_err(fs_errno)?;
        Ok(fs.root())
    })?;
    record_root(kind::FS_COMMIT, axiom_x_ledger::decision::ALLOW, pid, &root);
    Ok(())
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

/// Buffer for loading a program from the file system (single CPU; used
/// only inside the spawn syscall, with interrupts off).
static mut LOAD_BUF: [u8; MAX_FILE_SIZE] = [0; MAX_FILE_SIZE];

/// Read `name` into the kernel load buffer and return its bytes.
pub fn load_program(name: &str) -> Result<&'static [u8], i64> {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(LOAD_BUF) };
    let n = read(name, buf)?;
    if n > buf.len() {
        return Err(-errno::EFBIG);
    }
    Ok(&buf[..n])
}
