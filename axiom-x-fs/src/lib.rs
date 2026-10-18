//! AXFS: a small copy-on-write, hash-verified file system.
//!
//! Layout (512-byte sectors):
//!
//! ```text
//! sector 0, 1   superblock copies A/B; generation g lives in sector g % 2
//! sector 2..    log of data extents and file-table versions, append-only
//! ```
//!
//! Every change (write, replace, delete) writes the new file data and a new
//! version of the whole file table to *fresh* sectors, then writes the
//! superblock copy that is not current. That superblock write is the commit
//! point: a crash before it leaves the previous version fully intact, so no
//! journal is needed. Old versions stay on disk until space runs out (no
//! reclamation yet).
//!
//! Integrity: each table entry stores the SHA-256 of the file's content and
//! every read re-verifies it; the superblock stores the SHA-256 of the table
//! (the **root hash**), verified at mount. The kernel anchors each root hash
//! in its signed evidence ledger, so a disk that was modified or rolled back
//! is detected (see the kernel's `fsys` module).
//!
//! Status: `partial` — flat namespace (names may contain '/'), whole-file
//! read/write, at most `MAX_FILES` files of `MAX_FILE_SIZE` bytes, no space
//! reclamation, single writer.

#![cfg_attr(not(test), no_std)]

use axiom_x_ledger::{sha256, Sha256};

pub const SECTOR: usize = 512;
pub const MAGIC: [u8; 8] = *b"AXFS0001";
pub const VERSION: u32 = 1;
pub const MAX_FILES: usize = 64;
pub const ENTRY_LEN: usize = 128;
pub const NAME_MAX: usize = 48;
pub const TABLE_BYTES: usize = MAX_FILES * ENTRY_LEN;
pub const TABLE_SECTORS: u64 = (TABLE_BYTES / SECTOR) as u64;
/// First sector of the append-only log.
pub const LOG_START: u64 = 2;
pub const MAX_FILE_SIZE: usize = 256 * 1024;

pub type Digest = [u8; 32];

/// A sector-addressed disk.
pub trait BlockDev {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8; SECTOR]) -> Result<(), ()>;
    fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR]) -> Result<(), ()>;
    /// Make previous writes durable (drive cache flush).
    fn flush(&mut self) -> Result<(), ()>;
    fn sectors(&self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    Io,
    /// Not enough free sectors in the log.
    NoSpace,
    NotFound,
    /// Empty, too long, or containing characters outside `[A-Za-z0-9._/-]`.
    BadName,
    TooLarge,
    TableFull,
    /// A file's content does not match its recorded SHA-256.
    Corrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountError {
    Io,
    /// Both superblock copies blank: a new disk, safe to format.
    Blank,
    /// No intact superblock copy and something that is not blank: never
    /// format over it.
    Unrecognized,
    /// The file table does not match the root hash in the superblock.
    TableCorrupt,
}

/// One file-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: [u8; NAME_MAX],
    pub size: u64,
    pub start: u64,
    pub sectors: u32,
    pub used: bool,
    /// Bumped each time the file is replaced.
    pub version: u64,
    pub digest: Digest,
}

impl Entry {
    const EMPTY: Entry = Entry { name: [0; NAME_MAX], size: 0, start: 0, sectors: 0, used: false, version: 0, digest: [0; 32] };

    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    fn encode(&self, b: &mut [u8]) {
        b[..ENTRY_LEN].fill(0);
        b[0..48].copy_from_slice(&self.name);
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..64].copy_from_slice(&self.start.to_le_bytes());
        b[64..68].copy_from_slice(&self.sectors.to_le_bytes());
        b[68..72].copy_from_slice(&(self.used as u32).to_le_bytes());
        b[72..80].copy_from_slice(&self.version.to_le_bytes());
        b[80..112].copy_from_slice(&self.digest);
    }

    fn decode(b: &[u8]) -> Self {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Entry {
            name: b[0..48].try_into().unwrap(),
            size: u64_at(48),
            start: u64_at(56),
            sectors: u32::from_le_bytes(b[64..68].try_into().unwrap()),
            used: b[68] == 1,
            version: u64_at(72),
            digest: b[80..112].try_into().unwrap(),
        }
    }
}

/// The commit record in sectors 0 and 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub generation: u64,
    pub table_sector: u64,
    pub next_free: u64,
    pub files: u32,
    /// SHA-256 of the file table at `table_sector`.
    pub root: Digest,
    pub total_sectors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SbState {
    Valid(Superblock),
    Blank,
    Bad,
}

impl Superblock {
    fn encode(&self) -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&self.files.to_le_bytes());
        b[16..24].copy_from_slice(&self.generation.to_le_bytes());
        b[24..32].copy_from_slice(&self.table_sector.to_le_bytes());
        b[32..40].copy_from_slice(&self.next_free.to_le_bytes());
        b[40..72].copy_from_slice(&self.root);
        b[72..80].copy_from_slice(&self.total_sectors.to_le_bytes());
        let sum = sha256(&b[0..80]);
        b[80..112].copy_from_slice(&sum);
        b
    }

    fn decode(b: &[u8; SECTOR]) -> SbState {
        if b.iter().all(|&x| x == 0) {
            return SbState::Blank;
        }
        if b[0..8] != MAGIC || sha256(&b[0..80])[..] != b[80..112] {
            return SbState::Bad;
        }
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        SbState::Valid(Superblock {
            files: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            generation: u64_at(16),
            table_sector: u64_at(24),
            next_free: u64_at(32),
            root: b[40..72].try_into().unwrap(),
            total_sectors: u64_at(72),
        })
    }
}

/// A file system on `dev`. All working state lives inside the struct
/// (current table, staged table, encoding buffer: about 24 KiB), and the
/// in-place constructors never move it, so it can sit in a `static` and be
/// used from small kernel stacks.
pub struct Fs<D: BlockDev> {
    dev: D,
    sb: Superblock,
    table: [Entry; MAX_FILES],
    /// Next table version, built here and published by `commit`.
    staged: [Entry; MAX_FILES],
    /// Encoded table (commit) / table read from disk (mount).
    raw: [u8; TABLE_BYTES],
}

const EMPTY_SB: Superblock = Superblock { generation: 0, table_sector: 0, next_free: LOG_START, files: 0, root: [0; 32], total_sectors: 0 };

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._/-".contains(&c))
}

impl<D: BlockDev> Fs<D> {
    /// An unmounted, empty file system on `dev` (usable in a `static`).
    pub const fn new(dev: D) -> Self {
        Fs { dev, sb: EMPTY_SB, table: [Entry::EMPTY; MAX_FILES], staged: [Entry::EMPTY; MAX_FILES], raw: [0; TABLE_BYTES] }
    }

    /// Create an empty file system (generation 1). Use only on a disk whose
    /// superblocks are both blank (`mount` reports `Blank`).
    pub fn format(dev: D) -> Result<Self, FsError> {
        let mut fs = Self::new(dev);
        fs.format_in_place()?;
        Ok(fs)
    }

    /// `format` without moving `self`.
    pub fn format_in_place(&mut self) -> Result<(), FsError> {
        let total = self.dev.sectors();
        if total < LOG_START + TABLE_SECTORS + 1 {
            return Err(FsError::NoSpace);
        }
        self.sb = Superblock { total_sectors: total, ..EMPTY_SB };
        self.table = [Entry::EMPTY; MAX_FILES];
        self.staged = [Entry::EMPTY; MAX_FILES];
        self.commit(LOG_START)
    }

    /// Mount: newest intact superblock copy, then the table it names, which
    /// must hash to the recorded root.
    pub fn mount(dev: D) -> Result<Self, MountError> {
        let mut fs = Self::new(dev);
        fs.mount_in_place()?;
        Ok(fs)
    }

    /// `mount` without moving `self`. On error the state is left empty.
    pub fn mount_in_place(&mut self) -> Result<(), MountError> {
        self.sb = EMPTY_SB;
        self.table = [Entry::EMPTY; MAX_FILES];
        let mut a = [0u8; SECTOR];
        let mut b = [0u8; SECTOR];
        self.dev.read_sector(0, &mut a).map_err(|_| MountError::Io)?;
        self.dev.read_sector(1, &mut b).map_err(|_| MountError::Io)?;
        let sb = match (Superblock::decode(&a), Superblock::decode(&b)) {
            (SbState::Valid(x), SbState::Valid(y)) => {
                if y.generation > x.generation { y } else { x }
            }
            (SbState::Valid(x), _) | (_, SbState::Valid(x)) => x,
            (SbState::Blank, SbState::Blank) => return Err(MountError::Blank),
            _ => return Err(MountError::Unrecognized),
        };
        for i in 0..TABLE_SECTORS as usize {
            let s: &mut [u8; SECTOR] = (&mut self.raw[i * SECTOR..(i + 1) * SECTOR]).try_into().unwrap();
            self.dev.read_sector(sb.table_sector + i as u64, s).map_err(|_| MountError::Io)?;
        }
        if sha256(&self.raw) != sb.root {
            return Err(MountError::TableCorrupt);
        }
        for i in 0..MAX_FILES {
            self.table[i] = Entry::decode(&self.raw[i * ENTRY_LEN..(i + 1) * ENTRY_LEN]);
        }
        self.sb = sb;
        Ok(())
    }

    /// Write the staged table as a new version at `at`, then publish it with
    /// the other superblock copy. The superblock write is the commit point;
    /// on failure the current table is unchanged.
    fn commit(&mut self, at: u64) -> Result<(), FsError> {
        if at + TABLE_SECTORS > self.sb.total_sectors {
            return Err(FsError::NoSpace);
        }
        for i in 0..MAX_FILES {
            self.staged[i].encode(&mut self.raw[i * ENTRY_LEN..(i + 1) * ENTRY_LEN]);
        }
        for i in 0..TABLE_SECTORS as usize {
            let s: &[u8; SECTOR] = self.raw[i * SECTOR..(i + 1) * SECTOR].try_into().unwrap();
            self.dev.write_sector(at + i as u64, s).map_err(|_| FsError::Io)?;
        }
        let next = Superblock {
            generation: self.sb.generation + 1,
            table_sector: at,
            next_free: at + TABLE_SECTORS,
            files: self.staged.iter().filter(|e| e.used).count() as u32,
            root: sha256(&self.raw),
            total_sectors: self.sb.total_sectors,
        };
        // Data and table must be on disk before the superblock names them.
        self.dev.flush().map_err(|_| FsError::Io)?;
        self.dev.write_sector(next.generation % 2, &next.encode()).map_err(|_| FsError::Io)?;
        self.dev.flush().map_err(|_| FsError::Io)?;
        self.sb = next;
        for i in 0..MAX_FILES {
            self.table[i] = self.staged[i];
        }
        Ok(())
    }

    fn stage_current(&mut self) {
        for i in 0..MAX_FILES {
            self.staged[i] = self.table[i];
        }
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.table.iter().position(|e| e.used && e.name() == name)
    }

    /// Create or replace `name` with `data`, atomically.
    pub fn write(&mut self, name: &str, data: &[u8]) -> Result<(), FsError> {
        if !valid_name(name) {
            return Err(FsError::BadName);
        }
        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::TooLarge);
        }
        let slot = match self.find(name) {
            Some(i) => i,
            None => self.table.iter().position(|e| !e.used).ok_or(FsError::TableFull)?,
        };
        let sectors = data.len().div_ceil(SECTOR) as u64;
        let start = self.sb.next_free;
        if start + sectors + TABLE_SECTORS > self.sb.total_sectors {
            return Err(FsError::NoSpace);
        }
        for (i, chunk) in data.chunks(SECTOR).enumerate() {
            let mut s = [0u8; SECTOR];
            s[..chunk.len()].copy_from_slice(chunk);
            self.dev.write_sector(start + i as u64, &s).map_err(|_| FsError::Io)?;
        }
        self.stage_current();
        let old = self.table[slot];
        let mut name_buf = [0u8; NAME_MAX];
        name_buf[..name.len()].copy_from_slice(name.as_bytes());
        self.staged[slot] = Entry {
            name: name_buf,
            size: data.len() as u64,
            start,
            sectors: sectors as u32,
            used: true,
            version: if old.used { old.version + 1 } else { 1 },
            digest: sha256(data),
        };
        self.commit(start + sectors)
    }

    /// Read `name` into `out` (up to `out.len()` bytes) and return the
    /// file's full size. The whole content is re-hashed and must match the
    /// recorded SHA-256, even when `out` is shorter than the file.
    pub fn read(&mut self, name: &str, out: &mut [u8]) -> Result<usize, FsError> {
        let i = self.find(name).ok_or(FsError::NotFound)?;
        self.read_slot(i, out)
    }

    fn read_slot(&mut self, slot: usize, out: &mut [u8]) -> Result<usize, FsError> {
        let e = self.table[slot];
        let mut hasher = Sha256::new();
        let mut left = e.size as usize;
        let mut copied = 0;
        for i in 0..e.sectors as u64 {
            let mut s = [0u8; SECTOR];
            self.dev.read_sector(e.start + i, &mut s).map_err(|_| FsError::Io)?;
            let n = left.min(SECTOR);
            hasher.update(&s[..n]);
            let c = n.min(out.len() - copied);
            out[copied..copied + c].copy_from_slice(&s[..c]);
            copied += c;
            left -= n;
        }
        if hasher.finalize() != e.digest {
            return Err(FsError::Corrupt);
        }
        Ok(e.size as usize)
    }

    pub fn delete(&mut self, name: &str) -> Result<(), FsError> {
        let i = self.find(name).ok_or(FsError::NotFound)?;
        self.stage_current();
        self.staged[i] = Entry::EMPTY;
        let at = self.sb.next_free;
        self.commit(at)
    }

    /// Files in table order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.table.iter().filter(|e| e.used)
    }

    pub fn stat(&self, name: &str) -> Option<Entry> {
        self.find(name).map(|i| self.table[i])
    }

    /// SHA-256 of the current file table: identifies the whole state.
    pub fn root(&self) -> Digest {
        self.sb.root
    }

    pub fn superblock(&self) -> Superblock {
        self.sb
    }

    /// Free sectors left in the log.
    pub fn free_sectors(&self) -> u64 {
        self.sb.total_sectors - self.sb.next_free
    }

    /// Verify every file against its digest; returns the count, or the
    /// first corrupt file's name.
    pub fn verify_all(&mut self) -> Result<usize, [u8; NAME_MAX]> {
        let mut n = 0;
        for i in 0..MAX_FILES {
            if !self.table[i].used {
                continue;
            }
            if self.read_slot(i, &mut []).is_err() {
                return Err(self.table[i].name);
            }
            n += 1;
        }
        Ok(n)
    }

    /// Give back the device (e.g. to remount in tests).
    pub fn into_dev(self) -> D {
        self.dev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// In-memory disk. `write_budget`, when set, makes writes fail after
    /// that many sectors: a crash at an arbitrary point.
    #[derive(Clone)]
    struct MemDev {
        sectors: Vec<[u8; SECTOR]>,
        write_budget: Option<usize>,
    }

    impl MemDev {
        fn new(n: usize) -> Self {
            Self { sectors: std::vec![[0; SECTOR]; n], write_budget: None }
        }
    }

    impl BlockDev for MemDev {
        fn read_sector(&mut self, lba: u64, buf: &mut [u8; SECTOR]) -> Result<(), ()> {
            *buf = *self.sectors.get(lba as usize).ok_or(())?;
            Ok(())
        }
        fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR]) -> Result<(), ()> {
            if let Some(b) = self.write_budget.as_mut() {
                if *b == 0 {
                    return Err(());
                }
                *b -= 1;
            }
            *self.sectors.get_mut(lba as usize).ok_or(())? = *buf;
            Ok(())
        }
        fn flush(&mut self) -> Result<(), ()> {
            Ok(())
        }
        fn sectors(&self) -> u64 {
            self.sectors.len() as u64
        }
    }

    fn read_all(fs: &mut Fs<MemDev>, name: &str) -> Result<Vec<u8>, FsError> {
        let size = fs.stat(name).ok_or(FsError::NotFound)?.size as usize;
        let mut v = std::vec![0u8; size];
        fs.read(name, &mut v)?;
        Ok(v)
    }

    #[test]
    fn blank_disk_formats_and_mounts() {
        assert_eq!(Fs::mount(MemDev::new(256)).err(), Some(MountError::Blank));
        let fs = Fs::format(MemDev::new(256)).unwrap();
        let root = fs.root();
        let fs = Fs::mount(fs.into_dev()).unwrap();
        assert_eq!(fs.root(), root);
        assert_eq!(fs.entries().count(), 0);
    }

    #[test]
    fn write_read_replace_delete_survive_remount() {
        let mut fs = Fs::format(MemDev::new(512)).unwrap();
        let big: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        fs.write("/bin/hello", &big).unwrap();
        fs.write("/etc/motd", b"welcome").unwrap();
        fs.write("/etc/motd", b"welcome back").unwrap(); // replace
        let r1 = fs.root();
        let mut fs = Fs::mount(fs.into_dev()).unwrap();
        assert_eq!(fs.root(), r1);
        assert_eq!(read_all(&mut fs, "/bin/hello").unwrap(), big);
        assert_eq!(read_all(&mut fs, "/etc/motd").unwrap(), b"welcome back");
        assert_eq!(fs.stat("/etc/motd").unwrap().version, 2);
        fs.delete("/etc/motd").unwrap();
        assert_ne!(fs.root(), r1, "every change has a new root");
        let mut fs = Fs::mount(fs.into_dev()).unwrap();
        assert_eq!(fs.stat("/etc/motd"), None);
        assert_eq!(read_all(&mut fs, "/bin/hello").unwrap(), big);
        assert_eq!(fs.verify_all(), Ok(1));
    }

    #[test]
    fn empty_file_short_read_and_errors() {
        let mut fs = Fs::format(MemDev::new(256)).unwrap();
        fs.write("empty", b"").unwrap();
        assert_eq!(read_all(&mut fs, "empty").unwrap(), b"");
        fs.write("abc", b"abcdef").unwrap();
        let mut two = [0u8; 2];
        assert_eq!(fs.read("abc", &mut two), Ok(6), "returns full size");
        assert_eq!(&two, b"ab");
        assert_eq!(fs.write("", b"x"), Err(FsError::BadName));
        assert_eq!(fs.write("a b", b"x"), Err(FsError::BadName));
        assert_eq!(fs.write(&"n".repeat(49), b"x"), Err(FsError::BadName));
        assert_eq!(fs.write("big", &std::vec![0; MAX_FILE_SIZE + 1]), Err(FsError::TooLarge));
        assert_eq!(fs.delete("nope"), Err(FsError::NotFound));
    }

    /// Crash after every possible number of sector writes during an update:
    /// remounting always yields either the old or the new state, intact.
    #[test]
    fn crash_at_any_point_leaves_old_or_new_state() {
        let mut fs = Fs::format(MemDev::new(512)).unwrap();
        fs.write("keep", b"stable content").unwrap();
        fs.write("doc", b"version one").unwrap();
        let base = fs.into_dev();
        let new = std::vec![0x5au8; 1500]; // 3 data sectors + 16 table + 1 sb
        for budget in 0..=20 {
            let mut dev = base.clone();
            dev.write_budget = Some(budget);
            let mut fs = Fs::mount(dev).unwrap();
            let done = fs.write("doc", &new).is_ok();
            let mut dev = fs.into_dev();
            dev.write_budget = None;
            let mut fs = Fs::mount(dev).expect("must always mount after a crash");
            let doc = read_all(&mut fs, "doc").unwrap();
            assert!(doc == b"version one" || doc == new, "budget {budget}: torn file");
            assert_eq!(doc == new, done, "budget {budget}: committed iff write returned Ok");
            assert_eq!(read_all(&mut fs, "keep").unwrap(), b"stable content");
        }
    }

    #[test]
    fn tampered_data_is_detected_on_read() {
        let mut fs = Fs::format(MemDev::new(256)).unwrap();
        fs.write("secret", b"the original bytes").unwrap();
        let e = fs.stat("secret").unwrap();
        let mut dev = fs.into_dev();
        dev.sectors[e.start as usize][3] ^= 1;
        let mut fs = Fs::mount(dev).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(fs.read("secret", &mut out), Err(FsError::Corrupt));
        assert!(fs.verify_all().is_err());
    }

    #[test]
    fn tampered_table_fails_mount_and_damage_never_formats() {
        let mut fs = Fs::format(MemDev::new(256)).unwrap();
        fs.write("f", b"x").unwrap();
        let t = fs.superblock().table_sector as usize;
        let mut dev = fs.into_dev();
        dev.sectors[t][60] ^= 1; // e.g. change a file's start sector
        assert_eq!(Fs::mount(dev.clone()).err(), Some(MountError::TableCorrupt));
        // Both superblocks damaged: unrecognized, not blank (no reformat).
        dev.sectors[0][1] ^= 1;
        dev.sectors[1][1] ^= 1;
        assert_eq!(Fs::mount(dev).err(), Some(MountError::Unrecognized));
    }

    #[test]
    fn torn_newer_superblock_falls_back() {
        let mut fs = Fs::format(MemDev::new(256)).unwrap();
        fs.write("a", b"first").unwrap();
        let old_root = fs.root();
        fs.write("a", b"second").unwrap();
        let g = fs.superblock().generation;
        let mut dev = fs.into_dev();
        dev.sectors[(g % 2) as usize][..256].fill(0xAA); // tear the newest copy
        let mut fs = Fs::mount(dev).unwrap();
        assert_eq!(fs.root(), old_root);
        assert_eq!(read_all(&mut fs, "a").unwrap(), b"first");
    }

    #[test]
    fn out_of_space_is_an_error_not_corruption() {
        let mut fs = Fs::format(MemDev::new(LOG_START as usize + 3 * TABLE_SECTORS as usize + 4)).unwrap();
        fs.write("a", b"1").unwrap();
        assert_eq!(fs.write("b", &[0u8; 4000]), Err(FsError::NoSpace));
        let mut fs = Fs::mount(fs.into_dev()).unwrap();
        assert_eq!(read_all(&mut fs, "a").unwrap(), b"1");
    }
}
