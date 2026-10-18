//! On-disk layout of a persisted ledger (sector-addressed, 512-byte sectors).
//!
//! ```text
//! sector 0      superblock: magic, version, record count, boot count, chain
//!               head, then SHA-256 of those fields (corruption check)
//! sector 1..    record slots, 4 per sector: encoded record (96) + digest (32)
//!               record `seq` lives at sector 1 + seq / 4, slot seq % 4
//! ```
//!
//! The superblock checksum only detects accidental corruption; tampering is
//! caught by re-verifying the hash chain from genesis (see `verify_window`),
//! which is what the kernel does at boot before resuming the chain.

use crate::{sha256, Digest, Record, RECORD_LEN};

pub const SECTOR: usize = 512;
/// One stored record: encoding + its digest.
pub const SLOT: usize = RECORD_LEN + 32;
pub const SLOTS_PER_SECTOR: usize = SECTOR / SLOT;
pub const MAGIC: [u8; 8] = *b"AXLEDGR1";
pub const VERSION: u32 = 1;

/// Sector holding record `seq`, and the slot's byte offset in it.
pub fn slot_location(seq: u64) -> (u64, usize) {
    (1 + seq / SLOTS_PER_SECTOR as u64, (seq % SLOTS_PER_SECTOR as u64) as usize * SLOT)
}

/// Records that fit on a disk of `sectors` sectors.
pub fn capacity(sectors: u64) -> u64 {
    sectors.saturating_sub(1) * SLOTS_PER_SECTOR as u64
}

pub fn encode_slot(record: &Record, digest: &Digest) -> [u8; SLOT] {
    let mut b = [0u8; SLOT];
    b[..RECORD_LEN].copy_from_slice(&record.encode());
    b[RECORD_LEN..].copy_from_slice(digest);
    b
}

pub fn decode_slot(b: &[u8]) -> (Record, Digest) {
    let rec = Record::decode(b[..RECORD_LEN].try_into().unwrap());
    let digest: Digest = b[RECORD_LEN..SLOT].try_into().unwrap();
    (rec, digest)
}

/// What sector 0 says about the persisted chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// Records persisted (the next sequence number).
    pub total: u64,
    /// Digest of record `total - 1` (zeros when empty).
    pub head: Digest,
    /// Boots that have used this ledger.
    pub boots: u64,
}

/// Why sector 0 is not a usable superblock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperblockError {
    /// All zeros: a blank disk, safe to format.
    Blank,
    /// Not ours (wrong magic / version): never format over it.
    Foreign,
    /// Ours, but the checksum does not match: never format over it.
    Corrupt,
}

impl Superblock {
    pub fn encode(&self) -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[16..24].copy_from_slice(&self.total.to_le_bytes());
        b[24..32].copy_from_slice(&self.boots.to_le_bytes());
        b[32..64].copy_from_slice(&self.head);
        let sum = sha256(&b[0..64]);
        b[64..96].copy_from_slice(&sum);
        b
    }

    pub fn decode(b: &[u8; SECTOR]) -> Result<Self, SuperblockError> {
        if b.iter().all(|&x| x == 0) {
            return Err(SuperblockError::Blank);
        }
        if b[0..8] != MAGIC || u32::from_le_bytes(b[8..12].try_into().unwrap()) != VERSION {
            return Err(SuperblockError::Foreign);
        }
        if sha256(&b[0..64])[..] != b[64..96] {
            return Err(SuperblockError::Corrupt);
        }
        Ok(Self {
            total: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            boots: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            head: b[32..64].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_window, Ledger};

    #[test]
    fn layout() {
        assert_eq!(SLOT, 128);
        assert_eq!(SLOTS_PER_SECTOR, 4);
        assert_eq!(slot_location(0), (1, 0));
        assert_eq!(slot_location(3), (1, 384));
        assert_eq!(slot_location(4), (2, 0));
        assert_eq!(capacity(8192), 8191 * 4);
    }

    #[test]
    fn superblock_roundtrip_and_errors() {
        let sb = Superblock { total: 1234, head: [7; 32], boots: 3 };
        let enc = sb.encode();
        assert_eq!(Superblock::decode(&enc), Ok(sb));
        assert_eq!(Superblock::decode(&[0; SECTOR]), Err(SuperblockError::Blank));
        let mut foreign = [0u8; SECTOR];
        foreign[0] = 0xEB; // e.g. a boot sector
        assert_eq!(Superblock::decode(&foreign), Err(SuperblockError::Foreign));
        let mut corrupt = enc;
        corrupt[20] ^= 1; // flip a bit of `total`
        assert_eq!(Superblock::decode(&corrupt), Err(SuperblockError::Corrupt));
    }

    /// Simulate two boots on one disk: persist boot 1, resume in boot 2,
    /// and verify the combined chain from genesis.
    #[test]
    fn chain_continues_across_resume() {
        let mut disk = [[0u8; SLOT]; 32];
        let rec = |pid| Record { kind: 15, decision: 1, pid, subject: pid, ..Record::default() };

        let mut boot1: Ledger<8> = Ledger::new();
        for i in 0..5 {
            boot1.append(rec(i));
        }
        for seq in 0..boot1.total() {
            let (r, d) = boot1.get(seq).unwrap();
            disk[seq as usize] = encode_slot(&r, &d);
        }
        let sb = Superblock { total: boot1.total(), head: boot1.head(), boots: 1 };

        let mut boot2: Ledger<8> = Ledger::new();
        boot2.resume(sb.total, sb.head);
        assert_eq!(boot2.oldest(), sb.total, "nothing older is in memory");
        assert!(boot2.get(0).is_none());
        for i in 0..4 {
            boot2.append(rec(100 + i));
        }
        let (first_new, _) = boot2.get(sb.total).unwrap();
        assert_eq!(first_new.prev, sb.head, "boot 2 links to boot 1's head");

        let get = |seq: u64| boot2.get(seq).or_else(|| Some(decode_slot(&disk[seq as usize])));
        assert_eq!(verify_window(0, boot2.total(), get), Ok(boot2.head()));

        // One flipped byte on disk is found at boot-time verification.
        disk[2][40] ^= 0x01;
        let get = |seq: u64| boot2.get(seq).or_else(|| Some(decode_slot(&disk[seq as usize])));
        assert_eq!(verify_window(0, boot2.total(), get), Err(2));
    }
}
