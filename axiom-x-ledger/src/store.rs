//! On-disk layout of a persisted ledger, format v3 (512-byte sectors).
//!
//! ```text
//! sector 0, 1     superblock copies A/B; generation g lives in sector g % 2
//! sector 2        journal header (target sector, data checksum)
//! sector 3        journal data (the full new image of the target sector)
//! sector 4..259   checkpoint archive: one signed checkpoint per sector,
//!                 written once to a fresh sector, never rewritten
//! sector 260..    record slots, 4 per sector: encoded record (96) + digest (32)
//! ```
//!
//! Crash safety:
//! - A save writes the superblock copy that is *not* current, so a torn
//!   superblock write leaves the previous one intact (`pick_superblock`).
//! - The only in-place rewrite of persisted data (the partly filled last
//!   record sector) goes through the journal first; a complete journal is
//!   replayed at boot, a torn one is ignored (the target was not touched).
//! - Sectors that hold only new records are not referenced by any
//!   superblock until the save completes, so they need no journal.
//!
//! Integrity: editing records breaks the hash chain; replacing the whole
//! chain breaks the Ed25519 checkpoint signature (a signed tree head over
//! count, boots and head, which commits to all earlier records). The
//! archive keeps every signed checkpoint, so a verifier can check that each
//! past signed head is a prefix of the current chain (`verify_archive`).

use crate::ed25519::{self, Keypair, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::{sha256, Digest, Record, RECORD_LEN};

pub const SECTOR: usize = 512;
/// One stored record: encoding + its digest.
pub const SLOT: usize = RECORD_LEN + 32;
pub const SLOTS_PER_SECTOR: usize = SECTOR / SLOT;
pub const MAGIC: [u8; 8] = *b"AXLEDGR1";
pub const VERSION: u32 = 3;
const FLAG_SIGNED: u32 = 1;

pub const JOURNAL_HEADER_SECTOR: u64 = 2;
pub const JOURNAL_DATA_SECTOR: u64 = 3;
pub const CHECKPOINT_BASE: u64 = 4;
pub const CHECKPOINT_SECTORS: u64 = 256;
pub const RECORD_BASE: u64 = CHECKPOINT_BASE + CHECKPOINT_SECTORS;

const JOURNAL_MAGIC: [u8; 8] = *b"AXJRNL01";
const CHECKPOINT_MAGIC: [u8; 8] = *b"AXCKPT01";

/// Domain separation for checkpoint signatures.
pub const CHECKPOINT_DOMAIN: &[u8; 28] = b"AXIOM-X-LEDGER-CHECKPOINT-V1";
/// Length of the signed checkpoint message.
pub const CHECKPOINT_MSG_LEN: usize = 28 + 8 + 8 + 32 + 32;

/// Sector holding superblock generation `g`.
pub fn superblock_sector(generation: u64) -> u64 {
    generation % 2
}

/// Sector holding record `seq`, and the slot's byte offset in it.
pub fn slot_location(seq: u64) -> (u64, usize) {
    (RECORD_BASE + seq / SLOTS_PER_SECTOR as u64, (seq % SLOTS_PER_SECTOR as u64) as usize * SLOT)
}

/// Records that fit on a disk of `sectors` sectors.
pub fn capacity(sectors: u64) -> u64 {
    sectors.saturating_sub(RECORD_BASE) * SLOTS_PER_SECTOR as u64
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

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ============================================================================
// Signed checkpoint (signed tree head)
// ============================================================================

/// State of the chain at a save: what a signature attests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Records persisted (the next sequence number).
    pub total: u64,
    /// Boots that have used this ledger.
    pub boots: u64,
    /// Digest of record `total - 1` (zeros when empty).
    pub head: Digest,
    /// (signer public key, signature), if signed.
    pub signature: Option<([u8; PUBLIC_KEY_LEN], [u8; SIGNATURE_LEN])>,
}

/// Result of checking a checkpoint signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Unsigned,
    Valid,
    /// Validly formed but by a key other than the expected one.
    WrongKey,
    /// Does not verify (forged or modified checkpoint).
    Invalid,
}

impl Checkpoint {
    pub fn unsigned(total: u64, head: Digest, boots: u64) -> Self {
        Self { total, boots, head, signature: None }
    }

    /// The bytes a checkpoint signature covers.
    pub fn message(&self, public: &[u8; PUBLIC_KEY_LEN]) -> [u8; CHECKPOINT_MSG_LEN] {
        let mut m = [0u8; CHECKPOINT_MSG_LEN];
        m[0..28].copy_from_slice(CHECKPOINT_DOMAIN);
        m[28..36].copy_from_slice(&self.total.to_le_bytes());
        m[36..44].copy_from_slice(&self.boots.to_le_bytes());
        m[44..76].copy_from_slice(&self.head);
        m[76..108].copy_from_slice(public);
        m
    }

    pub fn sign(&mut self, key: &Keypair) {
        let sig = key.sign(&self.message(&key.public));
        self.signature = Some((key.public, sig));
    }

    /// Check the signature against the key the verifier trusts.
    pub fn status(&self, trusted: &[u8; PUBLIC_KEY_LEN]) -> SignatureStatus {
        match &self.signature {
            None => SignatureStatus::Unsigned,
            Some((public, sig)) => {
                if !ed25519::verify(public, &self.message(public), sig) {
                    SignatureStatus::Invalid
                } else if public != trusted {
                    SignatureStatus::WrongKey
                } else {
                    SignatureStatus::Valid
                }
            }
        }
    }

    /// Fields shared by the superblock and archive encodings (0..152).
    fn encode_into(&self, b: &mut [u8]) {
        b[8..16].copy_from_slice(&self.total.to_le_bytes());
        b[16..24].copy_from_slice(&self.boots.to_le_bytes());
        b[24..56].copy_from_slice(&self.head);
        if let Some((public, sig)) = &self.signature {
            b[56..88].copy_from_slice(public);
            b[88..152].copy_from_slice(sig);
        }
    }

    fn decode_from(b: &[u8], signed: bool) -> Self {
        Self {
            total: u64_at(b, 8),
            boots: u64_at(b, 16),
            head: b[24..56].try_into().unwrap(),
            signature: signed.then(|| (b[56..88].try_into().unwrap(), b[88..152].try_into().unwrap())),
        }
    }

    /// One archive sector: magic, flag, checkpoint, checksum.
    pub fn encode_archive(&self) -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&CHECKPOINT_MAGIC);
        self.encode_into(&mut b);
        b[152] = self.signature.is_some() as u8;
        let sum = sha256(&b[0..160]);
        b[160..192].copy_from_slice(&sum);
        b
    }

    pub fn decode_archive(b: &[u8; SECTOR]) -> Option<Self> {
        if b[0..8] != CHECKPOINT_MAGIC || sha256(&b[0..160])[..] != b[160..192] {
            return None;
        }
        Some(Self::decode_from(b, b[152] == 1))
    }
}

// ============================================================================
// Superblock (two alternating copies)
// ============================================================================

/// What a superblock copy says about the persisted chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// The latest signed checkpoint.
    pub checkpoint: Checkpoint,
    /// Bumped on every save; the valid copy with the highest wins.
    pub generation: u64,
    /// Checkpoints archived (sectors `CHECKPOINT_BASE..+archived`).
    pub archived: u64,
}

/// Why a superblock copy is not usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperblockError {
    /// All zeros: never written.
    Blank,
    /// Not ours (wrong magic / version).
    Foreign,
    /// Ours, but the checksum does not match (e.g. a torn write).
    Corrupt,
}

impl Superblock {
    pub fn encode(&self) -> [u8; SECTOR] {
        // 0..8 magic | 8..152 checkpoint | 152..156 version | 156..160 flags
        // 160..168 generation | 168..176 archived | 176..208 SHA-256(0..176)
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&MAGIC);
        self.checkpoint.encode_into(&mut b);
        b[152..156].copy_from_slice(&VERSION.to_le_bytes());
        let flags = if self.checkpoint.signature.is_some() { FLAG_SIGNED } else { 0 };
        b[156..160].copy_from_slice(&flags.to_le_bytes());
        b[160..168].copy_from_slice(&self.generation.to_le_bytes());
        b[168..176].copy_from_slice(&self.archived.to_le_bytes());
        let sum = sha256(&b[0..176]);
        b[176..208].copy_from_slice(&sum);
        b
    }

    pub fn decode(b: &[u8; SECTOR]) -> Result<Self, SuperblockError> {
        if b.iter().all(|&x| x == 0) {
            return Err(SuperblockError::Blank);
        }
        if b[0..8] != MAGIC || u32::from_le_bytes(b[152..156].try_into().unwrap()) != VERSION {
            return Err(SuperblockError::Foreign);
        }
        if sha256(&b[0..176])[..] != b[176..208] {
            return Err(SuperblockError::Corrupt);
        }
        let flags = u32::from_le_bytes(b[156..160].try_into().unwrap());
        Ok(Self {
            checkpoint: Checkpoint::decode_from(b, flags & FLAG_SIGNED != 0),
            generation: u64_at(b, 160),
            archived: u64_at(b, 168),
        })
    }
}

/// Which superblock copy to trust at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// Use this copy (and which sector it came from).
    Use(Superblock, u64),
    /// Both copies blank: a new disk, safe to format.
    Blank,
    /// No valid copy, and at least one is not blank: never format over it.
    Refuse(SuperblockError),
}

/// Choose between copy A (sector 0) and copy B (sector 1). The newest valid
/// copy wins, whatever state the other copy is in: a torn write can garble
/// any byte of a sector, magic included, so a damaged copy may look
/// "foreign", and one intact, checksummed copy is proof the disk is ours.
/// Without any valid copy, only a disk whose copies are *both* blank may be
/// formatted, so damaging the superblocks can never trick the kernel into
/// erasing evidence.
pub fn pick_superblock(a: Result<Superblock, SuperblockError>, b: Result<Superblock, SuperblockError>) -> Pick {
    match (a, b) {
        (Ok(x), Ok(y)) => {
            if y.generation > x.generation { Pick::Use(y, 1) } else { Pick::Use(x, 0) }
        }
        (Ok(x), Err(_)) => Pick::Use(x, 0),
        (Err(_), Ok(y)) => Pick::Use(y, 1),
        (Err(SuperblockError::Blank), Err(SuperblockError::Blank)) => Pick::Blank,
        (Err(SuperblockError::Foreign), _) | (_, Err(SuperblockError::Foreign)) => Pick::Refuse(SuperblockError::Foreign),
        _ => Pick::Refuse(SuperblockError::Corrupt),
    }
}

// ============================================================================
// Journal (for the one in-place rewrite)
// ============================================================================

/// A pending in-place write: `target` sector must become the journal data
/// sector, whose SHA-256 is `data_sum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub target: u64,
    pub data_sum: Digest,
}

impl JournalHeader {
    pub fn for_data(target: u64, data: &[u8; SECTOR]) -> Self {
        Self { target, data_sum: sha256(data) }
    }

    pub fn encode(&self) -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&JOURNAL_MAGIC);
        b[8..16].copy_from_slice(&self.target.to_le_bytes());
        b[16..48].copy_from_slice(&self.data_sum);
        let sum = sha256(&b[0..48]);
        b[48..80].copy_from_slice(&sum);
        b
    }

    /// A header that is intact (zeros / torn / foreign headers are `None`).
    pub fn decode(b: &[u8; SECTOR]) -> Option<Self> {
        if b[0..8] != JOURNAL_MAGIC || sha256(&b[0..48])[..] != b[48..80] {
            return None;
        }
        Some(Self { target: u64_at(b, 8), data_sum: b[16..48].try_into().unwrap() })
    }

    /// True when `data` is the complete journaled image (safe to replay).
    pub fn matches(&self, data: &[u8; SECTOR]) -> bool {
        sha256(data) == self.data_sum
    }
}

// ============================================================================
// Archive verification
// ============================================================================

/// Why an archived checkpoint fails verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveError {
    /// Entry unreadable or not a checkpoint.
    Unreadable,
    /// Not signed by the trusted key (or not signed at all).
    BadSignature(SignatureStatus),
    /// Record count went down: history was rolled back.
    NotMonotonic,
    /// The signed head is not the chain's digest at that point: the chain
    /// that key holder attested is not a prefix of this one.
    NotAPrefix,
}

/// Verify archived checkpoints `0..count` against the current chain: each
/// signed by `trusted`, record counts non-decreasing, and each signed head
/// equal to the chain's digest of record `total - 1`. Returns the number
/// verified, or `(index, why)` for the first failure.
pub fn verify_archive(
    count: u64,
    trusted: &[u8; PUBLIC_KEY_LEN],
    mut entry: impl FnMut(u64) -> Option<Checkpoint>,
    mut digest_of: impl FnMut(u64) -> Option<Digest>,
) -> Result<u64, (u64, ArchiveError)> {
    let mut last_total = 0;
    for i in 0..count {
        let c = entry(i).ok_or((i, ArchiveError::Unreadable))?;
        match c.status(trusted) {
            SignatureStatus::Valid => {}
            s => return Err((i, ArchiveError::BadSignature(s))),
        }
        if c.total < last_total {
            return Err((i, ArchiveError::NotMonotonic));
        }
        let expected = if c.total == 0 { Some([0u8; 32]) } else { digest_of(c.total - 1) };
        if expected != Some(c.head) {
            return Err((i, ArchiveError::NotAPrefix));
        }
        last_total = c.total;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_window, Ledger};

    #[test]
    fn layout() {
        assert_eq!(SLOT, 128);
        assert_eq!(SLOTS_PER_SECTOR, 4);
        assert_eq!(RECORD_BASE, 260);
        assert_eq!(slot_location(0), (260, 0));
        assert_eq!(slot_location(5), (261, 128));
        assert_eq!(capacity(8192), (8192 - 260) * 4);
        assert_eq!((superblock_sector(1), superblock_sector(2)), (1, 0));
    }

    fn sb(total: u64, generation: u64) -> Superblock {
        Superblock { checkpoint: Checkpoint::unsigned(total, [total as u8; 32], 1), generation, archived: 0 }
    }

    #[test]
    fn superblock_roundtrip_and_errors() {
        let s = sb(1234, 7);
        assert_eq!(Superblock::decode(&s.encode()), Ok(s));
        assert_eq!(Superblock::decode(&[0; SECTOR]), Err(SuperblockError::Blank));
        let mut foreign = [0u8; SECTOR];
        foreign[0] = 0xEB;
        assert_eq!(Superblock::decode(&foreign), Err(SuperblockError::Foreign));
        let mut torn = s.encode();
        torn[100] ^= 1;
        assert_eq!(Superblock::decode(&torn), Err(SuperblockError::Corrupt));
        // A v2 disk (version field elsewhere) is not ours.
        assert_eq!(Superblock::decode(&[0x41; SECTOR]), Err(SuperblockError::Foreign));
    }

    #[test]
    fn pick_prefers_newest_valid_and_never_formats_over_damage() {
        let (old, new) = (sb(10, 4), sb(20, 5));
        assert_eq!(pick_superblock(Ok(old), Ok(new)), Pick::Use(new, 1));
        assert_eq!(pick_superblock(Ok(new), Ok(old)), Pick::Use(new, 0));
        // Torn write of the newer copy: fall back to the older one.
        assert_eq!(pick_superblock(Ok(old), Err(SuperblockError::Corrupt)), Pick::Use(old, 0));
        assert_eq!(pick_superblock(Err(SuperblockError::Blank), Ok(new)), Pick::Use(new, 1));
        assert_eq!(pick_superblock(Err(SuperblockError::Blank), Err(SuperblockError::Blank)), Pick::Blank);
        assert_eq!(
            pick_superblock(Err(SuperblockError::Corrupt), Err(SuperblockError::Blank)),
            Pick::Refuse(SuperblockError::Corrupt)
        );
        // A torn write that garbled the magic looks foreign: the intact
        // copy still proves the disk is ours (regression: this bricked the
        // ledger in the QEMU torn-superblock test).
        let mut torn = new.encode();
        torn[..256].fill(0xAA);
        assert_eq!(Superblock::decode(&torn), Err(SuperblockError::Foreign));
        assert_eq!(pick_superblock(Ok(old), Superblock::decode(&torn)), Pick::Use(old, 0));
        // Without any valid copy, unrecognized data is never formatted over.
        assert_eq!(
            pick_superblock(Err(SuperblockError::Foreign), Err(SuperblockError::Blank)),
            Pick::Refuse(SuperblockError::Foreign)
        );
    }

    #[test]
    fn journal_replays_only_complete_images() {
        let data = [0x5a; SECTOR];
        let h = JournalHeader::for_data(300, &data);
        let dec = JournalHeader::decode(&h.encode()).unwrap();
        assert_eq!(dec, h);
        assert!(dec.matches(&data));
        let mut torn = data;
        torn[400] = 0;
        assert!(!dec.matches(&torn), "torn journal data must not be replayed");
        let mut torn_hdr = h.encode();
        torn_hdr[10] ^= 1;
        assert_eq!(JournalHeader::decode(&torn_hdr), None);
        assert_eq!(JournalHeader::decode(&[0; SECTOR]), None, "cleared journal");
    }

    #[test]
    fn signed_checkpoint_and_attacks() {
        let key = Keypair::from_seed(&[1; 32]);
        let other = Keypair::from_seed(&[2; 32]);
        let mut c = Checkpoint::unsigned(931, [9; 32], 2);
        assert_eq!(c.status(&key.public), SignatureStatus::Unsigned);
        c.sign(&key);
        let s = Superblock { checkpoint: c, generation: 3, archived: 1 };
        let dec = Superblock::decode(&s.encode()).unwrap();
        assert_eq!(dec, s);
        assert_eq!(dec.checkpoint.status(&key.public), SignatureStatus::Valid);
        assert_eq!(dec.checkpoint.status(&other.public), SignatureStatus::WrongKey);
        let mut forged = dec.checkpoint;
        forged.head[0] ^= 1;
        assert_eq!(forged.status(&key.public), SignatureStatus::Invalid);
        let mut rolled = dec.checkpoint;
        rolled.total -= 1;
        assert_eq!(rolled.status(&key.public), SignatureStatus::Invalid);
        assert_eq!(Checkpoint::decode_archive(&c.encode_archive()), Some(c));
    }

    /// Two boots on one disk, with the archive checked against the chain.
    #[test]
    fn resume_and_archive_verify_against_chain() {
        let key = Keypair::from_seed(&[3; 32]);
        let rec = |pid| Record { kind: 15, decision: 1, pid, subject: pid, ..Record::default() };
        let mut disk = std::vec::Vec::new();
        let mut archive = std::vec::Vec::new();

        let mut boot1: Ledger<8> = Ledger::new();
        for i in 0..5 {
            boot1.append(rec(i));
        }
        for seq in 0..boot1.total() {
            disk.push(boot1.get(seq).unwrap());
        }
        let mut c1 = Checkpoint::unsigned(boot1.total(), boot1.head(), 1);
        c1.sign(&key);
        archive.push(c1);

        let mut boot2: Ledger<8> = Ledger::new();
        boot2.resume(c1.total, c1.head);
        for i in 0..4 {
            boot2.append(rec(100 + i));
        }
        for seq in c1.total..boot2.total() {
            disk.push(boot2.get(seq).unwrap());
        }
        let mut c2 = Checkpoint::unsigned(boot2.total(), boot2.head(), 2);
        c2.sign(&key);
        archive.push(c2);

        let get = |s: u64| disk.get(s as usize).copied();
        assert_eq!(verify_window(0, boot2.total(), get), Ok(boot2.head()));
        let digest_of = |s: u64| disk.get(s as usize).map(|(_, d)| *d);
        assert_eq!(verify_archive(2, &key.public, |i| archive.get(i as usize).copied(), digest_of), Ok(2));

        // A checkpoint whose head is not this chain's digest at that point.
        let mut fork = c1;
        fork.head[5] ^= 1;
        fork.sign(&key); // even validly signed by the key holder
        let forked = [fork, c2];
        assert_eq!(
            verify_archive(2, &key.public, |i| forked.get(i as usize).copied(), digest_of),
            Err((0, ArchiveError::NotAPrefix))
        );
        // Record count going backwards.
        let backwards = [c2, c1];
        assert_eq!(
            verify_archive(2, &key.public, |i| backwards.get(i as usize).copied(), digest_of),
            Err((1, ArchiveError::NotMonotonic))
        );
    }

    extern crate std;
}
