//! On-disk layout of a persisted ledger (sector-addressed, 512-byte sectors).
//!
//! ```text
//! sector 0      superblock v2:
//!                 0..8    magic "AXLEDGR1"      8..12  version (2)
//!                 12..16  flags (bit 0: signed) 16..24 record count
//!                 24..32  boot count            32..64 chain head
//!                 64..96  signer Ed25519 public key (zeros if unsigned)
//!                 96..160 Ed25519 signature over `checkpoint_message`
//!                 160..192 SHA-256 of bytes 0..160 (corruption check)
//! sector 1..    record slots, 4 per sector: encoded record (96) + digest (32)
//!               record `seq` lives at sector 1 + seq / 4, slot seq % 4
//! ```
//!
//! The checksum only detects accidental corruption. Editing records is
//! caught by re-verifying the hash chain from genesis; replacing the whole
//! chain with a different self-consistent one is caught by the checkpoint
//! signature, which only the key holder can produce. The head commits to
//! every earlier record, so one signature covers the entire history (a
//! signed tree head).

use crate::ed25519::{self, Keypair, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::{sha256, Digest, Record, RECORD_LEN};

pub const SECTOR: usize = 512;
/// One stored record: encoding + its digest.
pub const SLOT: usize = RECORD_LEN + 32;
pub const SLOTS_PER_SECTOR: usize = SECTOR / SLOT;
pub const MAGIC: [u8; 8] = *b"AXLEDGR1";
pub const VERSION: u32 = 2;
const FLAG_SIGNED: u32 = 1;

/// Domain separation for checkpoint signatures.
pub const CHECKPOINT_DOMAIN: &[u8; 28] = b"AXIOM-X-LEDGER-CHECKPOINT-V1";
/// Length of the signed checkpoint message.
pub const CHECKPOINT_MSG_LEN: usize = 28 + 8 + 8 + 32 + 32;

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
    /// Signed checkpoint: (signer public key, signature), if any.
    pub signature: Option<([u8; PUBLIC_KEY_LEN], [u8; SIGNATURE_LEN])>,
}

/// Result of checking a superblock's checkpoint signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Unsigned,
    Valid,
    /// Validly formed but by a key other than the expected one.
    WrongKey,
    /// Does not verify (forged or modified checkpoint).
    Invalid,
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
    pub fn unsigned(total: u64, head: Digest, boots: u64) -> Self {
        Self { total, head, boots, signature: None }
    }

    /// The bytes a checkpoint signature covers.
    pub fn checkpoint_message(&self, public: &[u8; PUBLIC_KEY_LEN]) -> [u8; CHECKPOINT_MSG_LEN] {
        let mut m = [0u8; CHECKPOINT_MSG_LEN];
        m[0..28].copy_from_slice(CHECKPOINT_DOMAIN);
        m[28..36].copy_from_slice(&self.total.to_le_bytes());
        m[36..44].copy_from_slice(&self.boots.to_le_bytes());
        m[44..76].copy_from_slice(&self.head);
        m[76..108].copy_from_slice(public);
        m
    }

    /// Sign this checkpoint (total, boots, head) with `key`.
    pub fn sign(&mut self, key: &Keypair) {
        let sig = key.sign(&self.checkpoint_message(&key.public));
        self.signature = Some((key.public, sig));
    }

    /// Check the checkpoint signature against the key the verifier trusts.
    pub fn signature_status(&self, trusted: &[u8; PUBLIC_KEY_LEN]) -> SignatureStatus {
        match &self.signature {
            None => SignatureStatus::Unsigned,
            Some((public, sig)) => {
                if !ed25519::verify(public, &self.checkpoint_message(public), sig) {
                    SignatureStatus::Invalid
                } else if public != trusted {
                    SignatureStatus::WrongKey
                } else {
                    SignatureStatus::Valid
                }
            }
        }
    }

    pub fn encode(&self) -> [u8; SECTOR] {
        let mut b = [0u8; SECTOR];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[16..24].copy_from_slice(&self.total.to_le_bytes());
        b[24..32].copy_from_slice(&self.boots.to_le_bytes());
        b[32..64].copy_from_slice(&self.head);
        if let Some((public, sig)) = &self.signature {
            b[12..16].copy_from_slice(&FLAG_SIGNED.to_le_bytes());
            b[64..96].copy_from_slice(public);
            b[96..160].copy_from_slice(sig);
        }
        let sum = sha256(&b[0..160]);
        b[160..192].copy_from_slice(&sum);
        b
    }

    pub fn decode(b: &[u8; SECTOR]) -> Result<Self, SuperblockError> {
        if b.iter().all(|&x| x == 0) {
            return Err(SuperblockError::Blank);
        }
        if b[0..8] != MAGIC || u32::from_le_bytes(b[8..12].try_into().unwrap()) != VERSION {
            return Err(SuperblockError::Foreign);
        }
        if sha256(&b[0..160])[..] != b[160..192] {
            return Err(SuperblockError::Corrupt);
        }
        let flags = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let signature = (flags & FLAG_SIGNED != 0)
            .then(|| (b[64..96].try_into().unwrap(), b[96..160].try_into().unwrap()));
        Ok(Self {
            total: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            boots: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            head: b[32..64].try_into().unwrap(),
            signature,
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
        let sb = Superblock::unsigned(1234, [7; 32], 3);
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
        let sb = Superblock::unsigned(boot1.total(), boot1.head(), 1);

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

    #[test]
    fn signed_checkpoint_roundtrip_and_attacks() {
        let key = Keypair::from_seed(&[1; 32]);
        let other = Keypair::from_seed(&[2; 32]);
        let mut sb = Superblock::unsigned(931, [9; 32], 2);
        assert_eq!(sb.signature_status(&key.public), SignatureStatus::Unsigned);
        sb.sign(&key);
        let dec = Superblock::decode(&sb.encode()).unwrap();
        assert_eq!(dec, sb);
        assert_eq!(dec.signature_status(&key.public), SignatureStatus::Valid);
        assert_eq!(dec.signature_status(&other.public), SignatureStatus::WrongKey);

        // Forger without the key: rewrites the head (e.g. after rebuilding a
        // consistent chain) and fixes the checksum, keeping the old signature.
        let mut forged = dec;
        forged.head[0] ^= 1;
        let forged = Superblock::decode(&forged.encode()).unwrap();
        assert_eq!(forged.signature_status(&key.public), SignatureStatus::Invalid);

        // Forger signs with their own key: verifies, but not as the trusted key.
        let mut resigned = forged;
        resigned.sign(&other);
        assert_eq!(resigned.signature_status(&key.public), SignatureStatus::WrongKey);

        // Rolling back the record count is also caught.
        let mut rolled = dec;
        rolled.total -= 1;
        assert_eq!(rolled.signature_status(&key.public), SignatureStatus::Invalid);
    }

    #[test]
    fn version_1_disk_is_foreign() {
        let mut v1 = Superblock::unsigned(1, [0; 32], 1).encode();
        v1[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(Superblock::decode(&v1), Err(SuperblockError::Foreign));
    }
}
