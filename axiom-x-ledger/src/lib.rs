//! Hash-chained evidence ledger.
//!
//! Each `Record` carries the digest of the record before it, and its own
//! digest is `SHA-256(encode(record))`, so changing, dropping or reordering
//! any record breaks every link after it. The kernel appends a record for
//! every governed decision; user-space auditors read records back and verify
//! the chain with the same code (`verify_link`).
//!
//! `Ledger` keeps the newest `N` records in a ring. The chain head and
//! sequence numbers continue across eviction, so an auditor can verify any
//! contiguous window it can still read.
//!
//! Status: `partial` — used by the Axiom-X kernel and `elf-audit` in QEMU.

#![no_std]

pub mod civil;
pub mod ed25519;
pub mod sha256;
pub mod sha512;
pub mod store;

pub use sha256::{sha256, Sha256};

/// Kinds, numbered as `axiom_x_sys::EvidenceType`.
pub mod kind {
    pub const MEMORY_FREE: u32 = 2;
    pub const PROCESS_CREATE: u32 = 5;
    pub const PROCESS_EXIT: u32 = 6;
    pub const CONTRACT_ENFORCE: u32 = 15;
    /// Axiom-X kernel boot (not in `EvidenceType`): `arg` = boot number,
    /// `result` = records resumed from disk (-1 = none / not verified),
    /// `nr` = first 8 bytes of the signer key (0 = unsigned), `rights` =
    /// UNIX time (seconds) of the boot per the RTC (0 = unknown; no time
    /// zone: QEMU gives UTC, Hyper-V the host's local time).
    pub const BOOT: u32 = 100;
    /// Axiom-X file-system change committed by `pid`: the new root hash
    /// (SHA-256 of the file table) is split over `nr`, `arg`, `rights`,
    /// `result` (8 bytes each, little-endian, in that order).
    pub const FS_COMMIT: u32 = 101;
    /// File system mounted (decision ALLOW) or found inconsistent with the
    /// ledger / corrupt and mounted read-only (DENY); root hash as above.
    pub const FS_MOUNT: u32 = 102;
}

/// Outcome of the decision a record describes.
pub mod decision {
    pub const DENY: u32 = 0;
    pub const ALLOW: u32 = 1;
    /// The kernel ended a process for a fault it caused.
    pub const FAULT: u32 = 2;
}

pub type Digest = [u8; 32];

/// Encoded size of a record (fixed, little-endian).
pub const RECORD_LEN: usize = 96;

/// One governed decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Record {
    /// Position in the chain (0 = genesis), assigned by `Ledger::append`.
    pub seq: u64,
    /// Scheduler tick (10 ms) when the decision was made.
    pub tick: u64,
    /// `kind::*`
    pub kind: u32,
    /// `decision::*`
    pub decision: u32,
    /// Process that requested the action (0 = kernel).
    pub pid: u32,
    /// Process acted on (child PID for create/reap, else = `pid`).
    pub subject: u32,
    /// Syscall number, when the decision is about a syscall.
    pub nr: u64,
    /// First argument / detail (e.g. frames freed for MEMORY_FREE).
    pub arg: u64,
    /// Result returned (or exit code).
    pub result: i64,
    /// Rights (`axiom_x_capability::Rights` bits) relevant to the decision.
    pub rights: u64,
    /// Digest of the previous record (all zeros for genesis).
    pub prev: Digest,
}

impl Record {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8..16].copy_from_slice(&self.tick.to_le_bytes());
        b[16..20].copy_from_slice(&self.kind.to_le_bytes());
        b[20..24].copy_from_slice(&self.decision.to_le_bytes());
        b[24..28].copy_from_slice(&self.pid.to_le_bytes());
        b[28..32].copy_from_slice(&self.subject.to_le_bytes());
        b[32..40].copy_from_slice(&self.nr.to_le_bytes());
        b[40..48].copy_from_slice(&self.arg.to_le_bytes());
        b[48..56].copy_from_slice(&self.result.to_le_bytes());
        b[56..64].copy_from_slice(&self.rights.to_le_bytes());
        b[64..96].copy_from_slice(&self.prev);
        b
    }

    pub fn decode(b: &[u8; RECORD_LEN]) -> Self {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Self {
            seq: u64_at(0),
            tick: u64_at(8),
            kind: u32_at(16),
            decision: u32_at(20),
            pid: u32_at(24),
            subject: u32_at(28),
            nr: u64_at(32),
            arg: u64_at(40),
            result: u64_at(48) as i64,
            rights: u64_at(56),
            prev: b[64..96].try_into().unwrap(),
        }
    }

    pub fn digest(&self) -> Digest {
        sha256(&self.encode())
    }
}

/// True when `record` directly follows the record whose digest is `prev`
/// and hashes to `digest`.
pub fn verify_link(prev: &Digest, record: &Record, digest: &Digest) -> bool {
    record.prev == *prev && record.digest() == *digest
}

/// Ring of the newest `N` records plus the running chain head.
pub struct Ledger<const N: usize> {
    records: [Record; N],
    digests: [Digest; N],
    total: u64,
    head: Digest,
    /// First sequence number this ledger has held (0, or the resume point).
    base: u64,
}

impl<const N: usize> Default for Ledger<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Ledger<N> {
    pub const fn new() -> Self {
        const ZERO: Record = Record {
            seq: 0, tick: 0, kind: 0, decision: 0, pid: 0, subject: 0,
            nr: 0, arg: 0, result: 0, rights: 0, prev: [0; 32],
        };
        Self { records: [ZERO; N], digests: [[0; 32]; N], total: 0, head: [0; 32], base: 0 }
    }

    /// Continue an existing chain (e.g. one verified from disk) whose next
    /// sequence number is `total` and head digest `head`. Older records are
    /// not held in memory. Only valid on an empty ledger.
    pub fn resume(&mut self, total: u64, head: Digest) {
        assert_eq!(self.total, self.base, "resume on a non-empty ledger");
        self.total = total;
        self.head = head;
        self.base = total;
    }

    /// Chain `record` onto the head (its `seq` and `prev` are assigned
    /// here) and return its sequence number.
    pub fn append(&mut self, mut record: Record) -> u64 {
        record.seq = self.total;
        record.prev = self.head;
        let digest = record.digest();
        let slot = (self.total % N as u64) as usize;
        self.records[slot] = record;
        self.digests[slot] = digest;
        self.head = digest;
        self.total += 1;
        record.seq
    }

    /// Records ever appended (the next sequence number).
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Digest of the newest record (all zeros while empty).
    pub fn head(&self) -> Digest {
        self.head
    }

    /// Oldest sequence number still held.
    pub fn oldest(&self) -> u64 {
        self.total.saturating_sub(N as u64).max(self.base)
    }

    /// Record `seq` with its digest, if still held.
    pub fn get(&self, seq: u64) -> Option<(Record, Digest)> {
        if seq >= self.total || seq < self.oldest() {
            return None;
        }
        let slot = (seq % N as u64) as usize;
        Some((self.records[slot], self.digests[slot]))
    }
}

/// Verify every link in `[first, total)` of a ledger through an accessor
/// (`get(seq) -> (record, digest)`), as an auditor would. Returns the head
/// digest it reached, or the first sequence number whose link is broken.
pub fn verify_window(
    first: u64,
    total: u64,
    mut get: impl FnMut(u64) -> Option<(Record, Digest)>,
) -> Result<Digest, u64> {
    let mut prev: Option<Digest> = None;
    for seq in first..total {
        let (record, digest) = get(seq).ok_or(seq)?;
        if record.seq != seq || record.digest() != digest {
            return Err(seq);
        }
        if let Some(p) = prev {
            if record.prev != p {
                return Err(seq);
            }
        } else if seq == 0 && record.prev != [0; 32] {
            return Err(seq);
        }
        prev = Some(digest);
    }
    Ok(prev.unwrap_or([0; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pid: u32, nr: u64) -> Record {
        Record { kind: kind::CONTRACT_ENFORCE, decision: decision::ALLOW, pid, subject: pid, nr, ..Record::default() }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let r = Record {
            seq: 7, tick: 9, kind: 5, decision: 1, pid: 3, subject: 4,
            nr: 520, arg: 0xdead, result: -1, rights: 1 << 10, prev: [0xab; 32],
        };
        assert_eq!(Record::decode(&r.encode()), r);
    }

    #[test]
    fn chain_links_and_head() {
        let mut l: Ledger<8> = Ledger::new();
        for i in 0..5 {
            assert_eq!(l.append(rec(1, i)), i);
        }
        assert_eq!(l.total(), 5);
        let (first, _) = l.get(0).unwrap();
        assert_eq!(first.prev, [0; 32], "genesis links to zero");
        for seq in 1..5 {
            let (prev, prev_d) = l.get(seq - 1).unwrap();
            let (r, d) = l.get(seq).unwrap();
            assert!(verify_link(&prev_d, &r, &d));
            assert_eq!(r.prev, prev.digest());
        }
        assert_eq!(verify_window(0, l.total(), |s| l.get(s)), Ok(l.head()));
    }

    #[test]
    fn tampering_is_detected() {
        let mut l: Ledger<8> = Ledger::new();
        for i in 0..6 {
            l.append(rec(2, i));
        }
        // Change one field of record 3 (as a forger would) and keep its digest.
        let tamper = |s: u64| {
            l.get(s).map(|(mut r, d)| {
                if s == 3 {
                    r.result = 42;
                }
                (r, d)
            })
        };
        assert_eq!(verify_window(0, l.total(), tamper), Err(3));
        // Re-hashing the forged record does not help: the next link breaks.
        let rehash = |s: u64| {
            l.get(s).map(|(mut r, d)| {
                if s == 3 {
                    r.result = 42;
                    return (r, r.digest());
                }
                (r, d)
            })
        };
        assert_eq!(verify_window(0, l.total(), rehash), Err(4));
    }

    #[test]
    fn ring_eviction_keeps_chain_verifiable() {
        let mut l: Ledger<4> = Ledger::new();
        for i in 0..10 {
            l.append(rec(3, i));
        }
        assert_eq!(l.oldest(), 6);
        assert!(l.get(5).is_none());
        assert_eq!(verify_window(l.oldest(), l.total(), |s| l.get(s)), Ok(l.head()));
    }
}
