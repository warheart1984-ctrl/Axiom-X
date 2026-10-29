//! Egress response attestation and the boot knobs that bound a capture.
//!
//! The COM2 frame is `RESP` + `u64` little-endian length + payload. The
//! proxy and the kernel both hash the payload alone. A `Record` has no
//! 32-byte field, so the digest is split the same way an FS root is.

use crate::{decision, kind, Digest, Record};

/// Per-pid token-bucket burst when `axiom.egress.burst` is absent.
pub const DEFAULT_EGRESS_BURST: u32 = 4;
/// `elf-workload` petitions when `axiom.egress.petitions` is absent.
pub const DEFAULT_EGRESS_PETITIONS: u32 = 25;
/// `elf-egress` attempts when `axiom.egress.probes` is absent.
pub const DEFAULT_EGRESS_PROBES: u32 = 8;
/// Self-test rounds when `axiom.rounds` is absent.
pub const DEFAULT_SELFTEST_ROUNDS: u32 = 3;

const MAX_BURST: u32 = 64;
const MAX_COUNT: u32 = 10_000;
const MAX_ROUNDS: u32 = 3;

/// What one kernel command line asks for. Absent optional keys stay `None`
/// so the programs keep the defaults above. `burst` is always filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressBoot {
    pub burst: u32,
    pub petitions: Option<u32>,
    pub probes: Option<u32>,
    pub rounds: Option<u32>,
}

/// Parse `axiom.egress.burst`, `axiom.egress.petitions`, `axiom.egress.probes`
/// and `axiom.rounds`. A missing or out-of-range value is ignored (burst
/// stays at the default). The last copy of a key wins.
pub fn parse_egress_boot(cmdline: &str) -> EgressBoot {
    let mut boot = EgressBoot {
        burst: DEFAULT_EGRESS_BURST,
        petitions: None,
        probes: None,
        rounds: None,
    };
    for word in cmdline.split_whitespace() {
        if let Some(v) = word.strip_prefix("axiom.egress.burst=") {
            if let Some(n) = parse_u32_in(v, 1, MAX_BURST) {
                boot.burst = n;
            }
        } else if let Some(v) = word.strip_prefix("axiom.egress.petitions=") {
            if let Some(n) = parse_u32_in(v, 1, MAX_COUNT) {
                boot.petitions = Some(n);
            }
        } else if let Some(v) = word.strip_prefix("axiom.egress.probes=") {
            if let Some(n) = parse_u32_in(v, 0, MAX_COUNT) {
                boot.probes = Some(n);
            }
        } else if let Some(v) = word.strip_prefix("axiom.rounds=") {
            if let Some(n) = parse_u32_in(v, 1, MAX_ROUNDS) {
                boot.rounds = Some(n);
            }
        }
    }
    boot
}

fn parse_u32_in(s: &str, lo: u32, hi: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut n: u32 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    if n < lo || n > hi { None } else { Some(n) }
}

fn digest_fields(d: &Digest) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(d[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn fields_digest(nr: u64, arg: u64, rights: u64, result: u64) -> Digest {
    let mut d = [0u8; 32];
    for (i, v) in [nr, arg, rights, result].into_iter().enumerate() {
        d[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    d
}

/// First 8 bytes of `digest` as a big-endian integer: the 16 hex digits
/// the kernel and the proxy both print (`sha256_hex` is `hexdigest()[:16]`).
pub fn digest_log_prefix(digest: &Digest) -> u64 {
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

/// Ledger record for one response payload. `len` is the number of bytes
/// hashed (the unframed payload), which fits the proxy's 64 KiB frame cap.
pub fn egress_response_record(pid: u32, len: u32, digest: &Digest) -> Record {
    let f = digest_fields(digest);
    Record {
        kind: kind::EGRESS_RESPONSE,
        decision: decision::ALLOW,
        pid,
        subject: len,
        nr: f[0],
        arg: f[1],
        result: f[3] as i64,
        rights: f[2],
        ..Record::default()
    }
}

/// `(payload length, digest)` when `record` is an egress response.
pub fn egress_response_of(record: &Record) -> Option<(u32, Digest)> {
    if record.kind != kind::EGRESS_RESPONSE {
        return None;
    }
    Some((
        record.subject,
        fields_digest(record.nr, record.arg, record.rights, record.result as u64),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, verify_window, Ledger};

    #[test]
    fn defaults_when_the_command_line_says_nothing() {
        let b = parse_egress_boot("");
        assert_eq!(b.burst, DEFAULT_EGRESS_BURST);
        assert_eq!(b.petitions, None);
        assert_eq!(b.probes, None);
        assert_eq!(b.rounds, None);
        assert_eq!(DEFAULT_EGRESS_BURST, 4);
        assert_eq!(DEFAULT_EGRESS_PETITIONS, 25);
        assert_eq!(DEFAULT_EGRESS_PROBES, 8);
        assert_eq!(DEFAULT_SELFTEST_ROUNDS, 3);
    }

    #[test]
    fn live_capture_knobs_parse_and_junk_is_ignored() {
        let b = parse_egress_boot(
            "axiom.selftest=off axiom.egress.burst=10 axiom.egress.petitions=10 \
             axiom.egress.probes=0 axiom.rounds=1 axiom.egress.burst=0 \
             axiom.egress.burst=99 axiom.rounds=9",
        );
        // 0 and 99 are outside 1..=64, 9 is outside 1..=3: the earlier
        // burst=10 and rounds=1 stand. probes=0 is a real setting.
        assert_eq!(
            b,
            EgressBoot { burst: 10, petitions: Some(10), probes: Some(0), rounds: Some(1) }
        );
    }

    #[test]
    fn response_hash_is_the_unframed_payload() {
        let payload = b"{\"stub\":\"axiom-x-egress\"}\n";
        let mut framed = [0u8; 4 + 8 + 32];
        framed[..4].copy_from_slice(b"RESP");
        framed[4..12].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        framed[12..12 + payload.len()].copy_from_slice(payload);
        let framed = &framed[..12 + payload.len()];
        let digest = sha256(payload);
        assert_ne!(sha256(framed), digest, "framing must not enter the hash");
        // Same truncation the proxy prints and the kernel logs.
        assert_eq!(digest_log_prefix(&sha256(b"")), 0xe3b0c44298fc1c14);
        assert_eq!(digest_log_prefix(&sha256(b"abc")), 0xba7816bf8f01cfea);

        let rec = egress_response_record(11, payload.len() as u32, &digest);
        assert_eq!(egress_response_of(&rec), Some((payload.len() as u32, digest)));
        assert!(egress_response_of(&Record { kind: kind::CONTRACT_ENFORCE, ..rec }).is_none());

        // High bit set in the last field: the i64 slot must round-trip.
        let mut hi = [0xffu8; 32];
        hi[..4].copy_from_slice(b"resp");
        let rec = egress_response_record(3, 64 * 1024, &hi);
        assert_eq!(egress_response_of(&rec), Some((64 * 1024, hi)));
    }

    #[test]
    fn response_record_links_into_the_chain() {
        let mut ledger: Ledger<8> = Ledger::new();
        let petition = Record {
            kind: kind::CONTRACT_ENFORCE,
            decision: decision::ALLOW,
            pid: 10,
            subject: 10,
            nr: 537,
            result: 40,
            ..Record::default()
        };
        ledger.append(petition);
        let payload = b"ok";
        let digest = sha256(payload);
        ledger.append(egress_response_record(10, payload.len() as u32, &digest));
        assert_eq!(verify_window(0, ledger.total(), |s| ledger.get(s)), Ok(ledger.head()));
        let (stored, _) = ledger.get(1).unwrap();
        assert_eq!(egress_response_of(&stored), Some((payload.len() as u32, digest)));
        assert_eq!(stored.pid, 10);
    }
}
