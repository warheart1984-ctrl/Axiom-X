//! `ledger-tool`: verify an Axiom-X ledger disk image (format v3) off the machine.
//!
//! ```text
//! ledger-tool pubkey <seed-file>                 print the public key for a 32-byte seed
//! ledger-tool verify <disk-image> <pubkey> [--raw]
//!     choose the superblock copy as the kernel does, apply a complete
//!     pending journal as boot recovery would (unless --raw), then verify
//!     the chain from genesis, the latest checkpoint signature, and every
//!     archived checkpoint (signed by the key, monotonic, a prefix of the
//!     current chain)
//! ledger-tool fs-verify <fs-image> <ledger-image> <pubkey>
//!     verify the ledger as above, then the AXFS image: superblock, file
//!     table against its root hash, every file against its SHA-256, and
//!     that the root equals the newest file-system anchor (FS_COMMIT, or
//!     FS_MOUNT with decision ALLOW) in the verified ledger
//! ledger-tool forge <disk-image> <seq>
//!     TEST ONLY: rewrite record <seq> and rebuild a self-consistent chain
//!     and superblock, keeping the old signature (what an attacker without
//!     the key can do)
//! ```
//!
//! `verify` trusts only the public key it is given. Exit status: 0 =
//! verified, 1 = not verified, 2 = usage / I/O error.

use std::process::ExitCode;

use axiom_x_ledger::ed25519::Keypair;
use axiom_x_ledger::store::{self, Checkpoint, JournalHeader, Pick, SignatureStatus, Superblock};
use axiom_x_ledger::{verify_window, Digest, Record};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let v: Option<Vec<u8>> = (0..32).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect();
    v?.try_into().ok()
}

fn sector(img: &[u8], n: u64) -> Option<[u8; store::SECTOR]> {
    let start = (n as usize).checked_mul(store::SECTOR)?;
    img.get(start..start + store::SECTOR)?.try_into().ok()
}

fn set_sector(img: &mut [u8], n: u64, data: &[u8; store::SECTOR]) {
    let at = n as usize * store::SECTOR;
    img[at..at + store::SECTOR].copy_from_slice(data);
}

fn slot(img: &[u8], seq: u64) -> Option<(Record, Digest)> {
    let (sec, off) = store::slot_location(seq);
    let s = sector(img, sec)?;
    Some(store::decode_slot(&s[off..off + store::SLOT]))
}

fn read_image(path: &str) -> Result<Vec<u8>, ExitCode> {
    std::fs::read(path).map_err(|e| {
        eprintln!("{path}: {e}");
        ExitCode::from(2)
    })
}

fn pick(img: &[u8]) -> Pick {
    let dec = |n| sector(img, n).map_or(Err(store::SuperblockError::Blank), |s| Superblock::decode(&s));
    store::pick_superblock(dec(0), dec(1))
}

fn cmd_pubkey(seed_path: &str) -> ExitCode {
    match std::fs::read(seed_path) {
        Ok(b) if b.len() == 32 => {
            let seed: [u8; 32] = b.as_slice().try_into().unwrap();
            println!("{}", hex(&Keypair::from_seed(&seed).public));
            ExitCode::SUCCESS
        }
        Ok(b) => {
            eprintln!("{seed_path}: expected 32 bytes, got {}", b.len());
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("{seed_path}: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_verify(image: &str, pubkey: &str, raw: bool) -> ExitCode {
    match verify_ledger(image, pubkey, raw) {
        Ok(_) => ExitCode::SUCCESS,
        Err(c) => c,
    }
}

/// Verify a ledger image; on success return it (journal applied unless
/// `raw`) and its record count.
fn verify_ledger(image: &str, pubkey: &str, raw: bool) -> Result<(Vec<u8>, u64), ExitCode> {
    let Some(trusted) = unhex32(pubkey) else {
        eprintln!("public key must be 64 hex characters");
        return Err(ExitCode::from(2));
    };
    let mut img = read_image(image)?;

    // Pending journal: replay it virtually, exactly as boot recovery would.
    if let (Some(h), Some(data)) = (
        sector(&img, store::JOURNAL_HEADER_SECTOR).and_then(|s| JournalHeader::decode(&s)),
        sector(&img, store::JOURNAL_DATA_SECTOR),
    ) {
        if raw {
            println!("journal: pending entry for sector {} IGNORED (--raw)", h.target);
        } else if h.matches(&data) && h.target >= store::RECORD_BASE && (h.target as usize + 1) * store::SECTOR <= img.len() {
            set_sector(&mut img, h.target, &data);
            println!("journal: complete entry for sector {} applied (as boot recovery would)", h.target);
        } else {
            println!("journal: incomplete entry discarded (its target was never touched)");
        }
    } else {
        println!("journal: clear");
    }

    let (sb, which) = match pick(&img) {
        Pick::Use(sb, which) => (sb, which),
        other => {
            println!("FAIL: no usable superblock ({other:?})");
            return Err(ExitCode::from(1));
        }
    };
    let c = sb.checkpoint;
    println!(
        "superblock: copy {} (generation {}), {} records, {} boots, {} checkpoints archived, head {}",
        if which == 0 { "A" } else { "B" },
        sb.generation,
        c.total,
        c.boots,
        sb.archived,
        hex(&c.head)
    );

    // Chain consistency is reported on its own: a forger can rebuild a
    // consistent chain, so this alone proves nothing about origin.
    let chain = verify_window(0, c.total, |seq| slot(&img, seq));
    match chain {
        Ok(head) if head == c.head => println!("hash chain: internally consistent from genesis, matches superblock head"),
        Ok(_) => println!("hash chain: consistent, but does not end at the superblock head"),
        Err(seq) => println!("hash chain: broken at record {seq}"),
    }
    let sig = c.status(&trusted);
    println!("checkpoint signature: {sig:?}");
    if sig != SignatureStatus::Valid {
        println!("FAIL: latest checkpoint not signed by the trusted key {pubkey}");
        return Err(ExitCode::from(1));
    }
    match chain {
        Err(seq) => {
            println!("FAIL: hash chain broken at record {seq}");
            return Err(ExitCode::from(1));
        }
        Ok(head) if head != c.head => {
            println!("FAIL: chain head {} does not match the signed head", hex(&head));
            return Err(ExitCode::from(1));
        }
        Ok(_) => {}
    }

    let archive = store::verify_archive(
        sb.archived,
        &trusted,
        |i| sector(&img, store::CHECKPOINT_BASE + i).and_then(|s| Checkpoint::decode_archive(&s)),
        |seq| slot(&img, seq).map(|(_, d)| d),
    );
    match archive {
        Ok(n) => println!("checkpoint archive: {n} signed checkpoints verified; each is a prefix of the current chain"),
        Err((i, why)) => {
            println!("FAIL: archived checkpoint {i}: {why:?}");
            return Err(ExitCode::from(1));
        }
    }

    // Rollback check: a damaged newest superblock copy falls back to the
    // older one, whose lower `archived` count hides newer checkpoints.
    // Any *validly signed* archive entry past `sb.archived` claiming more
    // records proves this superblock is stale — one-sector rollbacks
    // must not verify.
    for i in sb.archived..store::CHECKPOINT_SECTORS {
        let Some(newer) = sector(&img, store::CHECKPOINT_BASE + i)
            .and_then(|s| Checkpoint::decode_archive(&s))
        else {
            break;
        };
        if newer.status(&trusted) == SignatureStatus::Valid && newer.total > c.total {
            println!(
                "FAIL: rollback evidence — archive entry {i} is a validly signed checkpoint with total {} > superblock {}",
                newer.total, c.total
            );
            return Err(ExitCode::from(1));
        }
    }

    // Egress attestation: groups of kind 103..106 records carry the proxy's
    // Ed25519 signature over sha256(request)||sha256(response). Verify each
    // quad against the proxy key (env ATTEST_KEY, 64-hex public key).
    if let Ok(pk_hex) = std::env::var("ATTEST_KEY") {
        let unpack = |r: &Record| -> [u8; 32] {
            let mut d = [0u8; 32];
            d[0..8].copy_from_slice(&r.nr.to_le_bytes());
            d[8..16].copy_from_slice(&r.arg.to_le_bytes());
            d[16..24].copy_from_slice(&(r.result as u64).to_le_bytes());
            d[24..32].copy_from_slice(&r.rights.to_le_bytes());
            d
        };
        let pk: [u8; 32] = match unhex32(&pk_hex) {
            Some(p) => p,
            None => {
                println!("FAIL: ATTEST_KEY is not a 64-hex Ed25519 public key");
                return Err(ExitCode::from(2));
            }
        };
        let mut quads: std::collections::BTreeMap<u32, [Option<Record>; 4]> = Default::default();
        for seq in 0..c.total {
            let (r, _) = slot(&img, seq).unwrap();
            let idx = match r.kind {
                axiom_x_ledger::kind::EGRESS_ATTEST_REQ => 0,
                axiom_x_ledger::kind::EGRESS_ATTEST_RESP => 1,
                axiom_x_ledger::kind::EGRESS_ATTEST_SIG_LO => 2,
                axiom_x_ledger::kind::EGRESS_ATTEST_SIG_HI => 3,
                _ => continue,
            };
            quads.entry(r.subject).or_default()[idx] = Some(r);
        }
        let (mut ok, mut bad) = (0usize, 0usize);
        for (sub, quad) in quads {
            let [Some(a), Some(b), Some(s1), Some(s2)] = quad else {
                println!("FAIL: incomplete attestation group for egress seq {sub}");
                bad += 1;
                continue;
            };
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&unpack(&a));
            msg[32..].copy_from_slice(&unpack(&b));
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&unpack(&s1));
            sig[32..].copy_from_slice(&unpack(&s2));
            if axiom_x_ledger::ed25519::verify(&pk, &msg, &sig) {
                ok += 1;
            } else {
                println!("FAIL: attestation signature invalid for egress seq {sub}");
                bad += 1;
            }
        }
        println!("egress attestations: {ok} signatures verified, {bad} invalid/incomplete");
        if bad > 0 {
            return Err(ExitCode::from(1));
        }
    }

    let (mut boots, mut denies) = (0, 0);
    for seq in 0..c.total {
        let (r, _) = slot(&img, seq).unwrap();
        if r.kind == axiom_x_ledger::kind::BOOT {
            boots += 1;
            // `rights` carries the boot's RTC time on kernels that have a clock.
            let when = if r.rights == 0 {
                "time unknown (kernel without a clock)".to_string()
            } else {
                format!("{} (RTC, no time zone)", axiom_x_ledger::civil::DateTime::from_unix(r.rights))
            };
            println!("  BOOT record #{seq}: boot {}, {when}, resumed {} records", r.arg, r.result);
        }
        denies += (r.decision == axiom_x_ledger::decision::DENY) as u32;
    }
    println!(
        "PASS: {} records verified from genesis ({} BOOT records, {} denies); latest and {} archived checkpoints signed by {}",
        c.total, boots, denies, sb.archived, pubkey
    );
    Ok((img, c.total))
}

/// A disk image in memory, as an AXFS block device.
struct ImageDev(Vec<u8>);

impl axiom_x_fs::BlockDev for ImageDev {
    fn read_sector(&mut self, lba: u64, buf: &mut [u8; axiom_x_fs::SECTOR]) -> Result<(), ()> {
        let o = lba as usize * axiom_x_fs::SECTOR;
        buf.copy_from_slice(self.0.get(o..o + axiom_x_fs::SECTOR).ok_or(())?);
        Ok(())
    }
    fn write_sector(&mut self, _: u64, _: &[u8; axiom_x_fs::SECTOR]) -> Result<(), ()> {
        Err(()) // read-only: verification never changes the image
    }
    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
    fn sectors(&self) -> u64 {
        (self.0.len() / axiom_x_fs::SECTOR) as u64
    }
}

/// Root hash carried by a file-system ledger record (see the kernel's `fsys`).
fn fs_root_of(r: &Record) -> Digest {
    let mut d = [0u8; 32];
    for (i, v) in [r.nr, r.arg, r.rights, r.result as u64].iter().enumerate() {
        d[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    d
}

fn cmd_fs_verify(fs_image: &str, ledger_image: &str, pubkey: &str) -> ExitCode {
    use axiom_x_fs::{Fs, MountError};
    use axiom_x_ledger::{decision, kind};
    println!("== ledger {ledger_image}");
    let (ledger, total) = match verify_ledger(ledger_image, pubkey, false) {
        Ok(v) => v,
        Err(c) => {
            println!("FAIL: the ledger does not verify, so it cannot vouch for the file system");
            return c;
        }
    };
    println!("== file system {fs_image}");
    let img = match read_image(fs_image) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let mut fs = match Fs::mount(ImageDev(img)) {
        Ok(fs) => fs,
        Err(MountError::TableCorrupt) => {
            println!("FAIL: file table does not match the root hash in the superblock");
            return ExitCode::from(1);
        }
        Err(e) => {
            println!("FAIL: not a mountable AXFS image ({e:?})");
            return ExitCode::from(1);
        }
    };
    let sb = fs.superblock();
    println!(
        "superblock: generation {}, {} files, table at sector {}, {} of {} sectors used; table matches root {}",
        sb.generation,
        sb.files,
        sb.table_sector,
        sb.next_free,
        sb.total_sectors,
        hex(&sb.root)
    );
    let entries: Vec<_> = fs.entries().copied().collect();
    for e in &entries {
        println!("  {:>8} bytes  v{:<3} sha256 {}  {}", e.size, e.version, hex(&e.digest), e.name());
    }
    if let Err(name) = fs.verify_all() {
        let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        println!("FAIL: file '{}' does not match its SHA-256", String::from_utf8_lossy(&name[..n]));
        return ExitCode::from(1);
    }
    println!("files: all {} verified against their SHA-256", entries.len());

    let (mut commits, mut mounts, mut refused) = (0, 0, 0);
    let mut newest = None;
    for seq in 0..total {
        let (r, _) = slot(&ledger, seq).unwrap();
        let anchor = match r.kind {
            kind::FS_COMMIT => {
                commits += 1;
                true
            }
            kind::FS_MOUNT if r.decision == decision::ALLOW => {
                mounts += 1;
                true
            }
            kind::FS_MOUNT => {
                refused += 1;
                println!("  FS_MOUNT DENY #{seq}: mounted read-only (root {}..)", &hex(&fs_root_of(&r))[..16]);
                false
            }
            _ => false,
        };
        if anchor {
            newest = Some((seq, fs_root_of(&r)));
        }
    }
    println!("ledger anchors: {commits} FS_COMMIT, {mounts} FS_MOUNT allowed, {refused} FS_MOUNT refused");
    match newest {
        None => {
            println!("FAIL: the ledger holds no file-system anchor");
            ExitCode::from(1)
        }
        Some((seq, root)) if root == sb.root => {
            println!(
                "PASS: file system root {} is the newest ledger anchor (record #{seq}), signed chain verified",
                hex(&sb.root)
            );
            ExitCode::SUCCESS
        }
        Some((seq, root)) => {
            println!("FAIL: newest ledger anchor (record #{seq}) is root {}; the image was changed or rolled back", hex(&root));
            ExitCode::from(1)
        }
    }
}

fn cmd_forge(image: &str, seq: &str) -> ExitCode {
    let Ok(target) = seq.parse::<u64>() else {
        eprintln!("seq must be a number");
        return ExitCode::from(2);
    };
    let mut img = match read_image(image) {
        Ok(b) => b,
        Err(c) => return c,
    };
    let Pick::Use(sb, _) = pick(&img) else {
        eprintln!("no usable superblock");
        return ExitCode::from(2);
    };
    let total = sb.checkpoint.total;
    if target >= total {
        eprintln!("record {target} does not exist ({total} records)");
        return ExitCode::from(2);
    }
    // Rewrite the record, then re-hash every later link so the chain is
    // internally consistent again: only signatures can expose this.
    let mut prev = if target == 0 { [0u8; 32] } else { slot(&img, target - 1).unwrap().1 };
    for s in target..total {
        let (mut r, _) = slot(&img, s).unwrap();
        if s == target {
            r.result ^= 1;
        }
        r.prev = prev;
        let d = r.digest();
        let (sec, off) = store::slot_location(s);
        let at = sec as usize * store::SECTOR + off;
        img[at..at + store::SLOT].copy_from_slice(&store::encode_slot(&r, &d));
        prev = d;
    }
    let mut forged = sb;
    forged.checkpoint.head = prev; // old signature kept; checksum recomputed by encode()
    forged.generation += 1;
    set_sector(&mut img, store::superblock_sector(forged.generation), &forged.encode());
    if let Err(e) = std::fs::write(image, &img) {
        eprintln!("{image}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "forged record {target}; rebuilt {} links and a newer superblock (head {}), old signature kept",
        total - target,
        hex(&prev)
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [_, "pubkey", seed] => cmd_pubkey(seed),
        [_, "verify", image, pk] => cmd_verify(image, pk, false),
        [_, "verify", image, pk, "--raw"] => cmd_verify(image, pk, true),
        [_, "forge", image, seq] => cmd_forge(image, seq),
        [_, "fs-verify", fs, ledger, pk] => cmd_fs_verify(fs, ledger, pk),
        _ => {
            eprintln!(
                "usage: ledger-tool pubkey <seed-file> | verify <disk-image> <pubkey-hex> [--raw] | fs-verify <fs-image> <ledger-image> <pubkey-hex> | forge <disk-image> <seq>"
            );
            ExitCode::from(2)
        }
    }
}
