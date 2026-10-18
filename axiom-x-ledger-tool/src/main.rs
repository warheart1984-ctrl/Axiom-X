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
    let Some(trusted) = unhex32(pubkey) else {
        eprintln!("public key must be 64 hex characters");
        return ExitCode::from(2);
    };
    let mut img = match read_image(image) {
        Ok(b) => b,
        Err(c) => return c,
    };

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
            return ExitCode::from(1);
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
        return ExitCode::from(1);
    }
    match chain {
        Err(seq) => {
            println!("FAIL: hash chain broken at record {seq}");
            return ExitCode::from(1);
        }
        Ok(head) if head != c.head => {
            println!("FAIL: chain head {} does not match the signed head", hex(&head));
            return ExitCode::from(1);
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
            return ExitCode::from(1);
        }
    }

    let (mut boots, mut denies) = (0, 0);
    for seq in 0..c.total {
        let (r, _) = slot(&img, seq).unwrap();
        boots += (r.kind == axiom_x_ledger::kind::BOOT) as u32;
        denies += (r.decision == axiom_x_ledger::decision::DENY) as u32;
    }
    println!(
        "PASS: {} records verified from genesis ({} BOOT records, {} denies); latest and {} archived checkpoints signed by {}",
        c.total, boots, denies, sb.archived, pubkey
    );
    ExitCode::SUCCESS
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
        _ => {
            eprintln!(
                "usage: ledger-tool pubkey <seed-file> | verify <disk-image> <pubkey-hex> [--raw] | forge <disk-image> <seq>"
            );
            ExitCode::from(2)
        }
    }
}
