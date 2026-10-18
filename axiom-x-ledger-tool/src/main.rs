//! `ledger-tool`: verify an Axiom-X ledger disk image off the machine.
//!
//! ```text
//! ledger-tool pubkey <seed-file>              print the public key for a 32-byte seed
//! ledger-tool verify <disk-image> <pubkey>    verify chain from genesis + checkpoint signature
//! ledger-tool forge  <disk-image> <seq>       TEST ONLY: rewrite record <seq> and rebuild a
//!                                             self-consistent chain + superblock checksum,
//!                                             keeping the old signature (what an attacker
//!                                             without the key can do)
//! ```
//!
//! `verify` needs only the public key the operator published; it trusts
//! nothing else on the disk. Exit status: 0 = verified, 1 = not verified,
//! 2 = usage / I/O error.

use std::process::ExitCode;

use axiom_x_ledger::ed25519::Keypair;
use axiom_x_ledger::store::{self, SignatureStatus, Superblock};
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

fn sector(img: &[u8], n: u64) -> Option<&[u8; store::SECTOR]> {
    let start = (n as usize).checked_mul(store::SECTOR)?;
    img.get(start..start + store::SECTOR)?.try_into().ok()
}

fn slot(img: &[u8], seq: u64) -> Option<(Record, Digest)> {
    let (sec, off) = store::slot_location(seq);
    let s = sector(img, sec)?;
    Some(store::decode_slot(&s[off..off + store::SLOT]))
}

fn cmd_pubkey(seed_path: &str) -> ExitCode {
    let seed = match std::fs::read(seed_path) {
        Ok(b) if b.len() == 32 => <[u8; 32]>::try_from(b.as_slice()).unwrap(),
        Ok(b) => {
            eprintln!("{seed_path}: expected 32 bytes, got {}", b.len());
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("{seed_path}: {e}");
            return ExitCode::from(2);
        }
    };
    println!("{}", hex(&Keypair::from_seed(&seed).public));
    ExitCode::SUCCESS
}

fn cmd_verify(image: &str, pubkey: &str) -> ExitCode {
    let Some(trusted) = unhex32(pubkey) else {
        eprintln!("public key must be 64 hex characters");
        return ExitCode::from(2);
    };
    let img = match std::fs::read(image) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{image}: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(sb_bytes) = sector(&img, 0) else {
        println!("FAIL: image too small");
        return ExitCode::from(1);
    };
    let sb = match Superblock::decode(sb_bytes) {
        Ok(sb) => sb,
        Err(e) => {
            println!("FAIL: superblock unusable ({e:?})");
            return ExitCode::from(1);
        }
    };
    println!("superblock: {} records, {} boots, head {}", sb.total, sb.boots, hex(&sb.head));

    // Report chain consistency separately: a forger can rebuild a consistent
    // chain, so this alone proves nothing about origin.
    let chain = verify_window(0, sb.total, |seq| slot(&img, seq));
    match chain {
        Ok(head) if head == sb.head => println!("hash chain: internally consistent from genesis, matches superblock head"),
        Ok(_) => println!("hash chain: consistent, but does not end at the superblock head"),
        Err(seq) => println!("hash chain: broken at record {seq}"),
    }
    let sig = sb.signature_status(&trusted);
    println!("checkpoint signature: {sig:?}");
    if sig != SignatureStatus::Valid {
        println!("FAIL: checkpoint not signed by the trusted key {pubkey}");
        return ExitCode::from(1);
    }

    match chain {
        Err(seq) => {
            println!("FAIL: hash chain broken at record {seq}");
            ExitCode::from(1)
        }
        Ok(head) if head != sb.head => {
            println!("FAIL: chain head {} does not match the signed head", hex(&head));
            ExitCode::from(1)
        }
        Ok(_) => {
            let mut boots = 0;
            let mut denies = 0;
            for seq in 0..sb.total {
                let (r, _) = slot(&img, seq).unwrap();
                if r.kind == axiom_x_ledger::kind::BOOT {
                    boots += 1;
                }
                if r.decision == axiom_x_ledger::decision::DENY {
                    denies += 1;
                }
            }
            println!(
                "PASS: {} records verified from genesis ({} BOOT records, {} denies); head matches the checkpoint signed by {}",
                sb.total, boots, denies, pubkey
            );
            ExitCode::SUCCESS
        }
    }
}

fn cmd_forge(image: &str, seq: &str) -> ExitCode {
    let Ok(target) = seq.parse::<u64>() else {
        eprintln!("seq must be a number");
        return ExitCode::from(2);
    };
    let mut img = match std::fs::read(image) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{image}: {e}");
            return ExitCode::from(2);
        }
    };
    let sb = match sector(&img, 0).map(Superblock::decode) {
        Some(Ok(sb)) => sb,
        _ => {
            eprintln!("no usable superblock");
            return ExitCode::from(2);
        }
    };
    if target >= sb.total {
        eprintln!("record {target} does not exist ({} records)", sb.total);
        return ExitCode::from(2);
    }
    // Rewrite the record, then re-hash every later link so the chain is
    // internally consistent again: only the signature can expose this.
    let mut prev = if target == 0 { [0u8; 32] } else { slot(&img, target - 1).unwrap().1 };
    for s in target..sb.total {
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
    forged.head = prev; // keeps the old signature; checksum recomputed by encode()
    img[..store::SECTOR].copy_from_slice(&forged.encode());
    if let Err(e) = std::fs::write(image, &img) {
        eprintln!("{image}: {e}");
        return ExitCode::from(2);
    }
    println!(
        "forged record {target}; rebuilt {} links and the superblock (new head {}), old signature kept",
        sb.total - target,
        hex(&prev)
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [_, "pubkey", seed] => cmd_pubkey(seed),
        [_, "verify", image, pk] => cmd_verify(image, pk),
        [_, "forge", image, seq] => cmd_forge(image, seq),
        _ => {
            eprintln!("usage: ledger-tool pubkey <seed-file> | verify <disk-image> <pubkey-hex> | forge <disk-image> <seq>");
            ExitCode::from(2)
        }
    }
}
