//! Independent auditor: reads the kernel's evidence ledger through
//! `AX_GET_EVIDENCE` and re-verifies the SHA-256 hash chain with the same
//! code the kernel uses (`axiom_x_ledger::verify_window`), then checks that a
//! forged record would be caught. Needs `Rights::EVIDENCE` (and SEND to
//! report).
//!
//! Each read is itself a governed syscall and appends a record, so the
//! auditor verifies the window that existed when it started.

#![no_std]
#![no_main]

use axiom_x_user::ledger::{decision, kind, verify_window};
use axiom_x_user::{entry, errno, evidence, evidence_count, getpid, println};

/// Most records verified per audit: reads append records, so the window
/// must stay well inside the kernel's 1024-record ring.
const MAX_WINDOW: u64 = 400;

fn hex8(d: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in d[..8].iter().enumerate() {
        out[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
        out[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
    }
    out
}

fn main() -> i32 {
    let total = match evidence_count() {
        Ok(t) => t,
        Err(e) => {
            println!("[audit] cannot read the ledger: {} ({})", e, errno::name(e));
            return 1;
        }
    };
    let first = total.saturating_sub(MAX_WINDOW);
    println!("[audit] pid {}: verifying ledger records {}..{} (of {})", getpid(), first, total, total);

    // Pass 1: verify every link, and tally what the records say.
    let (mut denies, mut faults, mut creates, mut reaps) = (0u32, 0u32, 0u32, 0u32);
    let verified = verify_window(first, total, |seq| {
        let r = evidence(seq).ok()?;
        match (r.0.kind, r.0.decision) {
            (_, decision::DENY) => denies += 1,
            (kind::PROCESS_EXIT, decision::FAULT) => faults += 1,
            (kind::PROCESS_CREATE, decision::ALLOW) => creates += 1,
            (kind::MEMORY_FREE, _) => reaps += 1,
            _ => {}
        }
        Some(r)
    });
    let head = match verified {
        Ok(head) => head,
        Err(seq) => {
            println!("[audit] chain BROKEN at record {}", seq);
            return 1;
        }
    };
    let h = hex8(&head);
    println!(
        "[audit] chain intact: {} records, head {}... (denies {}, faults {}, creates {}, reaps {})",
        total - first,
        core::str::from_utf8(&h).unwrap_or("?"),
        denies, faults, creates, reaps
    );

    // Pass 2: forge one record in transit (change its result, keep the
    // kernel's digest); verification must reject it.
    let forged_at = first + (total - first) / 2;
    let forged = verify_window(first, total, |seq| {
        let (mut r, d) = evidence(seq).ok()?;
        if seq == forged_at {
            r.result ^= 1;
        }
        Some((r, d))
    });
    let tamper_caught = forged == Err(forged_at);
    println!(
        "[audit] forged record {} detected: {}",
        forged_at,
        if tamper_caught { "yes" } else { "NO" }
    );

    let ok = denies > 0 && faults > 0 && creates > 0 && tamper_caught;
    println!("[audit] ledger audit: {}", if ok { "PASS" } else { "FAIL" });
    if ok { 0 } else { 1 }
}

entry!(main);
