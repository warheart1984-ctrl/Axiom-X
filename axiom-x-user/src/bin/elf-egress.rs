//! Governed-egress self-test: petitions the host proxy over COM2 through
//! `AX_EGRESS` (Rights::NET), prints what came back. A channel timeout is
//! still evidence: the petition was made, gated, and ledgered.

#![no_std]
#![no_main]

use axiom_x_user::{egress, entry, getpid, println};

fn main() -> i32 {
    let pid = getpid();
    println!("[elf-egress] pid {}: governed egress petition", pid);

    let req = b"GET /v1/models HTTP/1.1\r\nHost: llm-gateway\r\n\r\n";
    let mut resp = [0u8; 1024];
    // Hammer the channel: the per-pid token bucket should allow the
    // burst (4) then start refusing (-EAGAIN) — visible rate limiting.
    let mut allowed = 0;
    let mut limited = 0;
    for i in 0..8 {
        let n = egress(req, &mut resp);
        if n < 0 {
            limited += 1;
            println!("[elf-egress] petition {} -> refused ({})", i, n);
        } else {
            allowed += 1;
            println!("[elf-egress] petition {} -> {} bytes", i, n);
        }
    }
    println!("[elf-egress] {} allowed, {} rate-limited", allowed, limited);
    if allowed > 0 {
        let n = resp.iter().position(|&b| b == 0).unwrap_or(80).min(80);
        if let Ok(s) = core::str::from_utf8(&resp[..n]) {
            println!("[elf-egress] host says: {}", s);
        }
    }
    if allowed == 0 { 1 } else { 0 }
}

entry!(main);
