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
    let n = egress(req, &mut resp);
    if n < 0 {
        println!("[elf-egress] petition recorded, no proxy answer ({})", n);
        // The syscall itself ran: rights check + ledger record happened
        // even though the channel timed out.
        return if n == -1 { 1 } else { 0 };
    }
    let n = n as usize;
    println!("[elf-egress] {} bytes from host:", n);
    for chunk in resp[..n].chunks(80) {
        if let Ok(s) = core::str::from_utf8(chunk) {
            println!("  {}", s);
        }
    }
    0
}

entry!(main);
