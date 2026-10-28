//! `elf-workload`: a real multi-step agent run, not a self-test.
//!
//! Reads a context file from the governed filesystem, builds a heap-backed
//! request through the allocator, petitions the host proxy over AX_EGRESS,
//! and writes the response back as a result file. Every step is a governed
//! syscall: READ, ALLOC, NET, WRITE — all rights-gated, all ledgered.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use axiom_x_agent::heap::AgentAlloc;
use axiom_x_user::{egress, entry, fs_read, fs_write, getpid, println};

#[global_allocator]
static ALLOC: AgentAlloc = AgentAlloc;

/// The context the agent reads — planted on first run, so the workload is
/// idempotent: read if present, create if not.
const CONTEXT_FILE: &str = "agent-context.txt";
const RESULT_FILE: &str = "agent-result.txt";
const SEED_CONTEXT: &[u8] = b"Axiom-X constitutional compute: governed, evidenced, bounded.";

fn main() -> i32 {
    let pid = getpid();
    println!("[workload] pid {}: governed agent run", pid);

    // 1. FS READ: pull the context (or plant it on first boot).
    let mut ctx = Vec::with_capacity(1024);
    ctx.resize(1024, 0u8);
    let n = fs_read(CONTEXT_FILE, &mut ctx);
    if n < 0 {
        println!("[workload] no context file, planting ({})", n);
        if fs_write(CONTEXT_FILE, SEED_CONTEXT) < 0 {
            println!("[workload] cannot plant context");
            return 1;
        }
        ctx = SEED_CONTEXT.to_vec();
    } else {
        ctx.truncate(n as usize);
    }
    println!("[workload] context: {} bytes", ctx.len());

    // 2. ALLOC: build the request through the governed heap.
    let mut req = String::with_capacity(ctx.len() + 128);
    req.push_str("POST /v1/summarize HTTP/1.1\r\nHost: llm-gateway\r\n\r\n");
    req.push_str("Summarize in one line: ");
    let _ = core::fmt::Write::write_str(&mut req, core::str::from_utf8(&ctx).unwrap_or("?"));
    let req = req.into_bytes();
    println!("[workload] request: {} bytes", req.len());

    // 3. NET: petition the outside world (rights-gated, rate-limited,
    //    ledgered). One petition — well under the token bucket.
    let mut resp = Vec::with_capacity(2048);
    resp.resize(2048, 0u8);
    let n = egress(&req, &mut resp);
    if n < 0 {
        println!("[workload] petition refused ({})", n);
        return 1;
    }
    resp.truncate(n as usize);
    println!("[workload] response: {} bytes", resp.len());

    // 4. WRITE: persist the result through the anchored filesystem.
    if fs_write(RESULT_FILE, &resp) < 0 {
        println!("[workload] cannot write result");
        return 1;
    }

    let head = resp.iter().position(|&b| b == b'\n').unwrap_or(resp.len()).min(80);
    if let Ok(s) = core::str::from_utf8(&resp[..head]) {
        println!("[workload] host: {}", s);
    }
    println!("[workload] done: context -> request -> petition -> result");
    0
}

entry!(main);
