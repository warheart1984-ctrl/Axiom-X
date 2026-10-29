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
    let mut req = String::with_capacity(ctx.len() + 256);
    req.push_str("POST /v1/chat/complete HTTP/1.1\r\nHost: llm-gateway\r\n\r\n");
    req.push_str("{\"model\":\"openrouter/gpt-4.1-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"");
    let _ = core::fmt::Write::write_str(&mut req, core::str::from_utf8(&ctx).unwrap_or("?"));
    req.push_str("\"}],\"params\":{\"max_tokens\":24}}");
    let req = req.into_bytes();
    println!("[workload] request: {} bytes", req.len());

    // 3. NET: the load run — 25 governed petitions. Each is rights-gated,
    //    rate-limited, and ledgered; -EAGAIN means the token bucket spoke,
    //    so we sleep a beat and retry — the limiter IS the demo.
    const PETITIONS: usize = 25;
    let mut allowed = 0usize;
    let mut limited = 0usize;
    let mut failed = 0usize;
    let mut resp = Vec::with_capacity(2048);
    for i in 0..PETITIONS {
        resp.clear();
        resp.resize(2048, 0u8);
        let mut tries = 0;
        let n = loop {
            let r = egress(&req, &mut resp);
            if r != -11 || tries >= 6 {
                break r;
            }
            tries += 1;
            limited += 1;
            axiom_x_user::sleep_ms(500);
        };
        if n < 0 {
            failed += 1;
            println!("[workload] petition {} -> {} ({})", i, n, tries);
        } else {
            allowed += 1;
            if i == 0 || i == PETITIONS - 1 || i % 8 == 0 {
                let head = resp[..n as usize].iter().position(|&b| b == b'\n').unwrap_or(n as usize).min(72);
                if let Ok(s) = core::str::from_utf8(&resp[..head]) {
                    println!("[workload] petition {} -> {}: {}", i, n, s);
                }
            }
        }
    }
    // 4. WRITE: persist a run summary through the anchored filesystem.
    let summary = alloc::format!(
        "petitions={} allowed={} rate_limited_retries={} failed={}\n",
        PETITIONS, allowed, limited, failed
    );
    if fs_write(RESULT_FILE, summary.as_bytes()) < 0 {
        println!("[workload] cannot write result");
        return 1;
    }
    println!("[workload] done: {}", summary.trim_end());
    if allowed == 0 { 1 } else { 0 }
}

entry!(main);
