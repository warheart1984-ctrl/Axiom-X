//! Agent-runtime smoke test: `Vec`, `String` and `format!` over the
//! `AX_MMAP`-backed `AgentAlloc` — the first user program with a real heap.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use axiom_x_agent::{entry, getpid, println, AgentAlloc};

#[global_allocator]
static ALLOC: AgentAlloc = AgentAlloc;

fn main() -> i32 {
    let pid = getpid();
    let mut probe: Vec<u8> = Vec::new();
    probe.push(1);
    println!("[elf-agent] pid {}: heap-backed collections", pid);

    // Vec growth forces repeated AX_MMAP arena extension.
    let mut words: Vec<String> = Vec::new();
    for i in 0..300u64 {
        words.push(format!("token-{}", i));
    }
    words.sort();
    let grown_ok = words.len() == 300 && words[0] == "token-0";

    // Free+realloc must hit the free list: drop half, refill, verify.
    words.truncate(150);
    let mut refill: Vec<String> = Vec::new();
    for i in 0..150u64 {
        refill.push(format!("r{}", i));
    }
    let reuse_ok = refill.len() == 150 && refill[149] == "r149";

    // One big allocation beyond a single arena chunk.
    let mut big: Vec<u8> = Vec::with_capacity(128 * 1024);
    for i in 0..big.capacity() {
        big.push((i & 0xff) as u8);
    }
    let big_ok = big.len() == 128 * 1024 && big[127 * 1024] == 0;

    println!(
        "[elf-agent] grow: {}, reuse: {}, big(128KiB): {}",
        grown_ok, reuse_ok, big_ok
    );
    if grown_ok && reuse_ok && big_ok { 0 } else { 1 }
}

entry!(main);
