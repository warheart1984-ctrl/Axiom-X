//! One file-system stress worker (started by `elf-fsstress`, two at a time).
//!
//! In each of `ROUNDS` rounds: write `FILES` files of `SIZE` bytes with
//! content unique to (pid, round, file), read every one back and compare,
//! then (after the last round) delete them. Running two of these at once
//! makes their file-system calls overlap: with preemptible file-system
//! syscalls, one is preempted while holding the FS lock and the other must
//! wait for it. Needs SEND, READ and WRITE. Exit code: number of problems.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, fs_delete, fs_read, fs_write, getpid, println};

const ROUNDS: u32 = 3;
const FILES: u32 = 8;
const SIZE: usize = 3000;

fn content(pid: u32, round: u32, file: u32, out: &mut [u8; SIZE]) {
    for (j, b) in out.iter_mut().enumerate() {
        *b = (pid.wrapping_mul(31) ^ round.wrapping_mul(7) ^ file.wrapping_mul(13)).wrapping_add(j as u32) as u8;
    }
}

/// "s<slot>-<file>": the slot keeps the two workers' names apart.
fn name(slot: u32, file: u32, buf: &mut [u8; 8]) -> &str {
    *buf = *b"s0-0    ";
    buf[1] = b'0' + (slot % 10) as u8;
    buf[3] = b'0' + (file % 10) as u8;
    core::str::from_utf8(&buf[..4]).unwrap()
}

fn main() -> i32 {
    let pid = getpid();
    let slot = pid % 2;
    let mut problems = 0;
    let mut want = [0u8; SIZE];
    let mut got = [0u8; SIZE];
    let mut nb = [0u8; 8];
    for round in 0..ROUNDS {
        for f in 0..FILES {
            content(pid, round, f, &mut want);
            let r = fs_write(name(slot, f, &mut nb), &want);
            if r < 0 {
                println!("[fswriter {}] write {} failed: {} ({})", pid, name(slot, f, &mut nb), r, errno::name(r));
                problems += 1;
            }
        }
        for f in 0..FILES {
            content(pid, round, f, &mut want);
            let r = fs_read(name(slot, f, &mut nb), &mut got);
            if r != SIZE as i64 || got != want {
                println!("[fswriter {}] read-back {} mismatch (r = {})", pid, name(slot, f, &mut nb), r);
                problems += 1;
            }
        }
    }
    for f in 0..FILES {
        if fs_delete(name(slot, f, &mut nb)) < 0 {
            problems += 1;
        }
    }
    println!(
        "[fswriter {}] {} rounds x {} files of {} bytes written, verified, deleted: {} problem(s)",
        pid, ROUNDS, FILES, SIZE, problems
    );
    problems
}

entry!(main);
