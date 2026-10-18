//! User-space init: starts the other programs with `AX_SPAWN_MODULE`,
//! checks the spawn failure cases, and reaps every child with `wait4`.
//!
//! Expected (the kernel's boot-module set):
//! - `elf-hello`, `elf-fast`, `elf-slow` exit 0; `elf-crash` is killed by
//!   signal 11 (ring-3 page fault);
//! - `elf-bad-wx` fails with -ENOEXEC (the loader rejects W+X), and
//!   `no-such-program` with -ENOENT;
//! - after all children are reaped, `wait4(-1)` returns -ECHILD.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, getpid, println, spawn, wait, ExitStatus};

const PROGRAMS: [&str; 6] = ["elf-hello", "elf-fast", "elf-slow", "elf-crash", "elf-bad-wx", "no-such-program"];

fn main() -> i32 {
    println!("[init] user-space init running as pid {}", getpid());

    let mut children = [0u32; PROGRAMS.len()];
    let mut n = 0;
    let mut failures_as_expected = 0;
    for name in PROGRAMS {
        let r = spawn(name);
        if r > 0 {
            println!("[init] spawn {} -> pid {}", name, r);
            children[n] = r as u32;
            n += 1;
        } else {
            println!("[init] spawn {} -> {} ({})", name, r, errno::name(r));
            let expected = match name {
                "elf-bad-wx" => -errno::ENOEXEC,
                "no-such-program" => -errno::ENOENT,
                _ => 0,
            };
            if r == expected {
                failures_as_expected += 1;
            }
        }
    }

    // Wait for the first child by PID, then for the rest in exit order.
    let mut reaped = 0;
    let mut clean = 0;
    let mut killed = 0;
    let mut record = |pid: u32, status: ExitStatus| {
        match status {
            ExitStatus::Exited(code) => {
                println!("[init] reaped pid {}: exited with code {}", pid, code);
                if code == 0 {
                    clean += 1;
                }
            }
            ExitStatus::Signaled(sig) => {
                println!("[init] reaped pid {}: killed by signal {}", pid, sig);
                killed += 1;
            }
        }
    };
    if n > 0 {
        match wait(children[0] as i64) {
            Ok((pid, st)) => {
                record(pid, st);
                reaped += 1;
            }
            Err(e) => println!("[init] wait({}) -> {} ({})", children[0], e, errno::name(e)),
        }
    }
    while reaped < n {
        match wait(-1) {
            Ok((pid, st)) => {
                record(pid, st);
                reaped += 1;
            }
            Err(e) => {
                println!("[init] wait(-1) -> {} ({})", e, errno::name(e));
                break;
            }
        }
    }

    let none_left = wait(-1);
    println!(
        "[init] all children reaped: {}/{} (exit 0: {}, signaled: {}); expected spawn failures: {}/2; wait(-1) now -> {:?}",
        reaped, n, clean, killed, failures_as_expected, none_left.map(|(p, _)| p)
    );
    let ok = reaped == n && clean == 3 && killed == 1 && failures_as_expected == 2
        && none_left == Err(-errno::ECHILD);
    println!("[init] process-lifecycle check: {}", if ok { "PASS" } else { "FAIL" });
    if ok { 0 } else { 1 }
}

entry!(main);
