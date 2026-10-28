//! User-space init: starts the other programs with `AX_SPAWN_MODULE`,
//! granting each only the rights it needs, checks the spawn failure cases
//! (including an escalation attempt), reaps every child with `wait4`, then
//! runs the auditor over the kernel's evidence ledger.
//!
//! Expected (the kernel's boot-module set):
//! - `elf-hello`, `elf-fast`, `elf-slow` (SEND) exit 0; `elf-crash` (SEND)
//!   is killed by signal 11; `elf-noperm` (no rights) exits 0 after both of
//!   its calls are refused with -EPERM;
//! - spawn failures: `elf-bad-wx` -ENOEXEC, `no-such-program` -ENOENT, and
//!   `elf-hello` with IO_PORT (which init does not hold) -EPERM;
//! - `elf-audit` (SEND + EVIDENCE) verifies the ledger chain and exits 0;
//! - finally `wait4(-1)` returns -ECHILD.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, getpid, println, spawn, wait, ExitStatus, Rights};

/// (module, rights granted, expected spawn result: 0 = success, else -errno)
const PROGRAMS: [(&str, Rights, i64); 9] = [
    ("elf-hello", Rights::SEND, 0),
    ("elf-heap", Rights::new(Rights::SEND.bits() | Rights::ALLOC.bits()), 0),
    ("elf-fast", Rights::SEND, 0),
    ("elf-slow", Rights::SEND, 0),
    ("elf-crash", Rights::SEND, 0),
    ("elf-noperm", Rights::NONE, 0),
    ("elf-bad-wx", Rights::SEND, -errno::ENOEXEC),
    ("no-such-program", Rights::SEND, -errno::ENOENT),
    // Escalation: init does not hold IO_PORT, so it cannot grant it.
    ("elf-hello", Rights::new(Rights::SEND.bits() | Rights::IO_PORT.bits()), -errno::EPERM),
];

fn main() -> i32 {
    println!("[init] user-space init running as pid {}", getpid());

    let mut children = [0u32; PROGRAMS.len()];
    let mut n = 0;
    let mut failures_as_expected = 0;
    for (name, rights, expected) in PROGRAMS {
        let r = spawn(name, rights);
        if r > 0 {
            println!("[init] spawn {} rights {:#x} -> pid {}", name, rights.bits(), r);
            children[n] = r as u32;
            n += 1;
        } else {
            println!("[init] spawn {} rights {:#x} -> {} ({})", name, rights.bits(), r, errno::name(r));
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

    // With every other child reaped, audit the ledger they produced.
    let audit_ok = match spawn("elf-audit", Rights::new(Rights::SEND.bits() | Rights::EVIDENCE.bits())) {
        r if r > 0 => matches!(wait(r), Ok((_, ExitStatus::Exited(0)))),
        r => {
            println!("[init] spawn elf-audit -> {} ({})", r, errno::name(r));
            false
        }
    };

    let none_left = wait(-1);
    println!(
        "[init] all children reaped: {}/{} (exit 0: {}, signaled: {}); expected spawn failures: {}/3; audit ok: {}; wait(-1) now -> {:?}",
        reaped, n, clean, killed, failures_as_expected, audit_ok, none_left.map(|(p, _)| p)
    );
    let ok = reaped == n && clean == 4 && killed == 1 && failures_as_expected == 3
        && audit_ok && none_left == Err(-errno::ECHILD);
    println!("[init] process-lifecycle check: {}", if ok { "PASS" } else { "FAIL" });
    if ok { 0 } else { 1 }
}

entry!(main);
