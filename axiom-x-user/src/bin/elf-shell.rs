//! `elf-shell`: the Axiom-X interactive shell.
//!
//! Reads the console (serial or PS/2 keyboard, via `read(0)`), edits a
//! line locally (echo, backspace), and runs built-in commands. Everything
//! it does goes through the same governed syscalls as any program: the
//! kernel grants the shell SEND, RECV, SPAWN, DELEGATE and EVIDENCE, and
//! programs it starts get only what `run` passes on.

#![no_std]
#![no_main]

use axiom_x_user::ledger::{civil::DateTime, verify_window};
use axiom_x_user::{
    clock_ns, entry, errno, evidence, evidence_count, getpid, print, println, proc_list, read, spawn, wait, write,
    ExitStatus, ProcInfo, Rights, CLOCK_MONOTONIC, CLOCK_REALTIME,
};

const PROMPT: &str = "axiom> ";
const MAX_LINE: usize = 128;

fn help() {
    println!("commands:");
    println!("  help                  this list");
    println!("  echo <text>           print text");
    println!("  date                  wall clock (RTC-anchored, no time zone)");
    println!("  uptime                time since boot (TSC)");
    println!("  ps                    processes: pid, parent, state, rights, name");
    println!("  rights                this shell's rights");
    println!("  run <program> [+evidence] [-send]");
    println!("                        start a boot module and wait; it gets SEND by default,");
    println!("                        +evidence adds EVIDENCE, -send removes SEND");
    println!("  ledger                verify the newest evidence records' hash chain");
    println!("  exit                  leave (the kernel starts a new shell)");
}

/// Short letters for the rights the shell knows about (`all` for kernel).
fn rights_str(r: u64, out: &mut [u8; 8]) -> &str {
    if r == u64::MAX {
        return "all";
    }
    let mut n = 0;
    for (bit, c) in [
        (Rights::SEND, b'S'),
        (Rights::RECV, b'R'),
        (Rights::SPAWN, b'P'),
        (Rights::DELEGATE, b'D'),
        (Rights::EVIDENCE, b'E'),
    ] {
        if r & bit.bits() != 0 {
            out[n] = c;
            n += 1;
        }
    }
    if n == 0 {
        return "-";
    }
    core::str::from_utf8(&out[..n]).unwrap_or("?")
}

fn cmd_ps() {
    let mut procs = [ProcInfo { pid: 0, parent: 0, state: 0, rights: 0, name: [0; 16] }; 32];
    let n = proc_list(&mut procs);
    if n < 0 {
        println!("ps: {} ({})", n, errno::name(n));
        return;
    }
    println!("  PID PARENT STATE    RIGHTS NAME");
    for p in &procs[..n as usize] {
        let mut b = [0u8; 8];
        println!("{:>5} {:>6} {:<8} {:<6} {}", p.pid, p.parent, p.state_name(), rights_str(p.rights, &mut b), p.name());
    }
}

fn cmd_rights() {
    let me = getpid();
    let mut procs = [ProcInfo { pid: 0, parent: 0, state: 0, rights: 0, name: [0; 16] }; 32];
    let n = proc_list(&mut procs);
    match procs[..n.max(0) as usize].iter().find(|p| p.pid == me) {
        Some(p) => {
            let mut b = [0u8; 8];
            println!("pid {}: rights {} ({:#x})  S=send R=recv P=spawn D=delegate E=evidence", me, rights_str(p.rights, &mut b), p.rights);
        }
        None => println!("rights: cannot see own entry ({})", errno::name(n)),
    }
}

fn cmd_date() {
    match clock_ns(CLOCK_REALTIME) {
        Ok(ns) => println!("{} (RTC time, no time zone)", DateTime::from_unix(ns / 1_000_000_000)),
        Err(e) => println!("date: {} ({})", e, errno::name(e)),
    }
}

fn cmd_uptime() {
    match clock_ns(CLOCK_MONOTONIC) {
        Ok(ns) => {
            let s = ns / 1_000_000_000;
            println!("up {}h {:02}m {:02}.{:03}s", s / 3600, s / 60 % 60, s % 60, ns / 1_000_000 % 1000);
        }
        Err(e) => println!("uptime: {} ({})", e, errno::name(e)),
    }
}

fn cmd_run(args: &str) {
    let mut parts = args.split_whitespace();
    let Some(name) = parts.next() else {
        println!("usage: run <program> [+evidence] [-send]");
        return;
    };
    let mut rights = Rights::SEND.bits();
    for flag in parts {
        match flag {
            "+evidence" => rights |= Rights::EVIDENCE.bits(),
            "-send" => rights &= !Rights::SEND.bits(),
            other => {
                println!("run: unknown flag '{}'", other);
                return;
            }
        }
    }
    let pid = spawn(name, Rights::new(rights));
    if pid < 0 {
        println!("run {}: {} ({})", name, pid, errno::name(pid));
        return;
    }
    match wait(pid) {
        Ok((p, ExitStatus::Exited(code))) => println!("[pid {} '{}' exited with code {}]", p, name, code),
        Ok((p, ExitStatus::Signaled(sig))) => println!("[pid {} '{}' killed by signal {}]", p, name, sig),
        Err(e) => println!("run: wait failed {} ({})", e, errno::name(e)),
    }
}

fn cmd_ledger() {
    let total = match evidence_count() {
        Ok(t) => t,
        Err(e) => {
            println!("ledger: {} ({})", e, errno::name(e));
            return;
        }
    };
    let first = total.saturating_sub(200);
    match verify_window(first, total, |seq| evidence(seq).ok()) {
        Ok(head) => {
            print!("ledger: {} records; newest {} verified; head ", total, total - first);
            for b in &head[..8] {
                print!("{:02x}", b);
            }
            println!("...");
        }
        Err(seq) => println!("ledger: chain BROKEN at record {}", seq),
    }
}

fn execute(line: &str) -> bool {
    let line = line.trim();
    let (cmd, rest) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };
    match cmd {
        "" => {}
        "help" | "?" => help(),
        "echo" => println!("{}", rest),
        "date" => cmd_date(),
        "uptime" => cmd_uptime(),
        "ps" => cmd_ps(),
        "rights" => cmd_rights(),
        "run" => cmd_run(rest),
        "ledger" => cmd_ledger(),
        "exit" => return false,
        other => println!("{}: unknown command (try 'help')", other),
    }
    true
}

fn main() -> i32 {
    println!("");
    println!("Axiom-X shell (pid {}). Type 'help'.", getpid());
    print!("{}", PROMPT);
    let mut line = [0u8; MAX_LINE];
    let mut len = 0;
    let mut buf = [0u8; 64];
    loop {
        let n = read(0, &mut buf);
        if n < 0 {
            println!("shell: read failed {} ({})", n, errno::name(n));
            return 1;
        }
        for &c in &buf[..n as usize] {
            match c {
                b'\n' => {
                    write(1, b"\n");
                    let text = core::str::from_utf8(&line[..len]).unwrap_or("");
                    if !execute(text) {
                        println!("bye");
                        return 0;
                    }
                    len = 0;
                    print!("{}", PROMPT);
                }
                0x08 | 0x7F => {
                    if len > 0 {
                        len -= 1;
                        write(1, b"\x08 \x08");
                    }
                }
                0x20..=0x7E if len < MAX_LINE => {
                    line[len] = c;
                    len += 1;
                    write(1, &[c]);
                }
                _ => {}
            }
        }
    }
}

entry!(main);
