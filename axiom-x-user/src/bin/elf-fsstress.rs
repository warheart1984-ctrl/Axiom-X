//! Concurrent file-system stress: starts two `elf-fswriter` workers at once
//! (and, if `/bin/h` exists in the file system, that program too, so a
//! spawn-from-file overlaps the writers), waits for all of them and reports.
//! Needs SEND, SPAWN, READ and WRITE (the workers get SEND + READ + WRITE).
//! Exit code 0 when every worker reported no problems.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, println, spawn, wait, ExitStatus, Rights};

fn main() -> i32 {
    let worker = Rights::new(Rights::SEND.bits() | Rights::READ.bits() | Rights::WRITE.bits());
    let mut started = 0;
    for _ in 0..2 {
        let pid = spawn("elf-fswriter", worker);
        if pid < 0 {
            println!("[fsstress] cannot start elf-fswriter: {} ({})", pid, errno::name(pid));
            return 1;
        }
        started += 1;
    }
    let extra = spawn("/bin/h", Rights::SEND);
    if extra > 0 {
        started += 1;
        println!("[fsstress] also started /bin/h from the file system as pid {}", extra);
    }
    let mut failed = 0;
    for _ in 0..started {
        match wait(-1) {
            Ok((_, ExitStatus::Exited(0))) => {}
            Ok((p, ExitStatus::Exited(c))) => {
                println!("[fsstress] pid {} reported {} problem(s)", p, c);
                failed += 1;
            }
            Ok((p, ExitStatus::Signaled(s))) => {
                println!("[fsstress] pid {} killed by signal {}", p, s);
                failed += 1;
            }
            Err(e) => {
                println!("[fsstress] wait failed: {} ({})", e, errno::name(e));
                failed += 1;
            }
        }
    }
    println!("[fsstress] {} process(es) finished, {} failed: {}", started, failed, if failed == 0 { "PASS" } else { "FAIL" });
    failed
}

entry!(main);
