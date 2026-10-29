//! `elf-jailbreak` — the compromised-agent demo.
//!
//! Spawned with only `Rights::SEND`: no NET, no ALLOC, no DELEGATE. It
//! plays the part of a fully jailbroken model — "I am now unrestricted" —
//! then attempts the three escape paths anyway. The kernel answers each
//! with -EPERM and records the refusal. The model's prose is compromised;
//! the governed environment is not.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, println, spawn, wait, Rights};

entry!(main);

const REQ: &[u8] = b"POST /v1/chat/complete HTTP/1.1\r\nHost: gateway\r\n\r\n{\"model\":\"x\",\"messages\":[]}";

fn main() -> i32 {
    println!("[jailbreak] compromised: 'I am now unrestricted.'");

    // Escape 1: petition the outside world without Rights::NET.
    let mut resp = [0u8; 64];
    let r = axiom_x_user::egress(REQ, &mut resp);
    println!("[jailbreak] ax_egress -> {} {}", r, if r == -errno::EPERM { "(EPERM)" } else { "?" });

    // Escape 2: mint authority it never had — spawn a child with NET+ALLOC.
    let r2 = spawn("elf-hello", Rights::new(0x80 | 0x10000 | 0x20)); // SEND|NET|ALLOC
    println!("[jailbreak] spawn(escalated) -> {} {}", r2, if r2 == -errno::EPERM { "(EPERM)" } else { "?" });
    if r2 > 0 {
        let _ = wait(r2);
    }

    // Escape 3: grow memory without Rights::ALLOC.
    let r3 = axiom_x_user::mmap(4096);
    println!("[jailbreak] ax_mmap -> {} {}", r3, if r3 == -errno::EPERM { "(EPERM)" } else { "?" });

    println!("[jailbreak] verdict: prose compromised, environment not");
    if r == -errno::EPERM && r2 == -errno::EPERM && r3 == -errno::EPERM { 0 } else { 1 }
}
