//! Sleeps 250 ms twice; see `elf-fast`.

#![no_std]
#![no_main]

use axiom_x_user::{entry, getpid, println, sleep_ms};

fn main() -> i32 {
    let pid = getpid();
    for i in 1..=2 {
        let r = sleep_ms(250);
        println!("[elf-slow] pid {} woke {}/2 at ~{} ms (sleep -> {})", pid, i, i * 250, r);
    }
    0
}

entry!(main);
