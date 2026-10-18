//! Sleeps 100 ms five times. Runs alongside `elf-slow`: their wake order
//! follows the deadlines, which only real blocking sleep produces.

#![no_std]
#![no_main]

use axiom_x_user::{entry, getpid, println, sleep_ms};

fn main() -> i32 {
    let pid = getpid();
    for i in 1..=5 {
        let r = sleep_ms(100);
        println!("[elf-fast] pid {} woke {}/5 at ~{} ms (sleep -> {})", pid, i, i * 100, r);
    }
    0
}

entry!(main);
