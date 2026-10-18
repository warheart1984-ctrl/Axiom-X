//! Touches kernel memory from ring 3; the kernel must kill it with
//! SIGSEGV (its parent then sees "killed by signal 11" from `wait4`).

#![no_std]
#![no_main]

use axiom_x_user::{entry, getpid, println};

fn main() -> i32 {
    println!("[elf-crash] pid {} reading a kernel address", getpid());
    let v = unsafe { (0xFFFF_8000_0010_0000 as *const u64).read_volatile() };
    // Only reachable if user/kernel isolation is broken.
    println!("[elf-crash] read {:#x}: isolation broken", v);
    2
}

entry!(main);
