//! First Rust program loaded from an ELF module: checks the loader set up
//! `.data` (initialized) and `.bss` (zeroed) correctly, and uses getpid and
//! sched_yield.

#![no_std]
#![no_main]

use axiom_x_user::{entry, getpid, println, yield_now};

/// In `.data`: must arrive with its initial value.
static mut COUNTER: u64 = 41;
/// In `.bss` (memsz > filesz): must arrive zeroed.
static mut ZEROED: [u64; 512] = [0; 512];

fn main() -> i32 {
    let pid = getpid();
    println!("[elf-hello] pid {}: Rust ELF running in ring 3", pid);

    // Volatile accesses: the optimizer must not fold these statics away, or
    // the check would not touch the loaded .data/.bss pages at all.
    let (data_ok, bss_ok) = unsafe {
        let p = core::ptr::addr_of_mut!(COUNTER);
        p.write_volatile(p.read_volatile() + 1);
        let z = core::ptr::addr_of!(ZEROED) as *const u64;
        let bss_ok = (0..512).all(|i| z.add(i).read_volatile() == 0);
        (p.read_volatile() == 42, bss_ok)
    };
    println!("[elf-hello] .data initialized: {}, .bss zeroed: {}", data_ok, bss_ok);

    yield_now();
    println!("[elf-hello] back after sched_yield, exiting");
    if data_ok && bss_ok { 0 } else { 1 }
}

entry!(main);
