//! `AX_MMAP` self-test: grows the private heap, writes a pattern through
//! the new mapping, reads it back, and checks growth increments return
//! distinct pages. Needs `Rights::ALLOC` (and `SEND` to report).

#![no_std]
#![no_main]

use axiom_x_user::{entry, getpid, mmap, println};

fn main() -> i32 {
    let pid = getpid();
    println!("[elf-heap] pid {}: AX_MMAP self-test", pid);

    // Two growth calls: 3 pages then 2 pages — must not overlap.
    let a = mmap(3 * 4096);
    if a < 0 {
        println!("[elf-heap] mmap #1 failed: {}", a);
        return 1;
    }
    let b = mmap(2 * 4096);
    if b < 0 {
        println!("[elf-heap] mmap #2 failed: {}", b);
        return 1;
    }
    let disjoint = b >= a + 3 * 4096;

    // The kernel promises zeroed pages.
    let zero_ok = unsafe { (0..(5 * 4096) as u64).all(|i| *(a as *const u8).offset(i as isize) == 0) };

    // Write a pattern across every page and read it back.
    let mut rw_ok = true;
    unsafe {
        for page in 0..5u64 {
            let p = a as *mut u64;
            for w in 0..512u64 {
                let val = page * 512 + w;
                p.offset((page * 512 + w) as isize).write_volatile(val);
            }
        }
        for i in 0..(5 * 512) as u64 {
            if (a as *const u64).offset(i as isize).read_volatile() != i {
                rw_ok = false;
            }
        }
    }
    println!(
        "[elf-heap] base {:#x}, growth disjoint: {}, zeroed: {}, rw: {}",
        a, disjoint, zero_ok, rw_ok
    );
    if disjoint && zero_ok && rw_ok { 0 } else { 1 }
}

entry!(main);
