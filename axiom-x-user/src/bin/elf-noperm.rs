//! Started with no rights: every governed call must be refused with -EPERM.
//! It cannot print (writing needs `Rights::SEND`), so the result is its exit
//! code (0 = both calls refused as expected) plus the kernel ledger's
//! DENY records.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, spawn, write, Rights};

fn main() -> i32 {
    let w = write(1, b"[elf-noperm] this must not appear\n");
    let s = spawn("elf-hello", Rights::NONE);
    if w == -errno::EPERM && s == -errno::EPERM { 0 } else { 1 }
}

entry!(main);
