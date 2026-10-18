//! Started with no rights: every governed call must be refused with -EPERM.
//! It cannot print (writing needs `Rights::SEND`), so the result is its exit
//! code (0 = every call refused as expected; otherwise bit i is set for
//! each call i that was not refused) plus the kernel ledger's DENY records.

#![no_std]
#![no_main]

use axiom_x_user::{entry, errno, fs_delete, fs_list, fs_read, fs_write, spawn, write, FileInfo, Rights};

fn main() -> i32 {
    let mut files = [FileInfo::EMPTY; 1];
    let mut buf = [0u8; 16];
    let results = [
        write(1, b"[elf-noperm] this must not appear\n"),
        spawn("elf-hello", Rights::NONE),
        spawn("/bin/hello", Rights::NONE),
        fs_list(&mut files),
        fs_read("notes.txt", &mut buf),
        fs_write("noperm.txt", b"must not be created"),
        fs_delete("notes.txt"),
    ];
    let mut code = 0;
    for (i, r) in results.iter().enumerate() {
        if *r != -errno::EPERM {
            code |= 1 << i;
        }
    }
    code
}

entry!(main);
