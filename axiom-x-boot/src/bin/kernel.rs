//! Axiom-X bootable kernel binary (x86_64, multiboot1+2, ELF64, higher-half).
//!
//! The multiboot1 + multiboot2 headers and the 32-bit → 64-bit entry trampoline
//! live in `src/trampoline.S` (assembled with GNU as). The Rust boot path is
//! provided by the `axiom-x-boot` library: `ax_kernel_entry` owns serial init,
//! multiboot2 parsing, paging, the scheduler, and the first context switch.
//!
//! Boot flow (a coordinate change, not just a jump):
//!
//! ```text
//! load : ELF -> P         bootloader loads segments at 1 MiB (physical)
//! map  : V -> P           trampoline builds identity + higher-half tables
//! tramp : P -> V          long mode + CR3, then jumps into the higher half
//! entry : V -> KernelState ax_kernel_entry runs linked at VIRT_BASE
//! ```
//!
//! Lang items (panic handler, global allocator) are supplied by the
//! `axiom-x-boot` library when built with the `freestanding` feature:
//!
//! ```text
//! cargo build --release --target x86_64-unknown-none \
//!     -p axiom-x-boot --bin kernel --no-default-features --features freestanding
//! ```

#![no_std]
#![no_main]

use core::arch::global_asm;

// Import the trampoline entry point from trampoline.S
global_asm!(
    ".section .multiboot, \"a\"",
    ".align 8",
    "mb2_start:",
    "    .long 0xE85250D6",
    "    .long 0",
    "    .long mb2_hdr_end - mb2_start",
    "    .long -(0xE85250D6 + 0 + (mb2_hdr_end - mb2_start))",
    "    .word 0",
    "    .word 0",
    "    .long 8",
    "mb2_hdr_end:",
    ".align 4",
    "    .long 0x1BADB002",
    "    .long 0x00000003",
    "    .long 0xE4524FFB",
);

extern "C" {
    // Defined in trampoline.S
    fn _start();
}

// Rust trampoline so the binary links against the `axiom-x-boot` library crate.
// Referencing the crate forces rustc to load its metadata, which is what
// surfaces the library's freestanding `#[panic_handler]` / `#[global_allocator]`.
#[no_mangle]
pub extern "C" fn kernel_rust_entry(mbi_addr: u64, magic: u32) -> ! {
    // Magic 0x2BADB002 = Multiboot1 (GRUB "multiboot" / QEMU -kernel),
    // magic 0x36D76289 = Multiboot2 (GRUB multiboot2 / Limine).
    match magic {
        0x2BADB002 => axiom_x_boot::ax_kernel_entry_mb1(mbi_addr),
        0x36D76289 => axiom_x_boot::ax_kernel_entry(mbi_addr),
        _ => loop {},
    }
}
