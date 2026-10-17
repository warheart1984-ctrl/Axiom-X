//! Axiom-X UEFI bootable kernel binary (x86_64, UEFI).
//!
//! This binary is built as a UEFI application (.efi) that can be booted
//! directly by OVMF/UEFI firmware. The UEFI firmware provides paging
//! already set up, avoiding the QEMU TCG bug with `mov cr0`.

#![no_std]
#![no_main]

#[cfg(feature = "uefi")]
use uefi::prelude::*;
#[cfg(feature = "uefi")]
use uefi_services::println;
#[cfg(feature = "uefi")]
use axiom_x_boot::ax_kernel_entry_uefi;

// Rust trampoline so the binary links against the `axiom-x-boot` library crate.
// Referencing the crate forces rustc to load its metadata, which is what
// surfaces the library's freestanding `#[panic_handler]` / `#[global_allocator]`.
#[cfg(feature = "uefi")]
#[no_mangle]
pub extern "efiapi" fn efi_main(image: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialize UEFI services
    uefi_services::init(&mut system_table).expect("Failed to initialize UEFI services");

    println!("Axiom-X UEFI kernel starting...");

    // Get memory map from UEFI
    let memory_map = system_table.boot_services().get_memory_map().expect("Failed to get memory map");

    // Get framebuffer info if available
    let framebuffer = system_table.boot_services().locate_protocol::<uefi::proto::console::gop::GraphicsOutput>().ok();

    // Convert UEFI memory map to our format
    let mut boot_info = crate::UefiBootInfo::new(memory_map, framebuffer);

    // Call the common kernel entry point
    ax_kernel_entry_uefi(boot_info)
}

// Import the common kernel entry point
extern "Rust" {
    fn ax_kernel_entry_uefi(boot_info: crate::UefiBootInfo) -> !;
}

global_asm!(
    ".section .text",
    ".global _start",
    "_start:",
    "    jmp efi_main",
);