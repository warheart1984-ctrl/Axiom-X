//! Axiom-X x86_64 Architecture Support
//!
//! Architecture-specific implementation for x86_64:
//! - Process management and context switching
//! - Interrupt handling (IDT, exceptions, IRQs, syscalls)
//! - Memory management (paging, page tables)
//! - CPU feature detection and initialization
//!
//! Status: `skeleton` — core structures and handlers defined; integration TODO.

#![no_std]
#![feature(abi_x86_interrupt, naked_functions, asm_const)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::ToString;

pub mod process;
pub mod interrupts;

pub use process::*;
pub use interrupts::*;

use core::arch::asm;
use x86_64::registers::control::{Cr0, Cr4};
use x86_64::registers::model_specific::{Efer, EferFlags};
use x86_64::VirtAddr;

/// PIT (Programmable Interval Timer) I/O ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

/// Initialize x86_64 architecture
pub fn init_arch() {
    // Enable SSE/FPU
    unsafe {
        Cr0::update(|c| {
            c.remove(x86_64::registers::control::Cr0Flags::EMULATE_COPROCESSOR);
            c.insert(x86_64::registers::control::Cr0Flags::MONITOR_COPROCESSOR);
        });
        Cr4::update(|c| {
            c.insert(x86_64::registers::control::Cr4Flags::OSFXSR);
            c.insert(x86_64::registers::control::Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }

    // Mask all PIC IRQs FIRST (before initializing PIT) to prevent
    // spurious interrupts before IDT is ready. The PIT will fire at
    // 1000 Hz immediately after initialization, and without a valid
    // IDT loaded, any interrupt would triple-fault.
    unsafe {
        outb(0x21, 0xFF); // Mask all IRQs on master PIC
        outb(0xA1, 0xFF); // Mask all IRQs on slave PIC
    }

    // Initialize PIT timer (100 Hz = the scheduler's 10 ms slice). At 1000 Hz
    // an unoptimized tick outlasts the period and the IRQ livelocks the CPU.
    init_pit(100);

    // Initialize IDT
    init_idt();

    // Initialize SYSCALL/SYSRET
    init_syscall();

    // Remap the 8259 PICs off the CPU exception vectors: the BIOS default
    // puts IRQ0 on vector 8, so an unremapped timer tick is a "double fault".
    remap_pic(0x20, 0x28);

    // Unmask IRQ0 (timer) on master PIC, keep other IRQs masked.
    // Interrupts stay disabled (IF=0): the timer handler needs the scheduler
    // and process table, so the boot path executes `sti` once those exist.
    outb(0x21, 0xFE);
    outb(0xA1, 0xFF);
    log::info!("x86_64 architecture initialized (interrupts still disabled)");
}

/// Reinitialize both 8259 PICs with IRQ0-7 at `master_offset` and IRQ8-15
/// at `slave_offset`, leaving every line masked.
pub fn remap_pic(master_offset: u8, slave_offset: u8) {
    outb(0x20, 0x11); // ICW1: init, expect ICW4
    outb(0xA0, 0x11);
    outb(0x21, master_offset); // ICW2: vector offsets
    outb(0xA1, slave_offset);
    outb(0x21, 0x04); // ICW3: slave on IRQ2
    outb(0xA1, 0x02); // ICW3: slave cascade identity
    outb(0x21, 0x01); // ICW4: 8086 mode
    outb(0xA1, 0x01);
    outb(0x21, 0xFF); // mask all
    outb(0xA1, 0xFF);
}

/// Initialize PIT (Programmable Interval Timer) for timer interrupts
/// Frequency in Hz (e.g., 1000 for 1ms ticks)
pub fn init_pit(frequency_hz: u32) {
    // PIT base frequency is 1193182 Hz
    const PIT_BASE_FREQ: u32 = 1193182;
    let divisor = PIT_BASE_FREQ / frequency_hz;
    
    // Command byte: Channel 0, lobyte/hibyte, mode 3 (square wave), binary
    unsafe {
        outb(PIT_COMMAND, 0x36); // Channel 0, lobyte/hibyte, mode 3
        outb(PIT_CHANNEL0, (divisor & 0xFF) as u8);        // Low byte
        outb(PIT_CHANNEL0, ((divisor >> 8) & 0xFF) as u8); // High byte
    }
    
    log::info!("PIT initialized at {} Hz (divisor={})", frequency_hz, divisor);
}

/// Initialize CPU features
pub fn init_cpu_features() {
    use raw_cpuid::CpuId;

    let cpuid = CpuId::new();
    let vendor = cpuid.get_vendor_info().map(|v| v.as_str().to_owned()).unwrap_or_else(|| "Unknown".to_owned());
    log::info!("CPU Vendor: {}", vendor);

    let feature_info = cpuid.get_feature_info();
    if let Some(feature_info) = feature_info.as_ref() {
        log::info!("Features: SSE={}, SSE2={}, SSE3={}, SSSE3={}, SSE4.1={}, SSE4.2={}, AVX={}, FMA={}",
            feature_info.has_sse(),
            feature_info.has_sse2(),
            feature_info.has_sse3(),
            feature_info.has_ssse3(),
            feature_info.has_sse41(),
            feature_info.has_sse42(),
            feature_info.has_avx(),
            feature_info.has_fma()
        );
    }

    if let Some(ext_features) = cpuid.get_extended_feature_info() {
        log::info!("Extended: FSGSBASE={}, RDRAND={}, RDSEED={}, CLFLUSHOPT={}, CLWB={}, AVX2={}",
            ext_features.has_fsgsbase(),
            feature_info.as_ref().map(|f| f.has_rdrand()).unwrap_or(false),
            ext_features.has_rdseed(),
            ext_features.has_clflushopt(),
            ext_features.has_clwb(),
            ext_features.has_avx2()
        );
    }
}

/// Enable long mode (if not already in it)
pub fn ensure_long_mode() -> Result<(), &'static str> {
    let cpuid = raw_cpuid::CpuId::new();

    // Check long mode support
    if let Some(extended) = cpuid.get_extended_processor_and_feature_identifiers() {
        if !extended.has_64bit_mode() {
            return Err("Long mode not supported");
        }
    }

    // Check if already in long mode
    let efer = Efer::read();
    if efer.contains(EferFlags::LONG_MODE_ENABLE) {
        log::info!("Already in long mode");
        return Ok(());
    }

    Err("Long mode enable must be done in bootloader")
}

/// Get current stack pointer
#[inline]
pub fn current_stack_pointer() -> VirtAddr {
    let rsp: u64;
    unsafe { asm!("mov {}, rsp", out(reg) rsp) };
    VirtAddr::new(rsp)
}

/// Halt CPU (for idle loop)
#[inline]
pub fn halt() {
    unsafe { asm!("hlt") };
}

/// Read TSC (timestamp counter)
#[inline]
pub fn read_tsc() -> u64 {
    let tsc: u64;
    unsafe { asm!("rdtsc", out("rax") tsc) };
    tsc
}

/// Write to I/O port
#[inline]
pub fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value) };
}

/// Read from I/O port
#[inline]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") value) };
    value
}

/// Write 16-bit to I/O port
#[inline]
pub fn outw(port: u16, value: u16) {
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") value) };
}

/// Read 16-bit from I/O port
#[inline]
pub fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe { asm!("in ax, dx", in("dx") port, out("ax") value) };
    value
}

/// Write 32-bit to I/O port
#[inline]
pub fn outl(port: u16, value: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value) };
}

/// Read 32-bit from I/O port
#[inline]
pub fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe { asm!("in eax, dx", in("dx") port, out("eax") value) };
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_context_size() {
        assert_eq!(core::mem::size_of::<crate::process::CpuContext>(), 15 * 8 + 8 * 6 + 2 * 8 + 6 * 2 + 2 * 8 + 8);
    }

    #[test]
    fn test_syscall_frame_size() {
        assert_eq!(core::mem::size_of::<interrupts::SyscallFrame>(), 15 * 8);
    }
}