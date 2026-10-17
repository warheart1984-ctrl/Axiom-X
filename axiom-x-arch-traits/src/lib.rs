//! Architecture-Agnostic Hardware Abstraction Traits for Axiom-X
//!
//! These traits define the hardware contract that the kernel depends on.
//! Each architecture (x86_64, ARM64, RISC-V) provides its own implementation.
//!
//! Status: `enforced` — stable contract; implementations in arch-specific crates.

#![no_std]

use core::fmt::Debug;
use axiom_x_math::scheduler_math::{ProcessMeasurement, SchedulerDecision};

// ============================================================================
// Type Definitions (Architecture-Agnostic)
// ============================================================================

/// Virtual address (architecture-agnostic)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn as_u64(self) -> u64 { self.0 }
}

impl core::ops::Add<u64> for VirtAddr {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl core::ops::AddAssign<u64> for VirtAddr {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl core::ops::Sub<u64> for VirtAddr {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl core::ops::SubAssign<u64> for VirtAddr {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

/// Physical address (architecture-agnostic)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self { Self(addr) }
    pub const fn as_u64(self) -> u64 { self.0 }
}

impl core::ops::Add<u64> for PhysAddr {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl core::ops::AddAssign<u64> for PhysAddr {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl core::ops::Sub<u64> for PhysAddr {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl core::ops::SubAssign<u64> for PhysAddr {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

/// Physical frame (architecture-agnostic)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysFrame<S> {
    addr: PhysAddr,
    _marker: core::marker::PhantomData<S>,
}

impl<S> PhysFrame<S> {
    pub const fn containing_address(addr: PhysAddr) -> Self {
        Self { addr, _marker: core::marker::PhantomData }
    }
    pub fn start_address(&self) -> PhysAddr { self.addr }
}

/// Page size marker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4KiB,
    Size2MiB,
    Size1GiB,
}

/// Page table flags (architecture-agnostic subset)
bitflags::bitflags! {
    pub struct PageTableFlags: u64 {
        const PRESENT = 1 << 0;
        const WRITABLE = 1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE = 1 << 4;
        const ACCESSED = 1 << 5;
        const DIRTY = 1 << 6;
        const HUGE_PAGE = 1 << 7;
        const GLOBAL = 1 << 8;
        const NO_EXECUTE = 1 << 63;
    }
}

/// CPU context for context switching (architecture-agnostic layout)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CpuContext {
    // Architecture-specific register state
    // Each arch implementation defines its own layout
    pub data: [u64; 32], // Sufficient for x86_64, ARM64, RISC-V
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub flags: u64,
    pub page_table_root: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            data: [0; 32],
            instruction_pointer: 0,
            stack_pointer: 0,
            flags: 0x202,
            page_table_root: 0,
        }
    }
}

/// Process state (architecture-agnostic)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessState {
    New = 0,
    Runnable = 1,
    Running = 2,
    Blocked = 3,
    Terminated = 4,
}

// ============================================================================
// Hardware Abstraction Traits
// ============================================================================

/// Interrupt controller abstraction
pub trait InterruptController: Send + Sync + Debug {
    /// Architecture-specific handler type
    type Handler: Send + Sync;

    /// Enable interrupts globally
    fn enable(&mut self);

    /// Disable interrupts globally
    fn disable(&mut self);

    /// Register an interrupt handler for a vector
    fn register_handler(&mut self, vector: u8, handler: Self::Handler);

    /// Set interrupt handler for timer
    fn set_timer_handler(&mut self, handler: Self::Handler);

    /// End of interrupt notification
    fn end_of_interrupt(&mut self, vector: u8);

    /// Get current interrupt vector (if in handler)
    fn current_vector(&self) -> Option<u8>;
}

/// Page table manager abstraction
pub trait PageTableManager: Send + Sync + Debug {
    /// Map a virtual page to a physical frame
    fn map(&mut self, virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags, size: PageSize) -> Result<(), MapError>;

    /// Unmap a virtual page
    fn unmap(&mut self, virt: VirtAddr, size: PageSize) -> Result<(), UnmapError>;

    /// Switch to a different address space (load page table root)
    fn switch_address_space(&mut self, root: PhysAddr) -> Result<(), SwitchError>;

    /// Get current page table root
    fn current_root(&self) -> PhysAddr;

    /// Allocate a new page table (returns physical address of root)
    fn allocate_page_table(&mut self) -> Result<PhysAddr, AllocError>;

    /// Map kernel memory (identity or higher-half)
    fn map_kernel_range(&mut self, virt_start: VirtAddr, phys_start: PhysAddr, size: u64, flags: PageTableFlags) -> Result<(), MapError>;
}

/// Page table errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    OutOfMemory,
    InvalidAddress,
    AlreadyMapped,
    AlignmentError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapError {
    NotMapped,
    InvalidAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchError {
    InvalidRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    OutOfMemory,
}

/// Context switch abstraction
pub trait ContextSwitch: Send + Sync + Debug {
    /// Save current CPU context to the provided structure
    fn save_context(&mut self, ctx: &mut CpuContext);

    /// Restore CPU context and jump to it (never returns)
    fn restore_context(&mut self, ctx: &CpuContext) -> !;

    /// Create initial context for a new process/thread
    fn create_context(
        &self,
        entry_point: u64,
        stack_top: u64,
        page_table_root: u64,
        is_user: bool,
    ) -> CpuContext;
}

/// Timer source abstraction
pub trait TimerSource: Send + Sync + Debug {
    /// Initialize timer with given frequency (Hz)
    fn init(&mut self, frequency_hz: u64);

    /// Get current timer value (ticks)
    fn current_tick(&self) -> u64;

    /// Get timer frequency (Hz)
    fn frequency(&self) -> u64;

    /// Set next deadline (in ticks from now)
    fn set_deadline(&mut self, ticks: u64);

    /// Enable timer interrupts
    fn enable_interrupt(&mut self);

    /// Disable timer interrupts
    fn disable_interrupt(&mut self);

    /// Acknowledge timer interrupt
    fn acknowledge(&mut self);
}

/// CPU feature detection
pub trait CpuFeatures: Send + Sync + Debug {
    /// Vendor string (e.g., "GenuineIntel", "AuthenticAMD")
    fn vendor(&self) -> &str;

    /// Check if long mode / 64-bit is supported
    fn has_long_mode(&self) -> bool;

    /// Check for SSE/SSE2/SSE3/SSSE3/SSE4.1/SSE4.2
    fn has_sse(&self) -> bool;
    fn has_sse2(&self) -> bool;
    fn has_sse3(&self) -> bool;
    fn has_ssse3(&self) -> bool;
    fn has_sse41(&self) -> bool;
    fn has_sse42(&self) -> bool;

    /// Check for AVX/AVX2
    fn has_avx(&self) -> bool;
    fn has_avx2(&self) -> bool;

    /// Check for FMA
    fn has_fma(&self) -> bool;

    /// Check for RDRAND/RDSEED
    fn has_rdrand(&self) -> bool;
    fn has_rdseed(&self) -> bool;

    /// Check for FSGSBASE
    fn has_fsgsbase(&self) -> bool;

    /// Check for CLFLUSHOPT/CLWB
    fn has_clflushopt(&self) -> bool;
    fn has_clwb(&self) -> bool;

    /// Number of logical processors
    fn logical_processor_count(&self) -> usize;
}

/// Early console for boot-time logging
pub trait EarlyConsole: Send + Sync + Debug {
    /// Write a byte
    fn putc(&mut self, c: u8);

    /// Write a string
    fn puts(&mut self, s: &str) {
        for c in s.bytes() {
            self.putc(c);
        }
    }

    /// Flush output
    fn flush(&mut self);
}

/// Frame allocator for physical memory (used by page table manager)
pub trait FrameAllocator: Send + Sync + Debug {
    /// Allocate a physical frame
    fn alloc(&mut self) -> Option<PhysAddr>;

    /// Deallocate a physical frame
    fn dealloc(&mut self, addr: PhysAddr);

    /// Get total available frames
    fn total_frames(&self) -> usize;

    /// Get free frames count
    fn free_frames(&self) -> usize;
}

// ============================================================================
// Kernel Hardware Abstraction (Aggregate)
// ============================================================================

/// Complete hardware abstraction for the kernel
pub trait KernelHardware: Send + Sync + Debug {
    type InterruptController: InterruptController;
    type PageTableManager: PageTableManager;
    type ContextSwitch: ContextSwitch;
    type TimerSource: TimerSource;
    type CpuFeatures: CpuFeatures;
    type EarlyConsole: EarlyConsole;
    type FrameAllocator: FrameAllocator;

    fn interrupt_controller(&mut self) -> &mut Self::InterruptController;
    fn page_table_manager(&mut self) -> &mut Self::PageTableManager;
    fn context_switch(&mut self) -> &mut Self::ContextSwitch;
    fn timer_source(&mut self) -> &mut Self::TimerSource;
    fn cpu_features(&self) -> &Self::CpuFeatures;
    fn early_console(&mut self) -> &mut Self::EarlyConsole;
    fn frame_allocator(&mut self) -> &mut Self::FrameAllocator;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virt_addr() {
        let addr = VirtAddr::new(0xFFFF_8000_0000_0000);
        assert_eq!(addr.as_u64(), 0xFFFF_8000_0000_0000);
    }

    #[test]
    fn test_phys_addr() {
        let addr = PhysAddr::new(0x100000);
        assert_eq!(addr.as_u64(), 0x100000);
    }

    #[test]
    fn test_page_table_flags() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        assert!(flags.contains(PageTableFlags::PRESENT));
        assert!(flags.contains(PageTableFlags::WRITABLE));
    }

    #[test]
    fn test_cpu_context_default() {
        let ctx = CpuContext::default();
        assert_eq!(ctx.flags, 0x202);
    }
}