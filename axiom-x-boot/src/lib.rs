//! Axiom-X Boot Path for x86_64 (Multiboot2)
//!
//! Boot sequence:
//! 1. Multiboot2 entry point (assembly)
//! 2. Parse boot info (memory map, modules, command line)
//! 3. Initialize early page tables (identity map low memory)
//! 4. Set up kernel heap (bump allocator)
//! 5. Initialize serial console for early logging
//! 6. Initialize CPU features, IDT, scheduler
//! 7. Create init process and start scheduling
//! 8. Initialize movie subsystem (embedded boot movie)
//!
//! Status: `skeleton` — boot path structure defined; multiboot2 assembly entry TODO.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use core::arch::asm;
use core::ptr;
use heapless::Vec;
use multiboot2::{BootInformation, BootInformationHeader, FramebufferType};
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::Cr3,
    registers::model_specific::{Efer, EferFlags},
    structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB},
};
use axiom_x_arch::inb;
use axiom_x_arch::outb;
use axiom_x_arch::process::ProcessTable;
use axiom_x_arch::interrupts::{init_scheduler, set_process_table};
use axiom_x_math::memory_algebra::{FrameAllocator as MathFrameAllocator, RegionType, RegionFlags};
use alloc::boxed::Box;

/// Formatted serial output that never allocates (safe before the heap exists).
/// Written with interrupts off so a preempted thread cannot interleave its
/// half-written line with another thread's output.
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::KernelSerial, || {
            let _ = write!($crate::SerialWriter, $($arg)*);
        });
    }};
}

// Ring-3 programs (declared after `serial_print!` so it can use the macro).
#[cfg(feature = "freestanding")]
mod user;
#[cfg(feature = "freestanding")]
mod elf;

// Movie subsystem
pub mod movie;
pub mod elf_loader;

// ============================================================================
// Boot Information Structures
// ============================================================================

/// Parsed boot information passed to kernel
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Physical memory map from bootloader
    pub memory_map: Vec<MemoryRegion, 128>,
    /// Kernel physical load address
    pub kernel_phys_start: u64,
    /// Kernel physical end address
    pub kernel_phys_end: u64,
    /// Kernel virtual base (higher half)
    pub kernel_virt_base: u64,
    /// Command line string
    pub cmdline: Vec<u8, 256>,
    /// Bootloader name
    pub bootloader_name: Vec<u8, 64>,
    /// Modules loaded by bootloader
    pub modules: Vec<ModuleInfo, 16>,
    /// Framebuffer info (if available)
    pub framebuffer: Option<FramebufferInfo>,
}

/// Memory region from bootloader
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub region_type: u32, // multiboot2 memory type
}

/// Modules handed over by the bootloader, kept for init.
static mut BOOT_MODULES: Vec<ModuleInfo, 16> = Vec::new();
/// Kernel command line from the bootloader, kept for init.
static mut BOOT_CMDLINE: Vec<u8, 256> = Vec::new();

/// The kernel command line (empty if none / not UTF-8).
pub fn boot_cmdline() -> &'static str {
    core::str::from_utf8(unsafe { &*core::ptr::addr_of!(BOOT_CMDLINE) }).unwrap_or("")
}

/// Modules handed over by the bootloader (physical ranges + names).
pub fn boot_modules() -> &'static [ModuleInfo] {
    unsafe { &*core::ptr::addr_of!(BOOT_MODULES) }
}

impl ModuleInfo {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len.min(64)]).unwrap_or("?")
    }
    /// The module's bytes (physical memory, reached via the identity map).
    pub fn bytes(&self) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(self.start as *const u8, (self.end - self.start) as usize) }
    }
}

/// Module loaded by bootloader
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    pub start: u64,
    pub end: u64,
    pub name: [u8; 64],
    pub name_len: usize,
}

/// Framebuffer information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferInfo {
    pub addr: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub type_: u8,
}

// ============================================================================
// Early Page Table Setup
// ============================================================================

/// Kernel page table root (PML4)
static mut KERNEL_PML4: Option<PhysFrame<Size4KiB>> = None;

/// Virtual to physical offset (higher half mapping)
const VIRT_PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Region for per-thread kernel stacks (PML4 slot 256, whose lower-level
/// tables every address space shares, so stacks mapped later are visible
/// everywhere). Each slot is an unmapped guard page followed by the stack.
const KERNEL_STACK_REGION: u64 = 0xFFFF_8000_0800_0000;
const KERNEL_STACK_REGION_END: u64 = 0xFFFF_8000_1000_0000;
/// 64 KiB per thread: the trap-frame scheduler and syscall paths are small;
/// overflow hits the guard page and faults instead of corrupting memory.
pub const KERNEL_STACK_SIZE: u64 = 64 * 1024;
static mut NEXT_KERNEL_STACK: u64 = KERNEL_STACK_REGION;
/// Guard-page addresses of freed stack slots, reused before bumping.
static mut FREE_KERNEL_STACK_SLOTS: Vec<u64, 64> = Vec::new();

/// Identity map the first 1 GiB
const IDENTITY_MAP_LIMIT: u64 = 1 << 30; // 1 GiB

/// Initialize early page tables
pub unsafe fn init_early_page_tables(
    boot_info: &BootInfo,
) -> PhysFrame<Size4KiB> {
    // Allocate PML4 frame
    let pml4_frame = alloc_boot_frame().expect("failed to allocate PML4 frame");
    let pml4 = pml4_frame.start_address().as_u64() as *mut PageTable;
    ptr::write_bytes(pml4, 0, 1);

    // Identity map first 1 GiB (2 MiB huge pages)
    for i in 0..(IDENTITY_MAP_LIMIT / (2 * 1024 * 1024)) {
        let virt = i * 2 * 1024 * 1024;
        let phys = virt;
        map_2mib_page(pml4, virt, phys, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    }

    // Higher-half map kernel (direct mapping)
    let kernel_virt = VIRT_PHYS_OFFSET;
    for region in &boot_info.memory_map {
        if region.region_type == 1 { // Available RAM
            let start = region.base;
            let end = start + region.length;
            let kernel_end = boot_info.kernel_phys_end;

            if start < kernel_end && end > boot_info.kernel_phys_start {
                // Map kernel region
                let map_start = start.max(boot_info.kernel_phys_start);
                let map_end = end.min(kernel_end);
                for addr in (map_start..map_end).step_by(4096) {
                    let virt = kernel_virt + addr;
                    map_4kib_page(pml4, virt, addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
                }
            }
        }
    }


    // NO_EXECUTE (bit 63) is a reserved bit unless EFER.NXE is set; the
    // trampoline only sets EFER.LME, so enable NXE before using these tables.
    Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));

    // Load CR3
    Cr3::write(pml4_frame, Cr3::read().1);

    KERNEL_PML4 = Some(pml4_frame);
    pml4_frame
}

/// Map a 2 MiB huge page
unsafe fn map_2mib_page(pml4: *mut PageTable, virt: u64, phys: u64, flags: PageTableFlags) {
    let pml4_idx = (virt >> 39) & 0x1FF;
    let pdpt_idx = (virt >> 30) & 0x1FF;
    let pd_idx = (virt >> 21) & 0x1FF;

    // Get or create PDPT
    let pdpt = get_or_create_table(pml4, pml4_idx, false);
    // Get or create PD
    let pd = get_or_create_table(pdpt, pdpt_idx, false);
    // Map 2 MiB page in PD
    let pd = unsafe { &mut *pd };
    pd[pd_idx as usize].set_addr(PhysAddr::new(phys), flags | PageTableFlags::HUGE_PAGE);
}

/// Map a 4 KiB page
unsafe fn map_4kib_page(pml4: *mut PageTable, virt: u64, phys: u64, flags: PageTableFlags) {
    let pml4_idx = (virt >> 39) & 0x1FF;
    let pdpt_idx = (virt >> 30) & 0x1FF;
    let pd_idx = (virt >> 21) & 0x1FF;
    let pt_idx = (virt >> 12) & 0x1FF;

    // x86 checks U/S at every level: a user leaf needs USER on its parents.
    let user = flags.contains(PageTableFlags::USER_ACCESSIBLE);
    let pdpt = get_or_create_table(pml4, pml4_idx, user);
    let pd = get_or_create_table(pdpt, pdpt_idx, user);
    let pt = get_or_create_table(pd, pd_idx, user);
    let pt = unsafe { &mut *pt };
    pt[pt_idx as usize].set_addr(PhysAddr::new(phys), flags);
}

/// Get or create next-level page table. With `user`, the entry also gets
/// USER_ACCESSIBLE (leaf permissions still decide what ring 3 can touch).
unsafe fn get_or_create_table(table: *mut PageTable, index: u64, user: bool) -> *mut PageTable {
    let table = unsafe { &mut *table };
    let entry = &mut table[index as usize];
    if entry.is_unused() {
        let frame = alloc_boot_frame().expect("out of memory for page table");
        entry.set_addr(frame.start_address(), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        ptr::write_bytes(frame.start_address().as_u64() as *mut PageTable, 0, 1);
    }
    assert!(
        !entry.flags().contains(PageTableFlags::HUGE_PAGE),
        "cannot map a 4 KiB page inside a huge-page mapping"
    );
    if user {
        entry.set_flags(entry.flags() | PageTableFlags::USER_ACCESSIBLE);
    }
    let phys = entry.addr().as_u64();
    phys as *mut PageTable
}

/// Allocate and map a kernel stack below an unmapped guard page; returns
/// its top. Stacks are never freed (bump allocation, like frames).
pub fn alloc_kernel_stack() -> VirtAddr {
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::Allocator, || unsafe { alloc_kernel_stack_inner() })
}

unsafe fn alloc_kernel_stack_inner() -> VirtAddr {
    {
        let slots = &mut *core::ptr::addr_of_mut!(FREE_KERNEL_STACK_SLOTS);
        let guard = match slots.pop() {
            Some(g) => g,
            None => {
                let g = NEXT_KERNEL_STACK;
                NEXT_KERNEL_STACK = g + 4096 + KERNEL_STACK_SIZE;
                g
            }
        };
        let base = guard + 4096;
        let top = base + KERNEL_STACK_SIZE;
        assert!(top <= KERNEL_STACK_REGION_END, "kernel stack region exhausted");
        let pml4 = KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64() as *mut PageTable;
        for va in (base..top).step_by(4096) {
            let phys = alloc_boot_frame().expect("out of memory for kernel stack");
            ptr::write_bytes(phys.start_address().as_u64() as *mut u8, 0, 4096);
            map_4kib_page(pml4, va, phys.start_address().as_u64(),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE);
        }
        VirtAddr::new(top)
    }
}

/// Unmap one 4 KiB kernel page from the shared kernel tables and return its
/// frame. Every address space shares these tables; other CR3s flush the
/// stale TLB entry on their next load (single CPU).
/// Physical address of the kernel's own PML4 root.
pub fn kernel_pml4_root() -> u64 {
    unsafe { KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64() }
}

pub(crate) unsafe fn unmap_kernel_page(virt: u64) -> Option<PhysFrame<Size4KiB>> {
    let mut table = KERNEL_PML4?.start_address().as_u64() as *mut PageTable;
    for shift in [39u64, 30, 21] {
        let entry = &(&*table)[((virt >> shift) & 0x1FF) as usize];
        if entry.is_unused() || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }
        table = entry.addr().as_u64() as *mut PageTable;
    }
    let entry = &mut (&mut *table)[((virt >> 12) & 0x1FF) as usize];
    if entry.is_unused() {
        return None;
    }
    let frame = PhysFrame::containing_address(entry.addr());
    entry.set_unused();
    x86_64::instructions::tlb::flush(VirtAddr::new(virt));
    Some(frame)
}

/// Free a stack from `alloc_kernel_stack` (by its top) and recycle its slot.
/// It must not be the stack currently in use.
pub fn free_kernel_stack(top: VirtAddr) -> u64 {
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::Allocator, || unsafe {
        let base = top.as_u64() - KERNEL_STACK_SIZE;
        let mut freed = 0;
        for va in (base..top.as_u64()).step_by(4096) {
            if let Some(f) = unmap_kernel_page(va) {
                free_frame(f);
                freed += 1;
            }
        }
        let slots = &mut *core::ptr::addr_of_mut!(FREE_KERNEL_STACK_SLOTS);
        let _ = slots.push(base - 4096);
        freed
    })
}

/// Free everything private to an address space from `new_address_space`:
/// the user slot's page tables and the frames they map, then the PML4.
/// The shared kernel half is not touched. It must not be the active CR3.
pub fn free_address_space(root: PhysFrame<Size4KiB>) -> u64 {
    unsafe fn free_level(table: u64, level: u8) -> u64 {
        let mut freed = 0;
        for entry in (&*(table as *const PageTable)).iter() {
            if entry.is_unused() {
                continue;
            }
            let frame = PhysFrame::containing_address(entry.addr());
            if level > 1 && !entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                freed += free_level(frame.start_address().as_u64(), level - 1);
            }
            free_frame(frame);
            freed += 1;
        }
        freed
    }
    assert!(Cr3::read().0 != root, "freeing the active address space");
    unsafe {
        let pml4 = &mut *(root.start_address().as_u64() as *mut PageTable);
        let mut freed = 0;
        let user = &pml4[USER_PML4_SLOT];
        if !user.is_unused() {
            let pdpt = PhysFrame::<Size4KiB>::containing_address(user.addr());
            // PDPT (level 3) -> PD (2) -> PT (1) -> leaf frames
            freed += free_level(pdpt.start_address().as_u64(), 3);
            free_frame(pdpt);
            freed += 1;
        }
        free_frame(root);
        freed + 1
    }
}

/// PML4 slot reserved for per-process user mappings.
pub const USER_PML4_SLOT: usize = 1;

/// New address space: shares every kernel PML4 entry (the supervisor-only
/// identity map and the higher half) and gets a private, empty user slot.
pub fn new_address_space() -> PhysFrame<Size4KiB> {
    unsafe {
        let frame = alloc_boot_frame().expect("out of memory for PML4");
        let new = frame.start_address().as_u64() as *mut PageTable;
        let kernel = KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64() as *const PageTable;
        ptr::copy_nonoverlapping(kernel, new, 1);
        (&mut *new)[USER_PML4_SLOT].set_unused();
        frame
    }
}

/// Map one 4 KiB page into the address space rooted at `root`.
pub fn map_page_in(root: u64, virt: u64, phys: u64, flags: PageTableFlags) {
    unsafe { map_4kib_page(root as *mut PageTable, virt, phys, flags) }
}

/// Boot-time frame allocator (bump allocator from available memory)
static mut BOOT_FRAME_ALLOCATOR: Option<BootFrameAllocator> = None;

/// Physical frame allocator: bump allocation from one usable region, plus a
/// free list of returned frames (each free frame stores the next link in its
/// first 8 bytes, reached through the identity map).
struct BootFrameAllocator {
    start: u64,
    current: u64,
    end: u64,
    free_head: u64,
    allocated: u64,
    freed: u64,
}

/// Frames must be reachable through the boot identity map (first 1 GiB):
/// page tables and the free list are accessed by physical address.
const IDENTITY_MAPPED_END: u64 = 1 << 30;

impl BootFrameAllocator {
    fn new(start: u64, end: u64) -> Self {
        Self { start, current: start, end: end.min(IDENTITY_MAPPED_END), free_head: 0, allocated: 0, freed: 0 }
    }

    /// Walk the free chain; false if it is longer than `freed` (cycle or
    /// a node written twice) or a node is unaligned/out of range. Used
    /// inside alloc() so the first allocation after a corrupting write
    /// panics instead of handing out a bogus frame.
    fn chain_ok(&self) -> bool {
        let mut head = self.free_head;
        let mut nodes = 0u64;
        while head != 0 {
            nodes += 1;
            if nodes > self.freed || head & 0xFFF != 0 || head >= self.end || head < self.start {
                return false;
            }
            head = unsafe { ptr::read(head as *const u64) };
        }
        true
    }

    fn alloc(&mut self) -> Option<PhysFrame<Size4KiB>> {
        assert!(self.chain_ok(), "free list corrupt before alloc");
        let addr = if self.free_head != 0 {
            let addr = self.free_head;
            self.free_head = unsafe { ptr::read(addr as *const u64) };
            addr
        } else {
            // The frame at `current` must be fully inside [start, end).
            if self.current + 4096 > self.end {
                return None;
            }
            let addr = self.current;
            self.current += 4096;
            addr
        };
        self.allocated += 1;
        Some(PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    fn free(&mut self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        // Debug: catch a double-free at the moment it happens — if `addr`
        // is already linked, the list walk finds it. The cap bounds the
        // walk if the chain is already corrupt.
        // A frame outside the allocator's region was never handed out —
        // freeing it is always a bug (e.g. a frame shared from a module or
        // a stale pointer misread as an allocation).
        assert!(
            addr >= self.start && addr < self.end,
            "frame {:#x} freed but outside allocator range [{:#x}, {:#x})",
            addr, self.start, self.end
        );
        let mut head = self.free_head;
        let mut walked = 0u64;
        while head != 0 && walked <= self.freed {
            assert!(head != addr, "frame {:#x} freed while already on the free list", addr);
            head = unsafe { ptr::read(head as *const u64) };
            walked += 1;
        }
        unsafe { ptr::write(addr as *mut u64, self.free_head) };
        self.free_head = addr;
        self.freed += 1;
    }
}

/// Walk the free list through the identity map. Returns nodes walked and
/// whether the chain is sane: a walk longer than `freed` means a cycle or
/// a frame recorded twice (double-free); unaligned/out-of-region nodes
/// mean corruption.
pub(crate) fn free_list_scan() -> (u64, bool) {
    unsafe {
        let a = BOOT_FRAME_ALLOCATOR.as_ref().expect("frame allocator");
        let mut head = a.free_head;
        let mut nodes = 0u64;
        while head != 0 {
            nodes += 1;
            if nodes > a.freed || head & 0xFFF != 0 || head >= a.end {
                return (nodes, false);
            }
            head = ptr::read(head as *const u64);
        }
        (nodes, true)
    }
}

/// Return a frame to the allocator. The caller guarantees nothing maps or
/// uses it any more.
pub unsafe fn free_frame(frame: PhysFrame<Size4KiB>) {
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::Allocator, || {
        BOOT_FRAME_ALLOCATOR.as_mut().expect("frame allocator").free(frame)
    });
}

/// Frames currently allocated (allocated minus freed).
pub fn frames_in_use() -> u64 {
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::Allocator, || unsafe {
        BOOT_FRAME_ALLOCATOR.as_ref().map_or(0, |a| a.allocated - a.freed)
    })
}

unsafe fn init_boot_allocator(boot_info: &BootInfo) {
    // Never hand out the kernel image or the modules GRUB loaded after it.
    let reserved_end = boot_info
        .modules
        .iter()
        .map(|m| m.end)
        .fold(boot_info.kernel_phys_end, u64::max);
    // Take the first usable region that has room, clamping the start past
    // the kernel image (the loader puts the image at 0x100000, inside the
    // first E820/GRUB usable region, so we can't require region.base >= end).
    for region in &boot_info.memory_map {
        if region.region_type != 1 {
            continue;
        }
        let region_end = region.base + region.length;
        let alloc_start = region.base.max(reserved_end);
        let aligned = (alloc_start + 4095) & !4095;
        
        // Check if we have at least 1 MiB of space for boot allocations
        const MIN_BOOT_ALLOC_SIZE: u64 = 1024 * 1024; // 1 MiB
        if aligned + MIN_BOOT_ALLOC_SIZE <= region_end {
            BOOT_FRAME_ALLOCATOR = Some(BootFrameAllocator::new(aligned, region_end));
            return;
        }
    }
    
    // Fallback: try to find ANY region with at least 64 KiB for minimal boot
    for region in &boot_info.memory_map {
        if region.region_type != 1 {
            continue;
        }
        let region_end = region.base + region.length;
        let alloc_start = region.base.max(reserved_end);
        let aligned = (alloc_start + 4095) & !4095;
        
        const MIN_BOOT_ALLOC_SIZE_FALLBACK: u64 = 64 * 1024; // 64 KiB
        if aligned + MIN_BOOT_ALLOC_SIZE_FALLBACK <= region_end {
            BOOT_FRAME_ALLOCATOR = Some(BootFrameAllocator::new(aligned, region_end));
            return;
        }
    }
    
    panic!("No available memory for boot allocator");
}

pub unsafe fn alloc_boot_frame() -> Option<PhysFrame<Size4KiB>> {
    // Interrupts off: init allocates while user threads run and fault/exit
    // paths may free.
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::Allocator, || BOOT_FRAME_ALLOCATOR.as_mut()?.alloc())
}

// ============================================================================
// Early Heap (Bump Allocator)
// ============================================================================

/// Kernel early heap
static mut EARLY_HEAP: Option<EarlyHeap> = None;

struct EarlyHeap {
    start: u64,
    end: u64,
    current: u64,
}

impl EarlyHeap {
    fn new(start: u64, size: u64) -> Self {
        Self { start, end: start + size, current: start }
    }

    fn alloc(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let aligned = (self.current + (align - 1) as u64) & !(align - 1) as u64;
        let next = aligned + size as u64;
        if next > self.end {
            return None;
        }
        self.current = next;
        Some(aligned as *mut u8)
    }
}

/// Initialize early heap (1 MiB at fixed virtual address)
unsafe fn init_early_heap() {
    const HEAP_START: u64 = 0xFFFF_8000_0100_0000;
    const HEAP_SIZE: u64 = 1024 * 1024; // 1 MiB

    // Map heap pages
    let pml4 = KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64() as *mut PageTable;
    for i in 0..(HEAP_SIZE / 4096) {
        let phys = alloc_boot_frame().expect("out of memory for heap").start_address().as_u64();
        let virt = HEAP_START + i * 4096;
        map_4kib_page(pml4, virt, phys, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE);
    }

    EARLY_HEAP = Some(EarlyHeap::new(HEAP_START, HEAP_SIZE));
}

/// Allocate from early heap
pub fn early_alloc(size: usize, align: usize) -> Option<*mut u8> {
    unsafe { EARLY_HEAP.as_mut()?.alloc(size, align) }
}

// ============================================================================
// Serial Console (Early Logging)
// ============================================================================

/// COM1 port
const COM1: u16 = 0x3F8;

/// Initialize serial port for early logging
pub fn init_serial() {
    outb(COM1 + 1, 0x00); // Disable interrupts
    outb(COM1 + 3, 0x80); // Enable DLAB
    // Divisor 1 = 115200 baud (1.8432 MHz UART clock / 16). It was 0x0C
    // (9600 baud): emulators model transmit time, so each character took
    // ~1 ms, and console lines (written with interrupts off) cost the PIT
    // many lost ticks.
    outb(COM1 + 0, 0x01); // Divisor low byte
    outb(COM1 + 1, 0x00); // Divisor high byte
    outb(COM1 + 3, 0x03); // 8N1, disable DLAB
    // COM2: the governed egress channel (AX_EGRESS talks to the host proxy).
    outb(0x2f8 + 1, 0x00);
    outb(0x2f8 + 3, 0x80);
    outb(0x2f8 + 0, 0x01);
    outb(0x2f8 + 1, 0x00);
    outb(0x2f8 + 3, 0x03);
    // Keep any byte already received (typed or piped in before boot).
    while inb(COM1 + 5) & 0x01 != 0 {
        axiom_x_arch::console::push_input(inb(COM1));
    }
    // The FIFO control register is deliberately left alone: changing the
    // FIFO-enable bit flushes the receive FIFO (16550 behaviour, and QEMU's),
    // which raced with input arriving during boot and dropped bytes. Without
    // the FIFO, receive is one byte at a time, drained by the IRQ4 handler;
    // transmit already waits for the holding register per byte.
    outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
}

/// Write byte to serial
pub fn serial_putc(c: u8) {
    // Buffered once the scheduler runs (see `console::serial_out`); also
    // mirrored to the VGA text screen.
    axiom_x_arch::console::serial_out(c);
}

/// Write string to serial
pub fn serial_puts(s: &str) {
    // Atomic per call under preemption (see `serial_print!`).
    axiom_x_arch::latency::irq_off(axiom_x_arch::latency::Site::KernelSerial, || {
        for c in s.bytes() {
            serial_putc(c);
        }
    });
}

// ============================================================================
// Multiboot2 Parsing
// ============================================================================

/// Parse Multiboot2 boot information
pub fn parse_multiboot2(mbi_addr: u64) -> BootInfo {
    let mbi = unsafe { BootInformation::load(mbi_addr as *const BootInformationHeader) }.expect("Invalid multiboot2 header");

    let mut memory_map = Vec::new();
    for area in mbi.memory_map_tag().expect("No memory map").memory_areas() {
        memory_map.push(MemoryRegion {
            base: area.start_address(),
            length: area.size(),
            region_type: u32::from(area.typ()),
        }).ok();
    }

    let mut cmdline = Vec::new();
    if let Some(tag) = mbi.command_line_tag() {
        for c in tag.cmdline().unwrap_or("").bytes() {
            cmdline.push(c).ok();
        }
    }

    let mut bootloader_name = Vec::new();
    if let Some(tag) = mbi.boot_loader_name_tag() {
        for c in tag.name().unwrap_or("").bytes() {
            bootloader_name.push(c).ok();
        }
    }

    let mut modules = Vec::new();
    for module in mbi.module_tags() {
        let mut name = [0u8; 64];
        let module_name = module.cmdline().unwrap_or("");
        for (i, c) in module_name.bytes().enumerate() {
            if i < 64 { name[i] = c; }
        }
        modules.push(ModuleInfo {
            start: module.start_address() as u64,
            end: module.end_address() as u64,
            name,
            name_len: module_name.len(),
        }).ok();
    }

    let mut framebuffer = None;
    if let Some(Ok(tag)) = mbi.framebuffer_tag() {
        framebuffer = Some(FramebufferInfo {
            addr: tag.address(),
            pitch: tag.pitch(),
            width: tag.width(),
            height: tag.height(),
            bpp: tag.bpp(),
            type_: tag.buffer_type().map(|t| match t {
                FramebufferType::Indexed { .. } => 0,
                FramebufferType::RGB { .. } => 1,
                FramebufferType::Text => 2,
            }).unwrap_or(0),
        });
    }

    // Kernel addresses from multiboot2 (ELF sections tag). The section tag
    // reports sh_addr (VMA); the kernel is linked higher-half, so convert
    // VMA back to the physical load address before deriving the kernel's
    // physical range for the frame allocator and early page tables.
    // The ELF sections tag also lists non-loaded sections (.debug_*,
    // .symtab) with sh_addr 0, which corrupts a min/max scan. The linker
    // script's bounds cover exactly the loaded image, so use them.
    let (kernel_phys_start, kernel_phys_end) = kernel_phys_bounds();

    BootInfo {
        memory_map,
        kernel_phys_start,
        kernel_phys_end,
        kernel_virt_base: VIRT_PHYS_OFFSET,
        cmdline,
        bootloader_name,
        modules,
        framebuffer,
    }
}

// ============================================================================
// Multiboot1 Parsing (QEMU -kernel / GRUB legacy "multiboot")
// ============================================================================

/// Linker-provided bounds of the kernel image (higher-half virtual addresses).
#[cfg(feature = "freestanding")]
extern "C" {
    static __kernel_phys_start: u8;
    static __kernel_virt_end: u8;
}

unsafe fn rd8(a: u64) -> u8 {
    core::ptr::read(a as *const u8)
}

unsafe fn rd32(a: u64) -> u32 {
    core::ptr::read(a as *const u32)
}

unsafe fn rd64(a: u64) -> u64 {
    core::ptr::read(a as *const u64)
}

/// Read a NUL-terminated string into a fixed-capacity vector.
unsafe fn read_cstring<const N: usize>(addr: u64) -> Vec<u8, N> {
    let mut v: Vec<u8, N> = Vec::new();
    if addr == 0 {
        return v;
    }
    for i in 0..N {
        let b = core::ptr::read((addr as *const u8).add(i));
        if b == 0 {
            break;
        }
        v.push(b).ok();
    }
    v
}

/// Physical bounds of the kernel image, for the boot frame allocator.
fn kernel_phys_bounds() -> (u64, u64) {
    #[cfg(feature = "freestanding")]
    {
        let start = unsafe { core::ptr::addr_of!(__kernel_phys_start) as u64 };
        let virt_end = unsafe { core::ptr::addr_of!(__kernel_virt_end) as u64 };
        (start, virt_end - VIRT_PHYS_OFFSET)
    }
    #[cfg(not(feature = "freestanding"))]
    {
        (0x100000, 0x200000) // Host-test fallback
    }
}

/// Parse a Multiboot1 info structure (multiboot spec v1.6, §3.3).
/// The Multiboot1 structure is a flat struct; the memory map is a series of
/// E820-style entries: u32 size, u64 base, u64 length, u32 type.
pub fn parse_multiboot1(mbi_addr: u64) -> BootInfo {
    unsafe {
        let flags = rd32(mbi_addr);

        let mut memory_map = Vec::new();
        if flags & (1 << 6) != 0 {
            let mmap_addr = rd32(mbi_addr + 48) as u64;
            let mmap_length = rd32(mbi_addr + 44) as u64;
            let mut off = 0u64;
            while off + 24 <= mmap_length {
                let entry = mmap_addr + off;
                let size = rd32(entry) as u64;
                if size == 0 {
                    break;
                }
                let base = (rd32(entry + 4) as u64) | ((rd32(entry + 8) as u64) << 32);
                let len = (rd32(entry + 12) as u64) | ((rd32(entry + 16) as u64) << 32);
                let typ = rd32(entry + 20);
                memory_map
                    .push(MemoryRegion { base, length: len, region_type: typ })
                    .ok();
                off += size + 4;
            }
        }

        let mut cmdline: Vec<u8, 256> = Vec::new();
        if flags & (1 << 2) != 0 {
            cmdline = read_cstring(rd32(mbi_addr + 16) as u64);
        }

        let mut bootloader_name: Vec<u8, 64> = Vec::new();
        if flags & (1 << 9) != 0 {
            bootloader_name = read_cstring(rd32(mbi_addr + 64) as u64);
        }

        let mut modules = Vec::new();
        if flags & (1 << 3) != 0 {
            let mods_count = rd32(mbi_addr + 20);
            let mods_addr = rd32(mbi_addr + 24) as u64;
            for i in 0..mods_count as u64 {
                let m = mods_addr + i * 16;
                let start = rd32(m) as u64;
                let end = rd32(m + 4) as u64;
                let string_addr = rd32(m + 8) as u64;
                let name_vec = read_cstring::<64>(string_addr);
                let mut name = [0u8; 64];
                for (j, b) in name_vec.iter().enumerate() {
                    name[j] = *b;
                }
                modules
                    .push(ModuleInfo { start, end, name, name_len: name_vec.len() })
                    .ok();
            }
        }

        let mut framebuffer = None;
        if flags & (1 << 12) != 0 {
            let addr = rd64(mbi_addr + 96);
            let pitch = rd32(mbi_addr + 104);
            let width = rd32(mbi_addr + 108);
            let height = rd32(mbi_addr + 112);
            let bpp = rd8(mbi_addr + 116);
            let typ = rd8(mbi_addr + 117);
            framebuffer = Some(FramebufferInfo {
                addr,
                pitch,
                width,
                height,
                bpp,
                type_: typ,
            });
        }

        let (kernel_phys_start, kernel_phys_end) = kernel_phys_bounds();

        BootInfo {
            memory_map,
            kernel_phys_start,
            kernel_phys_end,
            kernel_virt_base: VIRT_PHYS_OFFSET,
            cmdline,
            bootloader_name,
            modules,
            framebuffer,
        }
    }
}

// ============================================================================
// Kernel Entry Point (called from assembly)
// ============================================================================

/// Multiboot2 kernel entry point, dispatched from `kernel_rust_entry` in
/// `src/bin/kernel.rs` (the symbol trampoline.S jumps to) by boot magic.
#[no_mangle]
pub extern "C" fn ax_kernel_entry(mbi_addr: u64) -> ! {
    // 1. Initialize serial console FIRST (for early debugging)
    init_serial();
    serial_puts("AXIOM-X BOOT\n");

    // 2. Parse boot information
    serial_puts("Parsing multiboot2 info...\n");
    let boot_info = parse_multiboot2(mbi_addr);
    serial_print!("  Kernel: {:#x} - {:#x}\n", boot_info.kernel_phys_start, boot_info.kernel_phys_end);
    serial_print!("  Memory regions: {}\n", boot_info.memory_map.len());

    // 3. Initialize kernel frame allocator with memory map
    serial_puts("Initializing kernel frame allocator...\n");
    // Frame allocator will be initialized by kernel with memory map
    serial_puts("  Frame allocator will be initialized by kernel\n");

    // Continue with rest of initialization
    ax_kernel_entry_continue(boot_info);
}

/// Multiboot1 kernel entry point (QEMU -kernel, GRUB "multiboot").
/// Same boot flow as `ax_kernel_entry` but parses a Multiboot1 info structure.
#[no_mangle]
pub extern "C" fn ax_kernel_entry_mb1(mbi_addr: u64) -> ! {
    init_serial();
    serial_puts("Axiom-X kernel starting... (multiboot1)\n");

    serial_puts("Parsing multiboot1 info...\n");
    let boot_info = parse_multiboot1(mbi_addr);
    serial_print!("  Kernel: {:#x} - {:#x}\n", boot_info.kernel_phys_start, boot_info.kernel_phys_end);
    serial_print!("  Memory regions: {}\n", boot_info.memory_map.len());
    if boot_info.bootloader_name.len() > 0 {
        let bl_str = core::str::from_utf8(&boot_info.bootloader_name).unwrap_or("?");
        serial_print!("  Bootloader: {}\n", bl_str);
    }
    if boot_info.cmdline.len() > 0 {
        let cmd_str = core::str::from_utf8(&boot_info.cmdline).unwrap_or("?");
        serial_print!("  Cmdline: {}\n", cmd_str);
    }

    ax_kernel_entry_continue(boot_info);
}

/// Initialize kernel after frame allocator is set up
/// This function assumes the frame allocator has already been initialized
pub fn init_kernel_after_frame_allocator(boot_info: BootInfo) -> ! {
    ax_kernel_entry_continue(boot_info);
}

/// Continue kernel initialization after frame allocator is set up
fn ax_kernel_entry_continue(boot_info: BootInfo) -> ! {
    // 1. Initialize early boot allocator
    serial_puts("Initializing boot allocator...\n");
    unsafe { init_boot_allocator(&boot_info); }
    // Keep the module list (GRUB `module2` images, e.g. user ELF programs);
    // their memory is reserved from the frame allocator above.
    unsafe { BOOT_MODULES = boot_info.modules.clone(); }
    unsafe { BOOT_CMDLINE = boot_info.cmdline.clone(); }
    serial_print!("  Boot modules: {}\n", boot_info.modules.len());

    // 2. Initialize early page tables
    serial_puts("Setting up page tables...\n");
    let pml4_frame = unsafe { init_early_page_tables(&boot_info) };
    serial_print!("  PML4 at {:#x}\n", pml4_frame.start_address().as_u64());

    // 3. Initialize early heap
    serial_puts("Initializing early heap...\n");
    unsafe { init_early_heap(); }

    // 4. Initialize CPU features
    serial_puts("Initializing CPU features...\n");
    axiom_x_arch::init_cpu_features();

    // 5. Initialize architecture (IDT, syscall, etc.)
    serial_puts("Initializing architecture...\n");
    axiom_x_arch::init_arch();
    if let Some(r) = axiom_x_arch::PS2_REPORT.get() {
        serial_print!(
            "  PS/2: present {}, config {:#04x} -> {:#04x}, enable-scanning reply {:?}, {} stale bytes flushed
",
            r.present, r.config_before, r.config_after, r.enable_reply, r.flushed
        );
    }

    // Clock: RTC wall time + TSC calibrated against RTC second edges.
    // Interrupts are still off, so nothing disturbs the calibration.
    serial_puts("Calibrating clock (RTC + TSC, 1-2 s)...\n");
    let (rtc_now, tsc_hz) = axiom_x_arch::clock::init();
    serial_print!(
        "  RTC: {} (no time zone)  TSC: {}.{:03} MHz\n",
        rtc_now,
        tsc_hz / 1_000_000,
        tsc_hz / 1_000 % 1_000
    );

    // Scheduler tick: the local APIC timer, calibrated against the TSC just
    // above; the PIT stays as the fallback (and with axiom.timer=pit).
    start_tick_source();

    // Initialize movie subsystem (embedded boot movie)
    serial_puts("Initializing movie subsystem...\n");
    crate::movie::init_movie_subsystem();

    // 5. Create process table
    serial_puts("Creating process table...\n");
    let process_table: &'static mut ProcessTable = Box::leak(ProcessTable::new_boxed());
    serial_print!("  ProcessTable: {} bytes\n", core::mem::size_of::<ProcessTable>());

    // 6. Initialize scheduler
    serial_puts("Initializing scheduler...\n");
    let num_cores = detect_cpu_cores();
    init_scheduler(num_cores, 10_000_000); // 10ms time slice
    set_process_table(process_table);

    // 7. Create init process (PID 1): a kernel thread on its own guarded stack
    serial_puts("Creating init process...\n");
    let init_stack = alloc_kernel_stack();
    let init_pid = axiom_x_arch::sched::spawn_kernel_thread(init_process, init_stack, pml4_frame)
        .expect("Failed to create init process");
    serial_print!("  Init PID: {} (kernel stack top {:#x})\n", init_pid, init_stack.as_u64());

    // 8. Start scheduling (never returns). No `sti` here: init's initial
    // frame has IF=1, so interrupts come on atomically with the `iretq`.
    serial_puts("Starting scheduler...\n");
    axiom_x_arch::sched::start(init_pid);
}

/// Make the local APIC timer the scheduler tick if there is one. Interrupts
/// are still off; IRQ0 (PIT) is masked once the APIC timer runs.
fn start_tick_source() {
    if cmdline_flag("axiom.timer=pit") {
        serial_puts("  Tick: PIT (axiom.timer=pit)\n");
        return;
    }
    let Some(base) = axiom_x_arch::apic::base_phys() else {
        serial_puts("  Tick: PIT (no local APIC)\n");
        return;
    };
    unsafe {
        let pml4 = KERNEL_PML4.expect("PML4 not initialized").start_address().as_u64() as *mut PageTable;
        map_4kib_page(
            pml4,
            base,
            base,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE | PageTableFlags::NO_EXECUTE,
        );
        x86_64::instructions::tlb::flush(VirtAddr::new(base));
    }
    match axiom_x_arch::apic::start_timer(base, 100) {
        Ok(r) => {
            axiom_x_arch::outb(0x21, axiom_x_arch::inb(0x21) | 0x01); // mask IRQ0
            serial_print!(
                "  Tick: local APIC timer at 100 Hz (APIC base {:#x}, {} counts/s, {} per tick); PIT IRQ0 masked\n",
                base, r.counts_per_s, r.per_tick
            );
        }
        Err(why) => serial_print!("  Tick: PIT (local APIC timer unusable: {})\n", why),
    }
}

/// Measure the tick rate against the TSC for `ms` milliseconds and log it:
/// evidence that ticks arrive at the programmed 100 Hz on this machine.
fn check_tick_rate(ms: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let t0 = axiom_x_arch::clock::monotonic_ns();
    let k0 = axiom_x_arch::sched::TICKS.load(Relaxed);
    while axiom_x_arch::clock::monotonic_ns() - t0 < ms * 1_000_000 {
        unsafe { asm!("hlt") };
    }
    let dt = axiom_x_arch::clock::monotonic_ns() - t0;
    let n = axiom_x_arch::sched::TICKS.load(Relaxed) - k0;
    let milli_hz = n * 1_000_000_000_000 / dt.max(1);
    serial_print!(
        "[clock] tick check ({}): {} ticks in {}.{:03} s (TSC) = {}.{:01} Hz, expected 100 Hz\n",
        axiom_x_arch::apic::source_name(),
        n,
        dt / 1_000_000_000,
        dt / 1_000_000 % 1000,
        milli_hz / 1000,
        milli_hz % 1000 / 100
    );
}

/// Print the interrupt-latency table to serial and reset it.
fn print_latency_report() {
    let mut buf = [0u8; 4096];
    let mut w = axiom_x_arch::latency::BufWriter { buf: &mut buf, len: 0 };
    axiom_x_arch::latency::report(&mut w);
    let n = w.len;
    serial_puts("[latency] after the self-tests:\n");
    if let Ok(text) = core::str::from_utf8(&buf[..n]) {
        for line in text.lines() {
            serial_print!("[latency] {}\n", line);
        }
    }
    axiom_x_arch::latency::reset();
}

/// Init process (PID 1)
extern "C" fn init_process() -> ! {
    log::info!("Init process started");
    serial_puts("PID 1 (init) running on its own stack; interrupts enabled\n");
    // Interrupts are on from here: console output can be buffered and
    // drained by the UART's transmit interrupt.
    axiom_x_arch::console::enable_async_tx();
    check_tick_rate(1000);

    // Start the ring-3 programs as concurrent processes, each in its own
    // address space. init stays runnable and is preempted like they are.
    #[cfg(feature = "freestanding")]
    {
        user::attach_ledger_disk();
        user::mount_fs();
        user::install_hooks();
        user::apply_egress_boot();
        if cmdline_flag("axiom.selftest=off") {
            serial_puts("[kernel] self-tests skipped (axiom.selftest=off)\n");
        } else {
            user::run_rounds();
            // Interrupt latency over the self-tests (then start counting afresh
            // for the interactive session).
            print_latency_report();
        }
        // Interactive shell on the console; only returns if there is none.
        user::run_shell();
    }

    // TODO: Mount root filesystem, start userspace init
    // Heartbeat on serial so boot evidence shows timer IRQs resuming PID 1.
    let mut wakes: u64 = 0;
    loop {
        unsafe { asm!("hlt") };
        wakes += 1;
        if wakes % 100 == 0 {
            let ticks = axiom_x_arch::sched::TICKS.load(core::sync::atomic::Ordering::Relaxed);
            let (pit_ms, tsc_ms, rtc_s) = axiom_x_arch::clock::timer_check(ticks);
            serial_print!(
                "  init heartbeat: {} wakes, {} switches | since boot: PIT {}.{:02}s, TSC {}.{:03}s, RTC {}s\n",
                wakes,
                axiom_x_arch::sched::SWITCHES.load(core::sync::atomic::Ordering::Relaxed),
                pit_ms / 1000,
                pit_ms % 1000 / 10,
                tsc_ms / 1000,
                tsc_ms % 1000,
                rtc_s
            );
        }
    }
}

/// True when `flag` appears as a word on the kernel command line.
fn cmdline_flag(flag: &str) -> bool {
    boot_cmdline().split_whitespace().any(|w| w == flag)
}

/// Detect CPU cores (simplified)
fn detect_cpu_cores() -> usize {
    // TODO: Parse ACPI MADT or CPUID
    4 // Assume 4 cores for now
}

// ============================================================================
// Panic Handler
// ============================================================================

/// Allocation-free serial writer: usable before the early heap exists.
struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_puts(s);
        Ok(())
    }
}

#[cfg(all(feature = "freestanding", not(test)))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    use core::sync::atomic::{AtomicBool, Ordering};
    static PANICKING: AtomicBool = AtomicBool::new(false);
    // Flush buffered output and write the rest directly: interrupts are
    // about to stop for good.
    x86_64::instructions::interrupts::disable();
    axiom_x_arch::console::serial_sync();
    if PANICKING.swap(true, Ordering::SeqCst) {
        serial_puts("\nKERNEL PANIC (nested)\n");
    } else {
        // Must not allocate: panics can happen before the heap is mapped.
        let _ = write!(SerialWriter, "KERNEL PANIC: {}\n", info);
    }
    loop {
        unsafe { asm!("cli; hlt") };
    }
}

// ============================================================================
// Global Allocator (uses early heap)
// ============================================================================

#[cfg(feature = "freestanding")]
struct KernelAllocator;

#[cfg(feature = "freestanding")]
unsafe impl core::alloc::GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        early_alloc(layout.size(), layout.align()).unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // No deallocation in bump allocator
    }
}

#[cfg(feature = "freestanding")]
#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

// ============================================================================
// Assembly Entry Point (boot.S equivalent in Rust)
// ============================================================================

/// This would be the assembly entry point (boot.S)
/// Provided here as documentation - actual file should be boot.S
///
/// ```nasm
/// ; boot.S - Multiboot2 entry point
/// section .multiboot
/// align 8
/// dd 0xE85250D6          ; magic
/// dd 0                   ; architecture (0 = i386)
/// dd header_end - header_start ; header length
/// dd 0x100000000 - (0xE85250D6 + 0 + (header_end - header_start)) ; checksum
///
/// ; Required tags
/// dw 1, 0, 24, 0         ; information request tag
/// dd 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
///
/// dw 0, 0, 8, 0          ; end tag
///
/// header_start:
/// header_end:
///
/// section .text
/// global _start
/// extern ax_kernel_entry
///
/// _start:
///     ; Verify multiboot2
///     cmp eax, 0x36D76289
///     jne .invalid
///
///     ; Set up stack
///     mov rsp, stack_top
///
///     ; Call Rust entry
///     mov rdi, rbx       ; mbi_addr in rbx per multiboot2 spec
///     call ax_kernel_entry
///
/// .invalid:
///     hlt
///     jmp .invalid
///
/// section .bss
/// align 16
/// stack_bottom:
/// resb 16384
/// stack_top:
/// ```
pub mod asm_entry_doc {}

#[cfg(feature = "uefi")]
mod uefi_boot {
    use super::*;
    use uefi::proto::console::gop::GraphicsOutput;
    use uefi::table::boot::MemoryDescriptor;
    use uefi::table::boot::MemoryType;
    use alloc::format;

    /// UEFI boot information structure
    #[derive(Debug, Clone)]
    pub struct UefiBootInfo {
        pub memory_map: Vec<UefiMemoryRegion, 128>,
        pub framebuffer: Option<FramebufferInfo>,
    }

    /// UEFI memory region
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UefiMemoryRegion {
        pub base: u64,
        pub length: u64,
        pub region_type: u32, // UEFI memory type
    }

    impl UefiBootInfo {
        pub fn new(memory_map: uefi::table::boot::MemoryMap, framebuffer: Option<GraphicsOutput>) -> Self {
            let mut regions = Vec::new();
            for desc in memory_map.entries() {
                let region_type = match desc.ty {
                    MemoryType::RESERVED => 0,
                    MemoryType::LOADER_CODE => 1,
                    MemoryType::LOADER_DATA => 2,
                    MemoryType::BOOT_SERVICES_CODE => 3,
                    MemoryType::BOOT_SERVICES_DATA => 4,
                    MemoryType::RUNTIME_SERVICES_CODE => 5,
                    MemoryType::RUNTIME_SERVICES_DATA => 6,
                    MemoryType::CONVENTIONAL => 7,
                    MemoryType::UNUSABLE => 8,
                    MemoryType::ACPI_RECLAIM => 9,
                    MemoryType::ACPI_NVS => 10,
                    MemoryType::MMIO => 11,
                    MemoryType::MMIO_PORT_SPACE => 12,
                    MemoryType::PAL_CODE => 13,
                    MemoryType::PERSISTENT_MEMORY => 14,
                    _ => 0,
                };
                regions.push(UefiMemoryRegion {
                    base: desc.phys_start,
                    length: desc.page_count * 4096,
                    region_type,
                }).ok();
            }

            let framebuffer = framebuffer.map(|gop| {
                let mode = gop.current_mode_info();
                FramebufferInfo {
                    addr: gop.frame_buffer_base(),
                    pitch: mode.stride() * 4,
                    width: mode.resolution().0,
                    height: mode.resolution().1,
                    bpp: 32,
                    type_: 1, // RGB
                }
            });

            Self {
                memory_map: regions,
                framebuffer,
            }
        }
    }

    /// UEFI kernel entry point
    pub fn ax_kernel_entry_uefi(boot_info: UefiBootInfo) -> ! {
        // Convert UEFI boot info to common BootInfo
        let mut memory_map = Vec::new();
        for region in boot_info.memory_map {
            let region_type = match region.region_type {
                7 => 1, // CONVENTIONAL -> Available RAM
                _ => region.region_type,
            };
            memory_map.push(MemoryRegion {
                base: region.base,
                length: region.length,
                region_type,
            }).ok();
        }

        let boot_info = BootInfo {
            memory_map,
            kernel_phys_start: 0,
            kernel_phys_end: 0,
            kernel_virt_base: VIRT_PHYS_OFFSET,
            cmdline: Vec::new(),
            bootloader_name: Vec::new(),
            modules: Vec::new(),
            framebuffer: boot_info.framebuffer,
        };

        // Initialize page tables (UEFI already has paging, but we set up our own)
        let pml4_frame = unsafe { init_early_page_tables(&boot_info) };

        // Initialize serial console
        init_serial();
        serial_puts("Axiom-X UEFI kernel starting...\n");

        // Continue with common kernel initialization
        crate::ax_kernel_entry_continue(boot_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_info_structure() {
        let info = BootInfo {
            memory_map: Vec::new(),
            kernel_phys_start: 0x100000,
            kernel_phys_end: 0x200000,
            kernel_virt_base: VIRT_PHYS_OFFSET,
            cmdline: Vec::new(),
            bootloader_name: Vec::new(),
            modules: Vec::new(),
            framebuffer: None,
        };
        assert_eq!(info.kernel_phys_start, 0x100000);
    }

    #[test]
    fn test_memory_region() {
        let region = MemoryRegion {
            base: 0x100000,
            length: 0x1000000,
            region_type: 1,
        };
        assert_eq!(region.base, 0x100000);
    }
}