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
use axiom_x_arch::process::{ProcessTable, CpuContext, init_kernel_process};
use axiom_x_arch::interrupts::{init_scheduler, set_process_table};
use axiom_x_math::memory_algebra::{FrameAllocator as MathFrameAllocator, RegionType, RegionFlags};
use alloc::boxed::Box;

/// Formatted serial output that never allocates (safe before the heap exists).
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = write!($crate::SerialWriter, $($arg)*);
    }};
}

// Movie subsystem
pub mod movie;

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

/// Kernel stacks for the boot-created threads: idle, then init (PID 1).
/// No guard pages yet: an overflow runs into the neighbour or unmapped memory.
const KERNEL_STACKS_BASE: u64 = 0xFFFF_8000_0020_0000;
/// 256 KiB each: IRQs run on the interrupted thread's stack, and the
/// unoptimized scheduler tick alone needs well over 16 KiB.
const BOOT_KSTACK_SIZE: u64 = 256 * 1024;
const IDLE_STACK_TOP: u64 = KERNEL_STACKS_BASE + BOOT_KSTACK_SIZE;
const INIT_STACK_TOP: u64 = KERNEL_STACKS_BASE + 2 * BOOT_KSTACK_SIZE;

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

    // Map kernel stacks (idle + init) and heap.
    // NOTE: must stay above the kernel image mapping (ends below VIRT+0x200000).
    let kernel_stack_start = KERNEL_STACKS_BASE;
    for i in 0..(2 * BOOT_KSTACK_SIZE / 4096) {
        let phys = alloc_boot_frame().expect("out of memory for kernel stack");
        let virt = kernel_stack_start + i * 4096;
        map_4kib_page(pml4, virt, phys.start_address().as_u64(),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE);
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
    let pdpt = get_or_create_table(pml4, pml4_idx);
    // Get or create PD
    let pd = get_or_create_table(pdpt, pdpt_idx);
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

    let pdpt = get_or_create_table(pml4, pml4_idx);
    let pd = get_or_create_table(pdpt, pdpt_idx);
    let pt = get_or_create_table(pd, pd_idx);
    let pt = unsafe { &mut *pt };
    pt[pt_idx as usize].set_addr(PhysAddr::new(phys), flags);
}

/// Get or create next-level page table
unsafe fn get_or_create_table(table: *mut PageTable, index: u64) -> *mut PageTable {
    let table = unsafe { &mut *table };
    let entry = &mut table[index as usize];
    if entry.is_unused() {
        let frame = alloc_boot_frame().expect("out of memory for page table");
        entry.set_addr(frame.start_address(), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
        ptr::write_bytes(frame.start_address().as_u64() as *mut PageTable, 0, 1);
    }
    let phys = entry.addr().as_u64();
    phys as *mut PageTable
}

/// Boot-time frame allocator (bump allocator from available memory)
static mut BOOT_FRAME_ALLOCATOR: Option<BootFrameAllocator> = None;

struct BootFrameAllocator {
    current: u64,
    end: u64,
}

impl BootFrameAllocator {
    fn new(start: u64, end: u64) -> Self {
        Self { current: start, end }
    }

    fn alloc(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // The frame at `current` must be fully inside [start, end).
        if self.current + 4096 > self.end {
            return None;
        }
        let frame = PhysFrame::containing_address(PhysAddr::new(self.current));
        self.current += 4096;
        Some(frame)
    }
}

unsafe fn init_boot_allocator(boot_info: &BootInfo) {
    // Take the first usable region that has room, clamping the start past
    // the kernel image (the loader puts the image at 0x100000, inside the
    // first E820/GRUB usable region, so we can't require region.base >= end).
    for region in &boot_info.memory_map {
        if region.region_type != 1 {
            continue;
        }
        let region_end = region.base + region.length;
        let alloc_start = region.base.max(boot_info.kernel_phys_end);
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
        let alloc_start = region.base.max(boot_info.kernel_phys_end);
        let aligned = (alloc_start + 4095) & !4095;
        
        const MIN_BOOT_ALLOC_SIZE_FALLBACK: u64 = 64 * 1024; // 64 KiB
        if aligned + MIN_BOOT_ALLOC_SIZE_FALLBACK <= region_end {
            BOOT_FRAME_ALLOCATOR = Some(BootFrameAllocator::new(aligned, region_end));
            return;
        }
    }
    
    panic!("No available memory for boot allocator");
}

unsafe fn alloc_boot_frame() -> Option<PhysFrame<Size4KiB>> {
    BOOT_FRAME_ALLOCATOR.as_mut()?.alloc()
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
    outb(COM1 + 0, 0x0C); // Divisor low byte (115200 baud @ 18.432 MHz)
    outb(COM1 + 1, 0x00); // Divisor high byte
    outb(COM1 + 3, 0x03); // 8N1, disable DLAB
    outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
}

/// Write byte to serial
pub fn serial_putc(c: u8) {
    while inb(COM1 + 5) & 0x20 == 0 {} // Wait for THR empty
    outb(COM1, c);
}

/// Write string to serial
pub fn serial_puts(s: &str) {
    for c in s.bytes() {
        serial_putc(c);
    }
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

    // 7. Create idle process
    serial_puts("Creating idle process...\n");
    let _idle_ctx = CpuContext::new_kernel(
        idle_loop as *const () as u64,
        IDLE_STACK_TOP,
        pml4_frame.start_address().as_u64(),
    );
    // Note: Process creation needs proper implementation

    // 8. Create init process (PID 1)
    serial_puts("Creating init process...\n");
    let init_pid = init_kernel_process(
        process_table,
        init_process as *const () as u64,
        VirtAddr::new(INIT_STACK_TOP),
        pml4_frame,
    ).expect("Failed to create init process");
    serial_print!("  Init PID: {}\n", init_pid);

    // 9. Start scheduler (this never returns)
    // No `sti` here: an IRQ taken between `sti` and the switch would run the
    // scheduler mid-handoff. The init context's RFLAGS has IF=1, so
    // interrupts are enabled atomically by the `iretq` into PID 1.
    serial_puts("Starting scheduler...\n");
    axiom_x_arch::process::context_switch(process_table, init_pid);
}

/// Idle process loop
extern "C" fn idle_loop() -> ! {
    loop {
        unsafe { asm!("hlt") };
    }
}

/// Init process (PID 1)
extern "C" fn init_process() -> ! {
    log::info!("Init process started");
    serial_puts("PID 1 (init) running on its own stack; interrupts enabled\n");

    // TODO: Mount root filesystem, start userspace init
    // Heartbeat on serial so boot evidence shows timer IRQs resuming PID 1.
    let mut wakes: u64 = 0;
    loop {
        unsafe { asm!("hlt") };
        wakes += 1;
        if wakes % 100 == 0 {
            serial_print!("  init heartbeat: {} timer wakes\n", wakes);
        }
    }
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