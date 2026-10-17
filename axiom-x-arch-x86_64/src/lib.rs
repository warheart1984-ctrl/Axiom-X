//! x86_64 Architecture Implementation for Axiom-X
//!
//! Implements the architecture-agnostic traits using x86_64 0.15 APIs.
//!
//! Status: `partial` — core traits implemented; needs integration testing.

#![feature(abi_x86_interrupt)]
#![no_std]

extern crate alloc;

use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use x86_64::{
    registers::model_specific::{Efer as EferMsr, EferFlags, LStar, SFMask, Star},
    registers::rflags::RFlags,
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame},
    structures::paging::{Mapper, Size4KiB},
};
use raw_cpuid::CpuId;
use axiom_x_arch_traits::*;

// ============================================================================
// Interrupt Controller Implementation
// ============================================================================

/// Interrupt handler function (no error code)
type X86InterruptHandler = x86_64::structures::idt::HandlerFunc;
/// Interrupt handler function (with error code)
type X86InterruptHandlerWithError = x86_64::structures::idt::HandlerFuncWithErrCode;
/// Page fault handler function
type X86PageFaultHandler = x86_64::structures::idt::PageFaultHandlerFunc;

pub struct X86InterruptController {
    idt: InterruptDescriptorTable,
    handlers: [Option<X86InterruptHandler>; 256],
    handlers_with_error: [Option<X86InterruptHandlerWithError>; 256],
    page_fault_handler: Option<X86PageFaultHandler>,
    pic_initialized: bool,
}

impl X86InterruptController {
    pub fn new() -> Self {
        Self {
            idt: InterruptDescriptorTable::new(),
            handlers: [None; 256],
            handlers_with_error: [None; 256],
            page_fault_handler: None,
            pic_initialized: false,
        }
    }

    fn init_pic(&mut self) {
        if self.pic_initialized { return; }
        // Remap PIC: master to 0x20, slave to 0x28
        unsafe {
            asm!("out 0x20, al", in("al") 0x11u8); // ICW1
            asm!("out 0xA0, al", in("al") 0x11u8);
            asm!("out 0x21, al", in("al") 0x20u8); // ICW2: master offset
            asm!("out 0xA1, al", in("al") 0x28u8); // ICW2: slave offset
            asm!("out 0x21, al", in("al") 0x04u8); // ICW3: master has slave on IRQ2
            asm!("out 0xA1, al", in("al") 0x02u8); // ICW3: slave cascade identity
            asm!("out 0x21, al", in("al") 0x01u8); // ICW4: 8086 mode
            asm!("out 0xA1, al", in("al") 0x01u8);
            asm!("out 0x21, al", in("al") 0x00u8); // OCW1: unmask all
             asm!("out 0xA1, al", in("al") 0x00u8);
        }
        self.pic_initialized = true;
    }
}

impl Default for X86InterruptController {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for X86InterruptController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86InterruptController")
            .field("pic_initialized", &self.pic_initialized)
            .finish()
    }
}

impl InterruptController for X86InterruptController {
    type Handler = X86InterruptHandler;

    fn enable(&mut self) {
        unsafe { asm!("sti") };
    }

    fn disable(&mut self) {
        unsafe { asm!("cli") };
    }

    fn register_handler(&mut self, vector: u8, handler: Self::Handler) {
        self.handlers[vector as usize] = Some(handler);
        // Note: Actual IDT entry setup happens in init_idt()
    }

    fn set_timer_handler(&mut self, handler: Self::Handler) {
        self.register_handler(0x20, handler); // IRQ0
    }

    fn end_of_interrupt(&mut self, vector: u8) {
        unsafe {
            if vector >= 0x28 {
                asm!("out 0xA0, al", in("al") 0x20u8); // Slave PIC
            }
            asm!("out 0x20, al", in("al") 0x20u8); // Master PIC
        }
    }

    fn current_vector(&self) -> Option<u8> {
        // Would need to read from IST or task state
        None
    }
}

impl X86InterruptController {
    /// Initialize IDT with all exception handlers
    pub fn init_idt(&mut self) {
        // TODO: Re-enable after fixing "offset is not a multiple of 16" codegen bug
        // Exception handlers (0-31)
        // self.idt.divide_error.set_handler_fn(divide_error_handler);
        // self.idt.debug.set_handler_fn(debug_handler);
        // self.idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        // self.idt.breakpoint.set_handler_fn(breakpoint_handler);
        // self.idt.overflow.set_handler_fn(overflow_handler);
        // self.idt.bound_range_exceeded.set_handler_fn(bound_range_exceeded_handler);
        // self.idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        // self.idt.device_not_available.set_handler_fn(device_not_available_handler);
        // self.idt.double_fault.set_handler_fn(double_fault_handler);
        // self.idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        // self.idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        // self.idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
        // self.idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        // self.idt.page_fault.set_handler_fn(page_fault_handler);
        // self.idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        // self.idt.alignment_check.set_handler_fn(alignment_check_handler);
        // self.idt.machine_check.set_handler_fn(machine_check_handler);
        // self.idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
        // self.idt.virtualization.set_handler_fn(virtualization_handler);
        //
        // // IRQ handlers (0x20-0x2F)
        // self.idt[0x20].set_handler_fn(timer_handler);
        // self.idt[0x21].set_handler_fn(keyboard_handler);
        // self.idt[0x24].set_handler_fn(mouse_handler);
        // self.idt[0x2E].set_handler_fn(ide_handler);
        //
        // // Syscall handler (vector 0x80 or via SYSCALL MSR)
        // self.idt[0x80].set_handler_fn(syscall_handler);
        //
        // // Spurious interrupt
        // self.idt[0xFF].set_handler_fn(spurious_handler);
        //
        // // The IDT must live for the entire kernel lifetime. Clone and leak so
        // // the borrow does not escape `self`; the loaded IDTR references it.
        // let idt = Box::leak(Box::new(self.idt.clone()));
        // idt.load();
        // self.init_pic();
    }

    /// Initialize SYSCALL/SYSRET
    pub fn init_syscall(&mut self, entry_point: u64) {
        unsafe {
            // STAR: SYSRET CS/SS (user) in bits 63:48, SYSCALL CS/SS (kernel) in bits 47:32
            Star::write_raw(0x1B, 0x08);

            // LSTAR: syscall entry point
            LStar::write(x86_64::VirtAddr::new(entry_point));

            // SFMASK: RFLAGS mask (clear IF on syscall entry)
            SFMask::write(RFlags::from_bits_truncate(0x200));

            // Enable SYSCALL/SYSRET in EFER
            let mut efer = EferMsr::read();
            efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS); // SCE bit
            EferMsr::write(efer);
        }
    }
}

// ============================================================================
// Exception Handlers
// ============================================================================
//
// extern "x86-interrupt" fn divide_error_handler(_frame: InterruptStackFrame) {
//     panic!("DIVIDE ERROR");
// }
//
// extern "x86-interrupt" fn debug_handler(_frame: InterruptStackFrame) {
//     // Debug exception - could be breakpoint
// }
//
// extern "x86-interrupt" fn nmi_handler(_frame: InterruptStackFrame) {
//     panic!("NMI");
// }
//
// extern "x86-interrupt" fn breakpoint_handler(_frame: InterruptStackFrame) {
//     // Breakpoint - int3
// }
//
// extern "x86-interrupt" fn overflow_handler(_frame: InterruptStackFrame) {
//     panic!("OVERFLOW");
// }
//
// extern "x86-interrupt" fn bound_range_handler(_frame: InterruptStackFrame) {
//     panic!("BOUND RANGE EXCEEDED");
// }
//
// extern "x86-interrupt" fn invalid_opcode_handler(_frame: InterruptStackFrame) {
//     panic!("INVALID OPCODE");
// }
//
// extern "x86-interrupt" fn device_not_available_handler(_frame: InterruptStackFrame) {
//     unsafe { asm!("clts") }; // Clear TS bit for lazy FPU restore
// }
//
// extern "x86-interrupt" fn double_fault_handler(_frame: InterruptStackFrame, _error_code: u64) -> ! {
//     panic!("DOUBLE FAULT");
// }
//
// extern "x86-interrupt" fn x87_floating_point_handler(_frame: InterruptStackFrame) {
//     panic!("x87 FP EXCEPTION");
// }
//
// extern "x86-interrupt" fn machine_check_handler(_frame: InterruptStackFrame) -> ! {
//     panic!("MACHINE CHECK");
// }
//
// extern "x86-interrupt" fn simd_floating_point_handler(_frame: InterruptStackFrame) {
//     panic!("SIMD FP EXCEPTION");
// }
//
// extern "x86-interrupt" fn virtualization_handler(_frame: InterruptStackFrame) {
//     panic!("VIRTUALIZATION EXCEPTION");
// }
//
// // ============================================================================
// // IRQ Handlers
// // ============================================================================
//
// extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
//     unsafe {
//         asm!("out 0x20, al", in("al") 0x20u8); // EOI to master PIC
//     }
//     // Scheduler tick handled by kernel
// }
//
// extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
//     unsafe { asm!("out 0x20, al", in("al") 0x20u8); }
// }
//
// extern "x86-interrupt" fn mouse_handler(_frame: InterruptStackFrame) {
//     unsafe {
//         asm!("out 0xA0, al", in("al") 0x20u8);
//         asm!("out 0x20, al", in("al") 0x20u8);
//     }
// }
//
// extern "x86-interrupt" fn ide_handler(_frame: InterruptStackFrame) {
//     unsafe {
//         asm!("out 0xA0, al", in("al") 0x20u8);
//         asm!("out 0x20, al", in("al") 0x20u8);
//     }
// }
//
// extern "x86-interrupt" fn syscall_handler(_frame: InterruptStackFrame) {
//     // Legacy INT 0x80 syscall
// }
//
// extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
//     // Ignore
// }

// ============================================================================
// Page Table Manager Implementation
// ============================================================================

pub struct X86PageTableManager {
    frame_allocator: Box<X86FrameAllocatorImpl>,
    kernel_offset: u64,
    active_root: PhysAddr,
}

impl X86PageTableManager {
    pub fn new(frame_allocator: Box<X86FrameAllocatorImpl>, kernel_offset: u64) -> Self {
        Self {
            frame_allocator,
            kernel_offset,
            active_root: PhysAddr::new(0),
        }
    }

    fn alloc_table(&mut self) -> Result<PhysAddr, AllocError> {
        self.frame_allocator.alloc().ok_or(AllocError::OutOfMemory)
    }
}

impl fmt::Debug for X86PageTableManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86PageTableManager")
            .field("active_root", &self.active_root)
            .finish()
    }
}

impl PageTableManager for X86PageTableManager {
    fn map(&mut self, virt: VirtAddr, phys: PhysAddr, flags: PageTableFlags, size: PageSize) -> Result<(), MapError> {
        let x86_flags = convert_flags(flags);
        let page: x86_64::structures::paging::Page<x86_64::structures::paging::Size4KiB> = 
            x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(virt.as_u64()));
        let frame: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB> = 
            x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(phys.as_u64()));

        let mut mapper = unsafe {
            x86_64::structures::paging::OffsetPageTable::new(
                &mut *((self.active_root.as_u64() + self.kernel_offset) as *mut x86_64::structures::paging::PageTable),
                x86_64::VirtAddr::new(self.kernel_offset),
            )
        };

        match size {
            PageSize::Size4KiB => {
                unsafe {
                    mapper.map_to(page, frame, x86_flags, self.frame_allocator.as_mut())
                        .map_err(|_| MapError::OutOfMemory)?
                        .flush();
                }
            }
            PageSize::Size2MiB => {
                // Huge page mapping requires Mapper<Size2MiB> - simplified for now
                return Err(MapError::AlignmentError);
            }
            PageSize::Size1GiB => {
                return Err(MapError::AlignmentError);
            }
        }
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr, size: PageSize) -> Result<(), UnmapError> {
        let page: x86_64::structures::paging::Page<x86_64::structures::paging::Size4KiB> = 
            x86_64::structures::paging::Page::containing_address(x86_64::VirtAddr::new(virt.as_u64()));
        let mut mapper = unsafe {
            x86_64::structures::paging::OffsetPageTable::new(
                &mut *((self.active_root.as_u64() + self.kernel_offset) as *mut x86_64::structures::paging::PageTable),
                x86_64::VirtAddr::new(self.kernel_offset),
            )
        };

        match size {
            PageSize::Size4KiB => {
                let (_frame, flush) = mapper.unmap(page).map_err(|_| UnmapError::NotMapped)?;
                flush.flush();
            }
            _ => return Err(UnmapError::InvalidAddress),
        }
        Ok(())
    }

    fn switch_address_space(&mut self, root: PhysAddr) -> Result<(), SwitchError> {
        self.active_root = root;
        unsafe {
            x86_64::registers::control::Cr3::write(
                x86_64::structures::paging::PhysFrame::containing_address(
                    x86_64::PhysAddr::new(root.as_u64())
                ),
                x86_64::registers::control::Cr3::read().1,
            );
        }
        Ok(())
    }

    fn current_root(&self) -> PhysAddr {
        self.active_root
    }

    fn allocate_page_table(&mut self) -> Result<PhysAddr, AllocError> {
        self.alloc_table()
    }

    fn map_kernel_range(&mut self, virt_start: VirtAddr, phys_start: PhysAddr, size: u64, flags: PageTableFlags) -> Result<(), MapError> {
        let mut addr = virt_start.as_u64();
        let end = addr + size;

        while addr < end {
            self.map(
                VirtAddr::new(addr),
                PhysAddr::new(phys_start.as_u64() + addr - virt_start.as_u64()),
                flags,
                PageSize::Size4KiB,
            )?;
            addr += 4096;
        }
        Ok(())
    }
}

// ============================================================================
// Context Switch Implementation
// ============================================================================

pub struct X86ContextSwitch;

impl fmt::Debug for X86ContextSwitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86ContextSwitch").finish()
    }
}

impl ContextSwitch for X86ContextSwitch {
    fn save_context(&mut self, ctx: &mut CpuContext) {
        unsafe {
            asm!(
                // Save callee-saved registers
                "mov [rdi + 0x00], r15",
                "mov [rdi + 0x08], r14",
                "mov [rdi + 0x10], r13",
                "mov [rdi + 0x18], r12",
                "mov [rdi + 0x20], rbx",
                "mov [rdi + 0x28], rbp",

                // Save RIP (return address from stack)
                "mov rax, [rsp]",
                "mov [rdi + 0x30], rax",

                // Save caller-saved registers
                "mov [rdi + 0x38], rdi",
                "mov [rdi + 0x40], rsi",
                "mov [rdi + 0x48], rdx",
                "mov [rdi + 0x50], rcx",
                "mov [rdi + 0x58], rax",
                "mov [rdi + 0x60], r8",
                "mov [rdi + 0x68], r9",
                "mov [rdi + 0x70], r10",
                "mov [rdi + 0x78], r11",

                // Save RSP (after return address)
                "lea rax, [rsp + 8]",
                "mov [rdi + 0x80], rax",

                // Save RFLAGS
                "pushfq",
                "pop rax",
                "mov [rdi + 0x88], rax",

                // Save CR3
                "mov rax, cr3",
                "mov [rdi + 0x90], rax",

                in("rdi") ctx as *mut CpuContext,
                options(nostack, preserves_flags)
            );
        }
    }

    fn restore_context(&mut self, ctx: &CpuContext) -> ! {
        unsafe {
            asm!(
                // Restore CR3
                "mov rax, [rdi + 0x90]",
                "mov cr3, rax",

                // Restore RFLAGS
                "push qword ptr [rdi + 0x88]",
                "popfq",

                // Restore RSP
                "mov rsp, [rdi + 0x80]",

                // Restore caller-saved registers
                "mov r11, [rdi + 0x78]",
                "mov r10, [rdi + 0x70]",
                "mov r9, [rdi + 0x68]",
                "mov r8, [rdi + 0x60]",
                "mov rax, [rdi + 0x58]",
                "mov rcx, [rdi + 0x50]",
                "mov rdx, [rdi + 0x48]",
                "mov rsi, [rdi + 0x40]",
                "mov rdi, [rdi + 0x38]",

                // Restore callee-saved and RIP via IRETQ
                "push qword ptr [rdi + 0x10]", // SS (kernel data segment)
                "push qword ptr [rdi + 0x80]", // RSP
                "push qword ptr [rdi + 0x88]", // RFLAGS
                "push qword ptr [rdi + 0x08]", // CS (kernel code segment)
                "push qword ptr [rdi + 0x30]", // RIP

                "mov rbp, [rdi + 0x28]",
                "mov rbx, [rdi + 0x20]",
                "mov r12, [rdi + 0x18]",
                "mov r13, [rdi + 0x10]",
                "mov r14, [rdi + 0x08]",
                "mov r15, [rdi + 0x00]",

                "iretq",
                in("rdi") ctx as *const CpuContext,
                options(noreturn, nostack)
            );
        }
    }

    fn create_context(
        &self,
        entry_point: u64,
        stack_top: u64,
        page_table_root: u64,
        is_user: bool,
    ) -> CpuContext {
        let mut ctx = CpuContext::default();
        ctx.instruction_pointer = entry_point;
        ctx.stack_pointer = stack_top;
        ctx.page_table_root = page_table_root;
        ctx.flags = 0x202; // IF=1

        if is_user {
            ctx.data[0] = 0x23; // SS (user data segment)
            ctx.data[1] = 0x1B; // CS (user code segment)
        } else {
            ctx.data[0] = 0x10; // SS (kernel data segment)
            ctx.data[1] = 0x08; // CS (kernel code segment)
        }
        ctx
    }
}

// ============================================================================
// Timer Source Implementation (LAPIC)
// ============================================================================

pub struct X86TimerSource {
    frequency_hz: u64,
    tick_count: AtomicU64,
}

impl X86TimerSource {
    pub fn new() -> Self {
        Self {
            frequency_hz: 0,
            tick_count: AtomicU64::new(0),
        }
    }
}

impl Default for X86TimerSource {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for X86TimerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86TimerSource")
            .field("frequency_hz", &self.frequency_hz)
            .field("tick_count", &self.tick_count.load(Ordering::Relaxed))
            .finish()
    }
}

impl TimerSource for X86TimerSource {
    fn init(&mut self, frequency_hz: u64) {
        self.frequency_hz = frequency_hz;
        // Initialize LAPIC timer
        // This is simplified - real implementation would configure LAPIC
    }

    fn current_tick(&self) -> u64 {
        self.tick_count.load(Ordering::Relaxed)
    }

    fn frequency(&self) -> u64 {
        self.frequency_hz
    }

    fn set_deadline(&mut self, _ticks: u64) {
        // Program LAPIC timer
    }

    fn enable_interrupt(&mut self) {
        // Enable LAPIC timer interrupt
    }

    fn disable_interrupt(&mut self) {
        // Disable LAPIC timer interrupt
    }

    fn acknowledge(&mut self) {
        self.tick_count.fetch_add(1, Ordering::Relaxed);
        unsafe { asm!("out 0x20, al", in("al") 0x20u8); } // EOI
    }
}

// ============================================================================
// CPU Features Implementation
// ============================================================================

pub struct X86CpuFeatures {
    cpuid: CpuId,
    vendor: &'static str,
    feature_info: Option<raw_cpuid::FeatureInfo>,
    ext_features: Option<raw_cpuid::ExtendedFeatures>,
}

impl X86CpuFeatures {
    pub fn new() -> Self {
        let cpuid = CpuId::new();
        let vendor = cpuid.get_vendor_info()
            .map(|v| Box::leak(v.as_str().to_string().into_boxed_str()) as &'static str)
            .unwrap_or("Unknown");
        let feature_info = cpuid.get_feature_info();
        let ext_features = cpuid.get_extended_feature_info();

        Self {
            cpuid,
            vendor,
            feature_info,
            ext_features,
        }
    }
}

impl Default for X86CpuFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for X86CpuFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86CpuFeatures")
            .field("vendor", &self.vendor)
            .finish()
    }
}

impl CpuFeatures for X86CpuFeatures {
    fn vendor(&self) -> &str {
        self.vendor
    }

    fn has_long_mode(&self) -> bool {
        self.cpuid.get_extended_processor_and_feature_identifiers()
            .map(|ext| ext.has_64bit_mode())
            .unwrap_or(false)
    }

    fn has_sse(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_sse()).unwrap_or(false)
    }

    fn has_sse2(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_sse2()).unwrap_or(false)
    }

    fn has_sse3(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_sse3()).unwrap_or(false)
    }

    fn has_ssse3(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_ssse3()).unwrap_or(false)
    }

    fn has_sse41(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_sse41()).unwrap_or(false)
    }

    fn has_sse42(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_sse42()).unwrap_or(false)
    }

    fn has_avx(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_avx()).unwrap_or(false)
    }

    fn has_avx2(&self) -> bool {
        self.ext_features.as_ref().map(|f| f.has_avx2()).unwrap_or(false)
    }

    fn has_fma(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_fma()).unwrap_or(false)
    }

    fn has_rdrand(&self) -> bool {
        self.feature_info.as_ref().map(|f| f.has_rdrand()).unwrap_or(false)
    }

    fn has_rdseed(&self) -> bool {
        self.ext_features.as_ref().map(|f| f.has_rdseed()).unwrap_or(false)
    }

    fn has_fsgsbase(&self) -> bool {
        self.ext_features.as_ref().map(|f| f.has_fsgsbase()).unwrap_or(false)
    }

    fn has_clflushopt(&self) -> bool {
        self.ext_features.as_ref().map(|f| f.has_clflushopt()).unwrap_or(false)
    }

    fn has_clwb(&self) -> bool {
        self.ext_features.as_ref().map(|f| f.has_clwb()).unwrap_or(false)
    }

    fn logical_processor_count(&self) -> usize {
        // Would parse ACPI MADT or CPUID leaf 0xB/0x1F
        4 // Placeholder
    }
}

// ============================================================================
// Early Console Implementation (Serial)
// ============================================================================

pub struct X86SerialConsole {
    port: u16,
}

impl X86SerialConsole {
    pub fn new(port: u16) -> Self {
        let console = Self { port };
        console.init();
        console
    }

    fn init(&self) {
        unsafe {
            asm!("out dx, al", in("dx") self.port + 1, in("al") 0x00u8); // Disable interrupts
            asm!("out dx, al", in("dx") self.port + 3, in("al") 0x80u8); // Enable DLAB
            asm!("out dx, al", in("dx") self.port + 0, in("al") 0x0Cu8); // Divisor low (115200)
            asm!("out dx, al", in("dx") self.port + 1, in("al") 0x00u8); // Divisor high
            asm!("out dx, al", in("dx") self.port + 3, in("al") 0x03u8); // 8N1, disable DLAB
            asm!("out dx, al", in("dx") self.port + 2, in("al") 0xC7u8); // Enable FIFO
            asm!("out dx, al", in("dx") self.port + 4, in("al") 0x0Bu8); // IRQs, RTS/DSR
        }
    }
}

impl Default for X86SerialConsole {
    fn default() -> Self {
        Self::new(0x3F8) // COM1
    }
}

impl fmt::Debug for X86SerialConsole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86SerialConsole")
            .field("port", &self.port)
            .finish()
    }
}

impl EarlyConsole for X86SerialConsole {
    fn putc(&mut self, c: u8) {
        unsafe {
            // Wait for THR empty (LSR bit 5)
            loop {
                let status: u8;
                asm!("in al, dx", in("dx") self.port + 5, out("al") status);
                if status & 0x20 != 0 {
                    break;
                }
            }
            asm!("out dx, al", in("dx") self.port, in("al") c);
        }
    }

    fn flush(&mut self) {
        // Serial is unbuffered
    }
}

// ============================================================================
// Frame Allocator Implementation
// ============================================================================

pub struct X86FrameAllocatorImpl {
    free_frames: Vec<PhysAddr>,
    total: usize,
}

impl X86FrameAllocatorImpl {
    pub fn new(memory_map: &[(PhysAddr, u64)]) -> Self {
        let mut free_frames = Vec::new();
        let mut total = 0;

        for (base, len) in memory_map {
            let mut addr = base.as_u64();
            let end = addr + len;
            while addr < end {
                free_frames.push(PhysAddr::new(addr));
                addr += 4096;
                total += 1;
            }
        }

        Self { free_frames, total }
    }
}

impl fmt::Debug for X86FrameAllocatorImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86FrameAllocatorImpl")
            .field("free_frames", &self.free_frames.len())
            .field("total", &self.total)
            .finish()
    }
}

impl FrameAllocator for X86FrameAllocatorImpl {
    fn alloc(&mut self) -> Option<PhysAddr> {
        self.free_frames.pop()
    }

    fn dealloc(&mut self, addr: PhysAddr) {
        self.free_frames.push(addr);
    }

    fn total_frames(&self) -> usize {
        self.total
    }

    fn free_frames(&self) -> usize {
        self.free_frames.len()
    }
}

unsafe impl x86_64::structures::paging::FrameAllocator<Size4KiB> for X86FrameAllocatorImpl {
    fn allocate_frame(&mut self) -> Option<x86_64::structures::paging::PhysFrame<Size4KiB>> {
        self.alloc()
            .map(|p| x86_64::structures::paging::PhysFrame::containing_address(
                x86_64::PhysAddr::new(p.as_u64())
            ))
    }
}

// ============================================================================
// Kernel Hardware Aggregate
// ============================================================================

pub struct X86KernelHardware {
    pub interrupt_controller: X86InterruptController,
    pub page_table_manager: X86PageTableManager,
    pub context_switch: X86ContextSwitch,
    pub timer_source: X86TimerSource,
    pub cpu_features: X86CpuFeatures,
    pub early_console: X86SerialConsole,
    pub frame_allocator: X86FrameAllocatorImpl,
}

impl X86KernelHardware {
    pub fn new(memory_map: &[(PhysAddr, u64)]) -> Self {
        let frame_allocator = Box::new(X86FrameAllocatorImpl::new(memory_map));
        let page_table_manager = X86PageTableManager::new(frame_allocator, 0xFFFF_8000_0000_0000);

        Self {
            interrupt_controller: X86InterruptController::new(),
            page_table_manager,
            context_switch: X86ContextSwitch,
            timer_source: X86TimerSource::new(),
            cpu_features: X86CpuFeatures::new(),
            early_console: X86SerialConsole::new(0x3F8),
            frame_allocator: X86FrameAllocatorImpl::new(memory_map),
        }
    }
}

impl fmt::Debug for X86KernelHardware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X86KernelHardware").finish()
    }
}

impl KernelHardware for X86KernelHardware {
    type InterruptController = X86InterruptController;
    type PageTableManager = X86PageTableManager;
    type ContextSwitch = X86ContextSwitch;
    type TimerSource = X86TimerSource;
    type CpuFeatures = X86CpuFeatures;
    type EarlyConsole = X86SerialConsole;
    type FrameAllocator = X86FrameAllocatorImpl;

    fn interrupt_controller(&mut self) -> &mut Self::InterruptController {
        &mut self.interrupt_controller
    }

    fn page_table_manager(&mut self) -> &mut Self::PageTableManager {
        &mut self.page_table_manager
    }

    fn context_switch(&mut self) -> &mut Self::ContextSwitch {
        &mut self.context_switch
    }

    fn timer_source(&mut self) -> &mut Self::TimerSource {
        &mut self.timer_source
    }

    fn cpu_features(&self) -> &Self::CpuFeatures {
        &self.cpu_features
    }

    fn early_console(&mut self) -> &mut Self::EarlyConsole {
        &mut self.early_console
    }

    fn frame_allocator(&mut self) -> &mut Self::FrameAllocator {
        &mut self.frame_allocator
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn convert_flags(flags: PageTableFlags) -> x86_64::structures::paging::PageTableFlags {
    let mut x86_flags = x86_64::structures::paging::PageTableFlags::empty();
    if flags.contains(PageTableFlags::PRESENT) { x86_flags |= x86_64::structures::paging::PageTableFlags::PRESENT; }
    if flags.contains(PageTableFlags::WRITABLE) { x86_flags |= x86_64::structures::paging::PageTableFlags::WRITABLE; }
    if flags.contains(PageTableFlags::USER_ACCESSIBLE) { x86_flags |= x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE; }
    if flags.contains(PageTableFlags::WRITE_THROUGH) { x86_flags |= x86_64::structures::paging::PageTableFlags::WRITE_THROUGH; }
    if flags.contains(PageTableFlags::NO_CACHE) { x86_flags |= x86_64::structures::paging::PageTableFlags::NO_CACHE; }
    if flags.contains(PageTableFlags::ACCESSED) { x86_flags |= x86_64::structures::paging::PageTableFlags::ACCESSED; }
    if flags.contains(PageTableFlags::DIRTY) { x86_flags |= x86_64::structures::paging::PageTableFlags::DIRTY; }
    if flags.contains(PageTableFlags::HUGE_PAGE) { x86_flags |= x86_64::structures::paging::PageTableFlags::HUGE_PAGE; }
    if flags.contains(PageTableFlags::GLOBAL) { x86_flags |= x86_64::structures::paging::PageTableFlags::GLOBAL; }
    if flags.contains(PageTableFlags::NO_EXECUTE) { x86_flags |= x86_64::structures::paging::PageTableFlags::NO_EXECUTE; }
    x86_flags
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_cpu_features() {
        let features = X86CpuFeatures::new();
        assert!(!features.vendor().is_empty());
    }

    #[test]
    fn test_serial_console() {
        let mut console = X86SerialConsole::new(0x3F8);
        console.putc(b'A');
        console.putc(b'B');
        console.flush();
    }

    #[test]
    fn test_frame_allocator() {
        let memory_map = [(PhysAddr::new(0x100000), 0x1000000)];
        let mut alloc = X86FrameAllocatorImpl::new(&memory_map);
        assert!(alloc.total_frames() > 0);
        let frame = alloc.alloc();
        assert!(frame.is_some());
    }
}