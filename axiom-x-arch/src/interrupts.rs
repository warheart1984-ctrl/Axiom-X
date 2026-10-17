//! Interrupt Descriptor Table and Exception Handling for Axiom-X x86_64
//!
//! Sets up IDT with handlers for:
//! - Timer interrupt (scheduler tick)
//! - Syscall entry (syscall/sysret)
//! - Page fault (memory management)
//! - General protection fault
//! - Double fault (NMI)
//!
//! Status: `skeleton` — IDT structure defined; handlers need implementation.

use core::arch::asm;
use core::arch::naked_asm;
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use x86_64::registers::control::Cr2;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::VirtAddr;
use spin::Once;
use crate::process::{ProcessTable, context_switch, current_pid};
use axiom_x_math::scheduler_math::{SchedulerState, ProcessMeasurement};

// ============================================================================
// Exception Handlers (using set_handler_fn - safe x86-interrupt ABI)
// ============================================================================

extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    divide_error_handler_impl(&frame)
}

fn divide_error_handler_impl(frame: &InterruptStackFrame) {
    log::error!("DIVIDE ERROR at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Divide error");
}

extern "x86-interrupt" fn debug_handler(frame: InterruptStackFrame) {
    debug_handler_impl(&frame)
}

fn debug_handler_impl(frame: &InterruptStackFrame) {
    log::debug!("DEBUG EXCEPTION at RIP={:#x}", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn nmi_handler(frame: InterruptStackFrame) {
    nmi_handler_impl(&frame)
}

fn nmi_handler_impl(frame: &InterruptStackFrame) {
    log::error!("NMI at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Non-maskable interrupt");
}

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    breakpoint_handler_impl(&frame)
}

fn breakpoint_handler_impl(frame: &InterruptStackFrame) {
    log::debug!("BREAKPOINT at RIP={:#x}", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn overflow_handler(frame: InterruptStackFrame) {
    overflow_handler_impl(&frame)
}

fn overflow_handler_impl(frame: &InterruptStackFrame) {
    log::error!("OVERFLOW at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Overflow");
}

extern "x86-interrupt" fn bound_range_handler(frame: InterruptStackFrame) {
    bound_range_handler_impl(&frame)
}

fn bound_range_handler_impl(frame: &InterruptStackFrame) {
    log::error!("BOUND RANGE EXCEEDED at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Bound range exceeded");
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    invalid_opcode_handler_impl(&frame)
}

fn invalid_opcode_handler_impl(frame: &InterruptStackFrame) {
    log::error!("INVALID OPCODE at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Invalid opcode");
}

extern "x86-interrupt" fn device_not_available_handler(_frame: InterruptStackFrame) {
    unsafe { asm!("clts"); }
}

#[unsafe(naked)]
extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, _error_code: u64) -> ! {
    naked_asm!(
        "mov rdi, rsp",
        "mov rsi, [rsp + 8]",
        "call {handler}",
        handler = sym double_fault_handler_impl,
    );
}

unsafe fn double_fault_handler_impl(frame: &InterruptStackFrame, _error_code: u64) -> ! {
    log::error!("DOUBLE FAULT at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Double fault");
}

#[unsafe(naked)]
extern "x86-interrupt" fn invalid_tss_handler(frame: InterruptStackFrame, error_code: u64) {
    naked_asm!(
        "mov rdi, rsp",
        "mov rsi, [rsp + 8]",
        "call {handler}",
        "iretq",
        handler = sym invalid_tss_handler_impl,
    );
}

unsafe fn invalid_tss_handler_impl(frame: &InterruptStackFrame, error_code: u64) {
    log::error!("INVALID TSS at RIP={:#x}, error={}", frame.instruction_pointer.as_u64(), error_code);
    panic!("Invalid TSS");
}

#[unsafe(naked)]
extern "x86-interrupt" fn segment_not_present_handler(frame: InterruptStackFrame, error_code: u64) {
    naked_asm!(
        "mov rdi, rsp",
        "mov rsi, [rsp + 8]",
        "call {handler}",
        "iretq",
        handler = sym segment_not_present_handler_impl,
    );
}

unsafe fn segment_not_present_handler_impl(frame: &InterruptStackFrame, error_code: u64) {
    log::error!("SEGMENT NOT PRESENT at RIP={:#x}, error={}", frame.instruction_pointer.as_u64(), error_code);
    panic!("Segment not present");
}

extern "x86-interrupt" fn stack_segment_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    stack_segment_fault_handler_impl(&frame, error_code)
}

fn stack_segment_fault_handler_impl(frame: &InterruptStackFrame, error_code: u64) {
    log::error!("STACK SEGMENT FAULT at RIP={:#x}, error={}", frame.instruction_pointer.as_u64(), error_code);
    panic!("Stack segment fault");
}

extern "x86-interrupt" fn general_protection_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    general_protection_fault_handler_impl(&frame, error_code)
}

fn general_protection_fault_handler_impl(frame: &InterruptStackFrame, error_code: u64) {
    if from_user(frame) {
        kill_user_process("general protection fault", frame.instruction_pointer.as_u64(), error_code);
    }
    log::error!("GENERAL PROTECTION FAULT at RIP={:#x}, error={}", frame.instruction_pointer.as_u64(), error_code);
    panic!("General protection fault");
}

/// True when the exception interrupted ring 3.
fn from_user(frame: &InterruptStackFrame) -> bool {
    frame.code_segment.0 & 3 == 3
}

/// A fault in ring 3 is the process's fault, not the kernel's: report it as
/// evidence and end the process with a signal-style code (128 + SIGSEGV).
fn kill_user_process(what: &str, rip: u64, detail: u64) -> ! {
    use core::fmt::Write;
    let _ = writeln!(
        crate::SerialPort,
        "[kernel] pid={} killed: {} in ring 3 at rip={:#x} ({:#x})",
        current_pid(), what, rip, detail
    );
    crate::syscall::end_current_process(128 + 11);
}

extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    page_fault_handler_impl(&frame, error_code)
}

fn page_fault_handler_impl(frame: &InterruptStackFrame, error_code: PageFaultErrorCode) {
    let addr = Cr2::read().unwrap_or(VirtAddr::new(0));
    log::error!(
        "PAGE FAULT at RIP={:#x}, addr={:#x}, error={:?}",
        frame.instruction_pointer.as_u64(),
        addr.as_u64(),
        error_code
    );

    if from_user(frame) {
        kill_user_process("page fault", frame.instruction_pointer.as_u64(), addr.as_u64());
    }
    // Returning would re-execute the faulting kernel instruction forever.
    panic!(
        "kernel page fault at RIP={:#x}, addr={:#x}, error={:?}",
        frame.instruction_pointer.as_u64(),
        addr.as_u64(),
        error_code
    );
}

extern "x86-interrupt" fn x87_floating_point_handler(frame: InterruptStackFrame) {
    x87_floating_point_handler_impl(&frame)
}

fn x87_floating_point_handler_impl(frame: &InterruptStackFrame) {
    log::error!("x87 FP EXCEPTION at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("x87 floating point exception");
}

extern "x86-interrupt" fn alignment_check_handler(frame: InterruptStackFrame, error_code: u64) {
    alignment_check_handler_impl(&frame, error_code)
}

fn alignment_check_handler_impl(frame: &InterruptStackFrame, error_code: u64) {
    log::error!("ALIGNMENT CHECK at RIP={:#x}, error={}", frame.instruction_pointer.as_u64(), error_code);
    panic!("Alignment check");
}

extern "x86-interrupt" fn machine_check_handler(frame: InterruptStackFrame) -> ! {
    machine_check_handler_impl(&frame)
}

fn machine_check_handler_impl(frame: &InterruptStackFrame) -> ! {
    log::error!("MACHINE CHECK at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Machine check");
}

extern "x86-interrupt" fn simd_floating_point_handler(frame: InterruptStackFrame) {
    simd_floating_point_handler_impl(&frame)
}

fn simd_floating_point_handler_impl(frame: &InterruptStackFrame) {
    log::error!("SIMD FP EXCEPTION at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("SIMD floating point exception");
}

extern "x86-interrupt" fn virtualization_handler(frame: InterruptStackFrame) {
    virtualization_handler_impl(&frame)
}

fn virtualization_handler_impl(frame: &InterruptStackFrame) {
    log::error!("VIRTUALIZATION EXCEPTION at RIP={:#x}", frame.instruction_pointer.as_u64());
    panic!("Virtualization exception");
}

// ============================================================================
// IRQ Handlers
// ============================================================================

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    timer_eoi();
    timer_handler_impl();
}

extern "x86-interrupt" fn keyboard_handler(_frame: InterruptStackFrame) {
    unsafe { asm!("out 0x20, al", in("al") 0x20u8); }
}

extern "x86-interrupt" fn mouse_handler(_frame: InterruptStackFrame) {
    unsafe { asm!("out 0xA0, al", in("al") 0x20u8); asm!("out 0x20, al", in("al") 0x20u8); }
}

extern "x86-interrupt" fn ide_handler(_frame: InterruptStackFrame) {
    unsafe { asm!("out 0xA0, al", in("al") 0x20u8); asm!("out 0x20, al", in("al") 0x20u8); }
}

extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {
    // Ignore spurious interrupt
}

fn timer_eoi() {
    unsafe { asm!("out 0x20, al", in("al") 0x20u8); }
}

fn timer_handler_impl() {
    let scheduler = scheduler_mut();
    let table = process_table();

    let mut measurements = heapless::Vec::<ProcessMeasurement, 256>::new();
    table.with_locked(|processes| {
        for (i, proc) in processes.iter().enumerate() {
            if proc.state == crate::process::ProcessState::Runnable
                || proc.state == crate::process::ProcessState::Running
            {
                measurements.push(ProcessMeasurement {
                    index: i,
                    latency_ns: (scheduler.tick * scheduler.core_time_budget_ns).saturating_sub(proc.metrics.total_runtime_ns),
                    dt_ns: scheduler.core_time_budget_ns,
                    instructions_retired: proc.metrics.instructions_retired,
                    cache_misses: proc.metrics.cache_misses,
                    cpu_load: 0.5,
                }).ok();
            }
        }
    });

    let decision = scheduler.tick(&measurements);

    log::debug!(
        "Scheduler tick {}: selected PID={}, slice={}ns, priority={:.2}",
        decision.tick,
        decision.selected_pid,
        decision.time_slice_ns,
        decision.metrics.priority
    );

if !decision.is_idle() && decision.selected_pid != current_pid() {
        context_switch(table, decision.selected_pid);
    }
}
/// Initialize IDT
pub fn init_idt() -> &'static InterruptDescriptorTable {
    IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // Exception handlers (0-31) - no error code
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        idt.x87_floating_point.set_handler_fn(x87_floating_point_handler);
        idt.virtualization.set_handler_fn(virtualization_handler);

        // Exception handlers with error code
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
            idt.invalid_tss.set_handler_fn(invalid_tss_handler);
            idt.segment_not_present.set_handler_fn(segment_not_present_handler);
            idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
            idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
            idt.page_fault.set_handler_fn(page_fault_handler);
            idt.alignment_check.set_handler_fn(alignment_check_handler);
            idt.machine_check.set_handler_fn(machine_check_handler);
            idt.simd_floating_point.set_handler_fn(simd_floating_point_handler);
        }

        // IRQ handlers (32-47) - remapped to 0x20-0x2F
        idt[0x20].set_handler_fn(timer_handler);      // IRQ0 - Timer
        idt[0x21].set_handler_fn(keyboard_handler);   // IRQ1 - Keyboard
        idt[0x24].set_handler_fn(mouse_handler);      // IRQ4 - Mouse (PS/2)
        idt[0x2E].set_handler_fn(ide_handler);        // IRQ14 - Primary IDE

        // int 0x80 system calls. DPL 3 so ring 3 may invoke it; no IST: the
        // CPU switches to TSS.RSP0 on the privilege change.
        unsafe {
            idt[0x80]
                .set_handler_addr(VirtAddr::new(crate::syscall::int80_entry as *const () as u64))
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }

        // Spurious interrupt
        idt[0xFF].set_handler_fn(spurious_handler);

        idt
    });
    let idt = IDT.get().unwrap();
    idt.load();
    idt
}

/// Initialize SYSCALL/SYSRET fast path
pub fn init_syscall() {
    unsafe {
        // STAR: SYSRET base (user data = base+8, user code = base+16) and
        // SYSCALL base (kernel code, kernel data = +8). `write` validates
        // the layout against gdt.rs.
        use x86_64::structures::gdt::SegmentSelector;
        use crate::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS};
        Star::write(
            SegmentSelector(USER_CS),
            SegmentSelector(USER_DS),
            SegmentSelector(KERNEL_CS),
            SegmentSelector(KERNEL_DS),
        )
        .expect("STAR selector layout");

        // LSTAR: syscall entry point (64-bit)
        LStar::write(VirtAddr::new(syscall_entry as u64));

        // SFMASK: RFLAGS mask (clear IF, TF, DF, NT, RF)
        SFMask::write(RFlags::from_bits_truncate(0x0000_0200)); // Clear IF

        // Enable SYSCALL/SYSRET in EFER
        let mut efer = Efer::read();
        efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS); // SCE bit
        Efer::write(efer);
    }
}

/// Get scheduler state (mutable)
pub fn scheduler_mut() -> &'static mut SchedulerState {
    unsafe { SCHEDULER.as_mut().expect("scheduler not initialized") }
}

/// Initialize scheduler
pub fn init_scheduler(max_cores: usize, time_slice_ns: u64) {
    unsafe {
        SCHEDULER = Some(SchedulerState::new(max_cores, time_slice_ns));
    }
}

/// Set process table reference
pub fn set_process_table(table: &'static ProcessTable) {
    unsafe {
        PROCESS_TABLE = Some(table);
    }
}

/// Get process table
pub fn process_table() -> &'static ProcessTable {
    unsafe { PROCESS_TABLE.expect("process table not set") }
}

/// Global IDT instance
static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Global scheduler state
static mut SCHEDULER: Option<SchedulerState> = None;

/// Global process table reference
static mut PROCESS_TABLE: Option<&'static ProcessTable> = None;

/// Schedule next process
pub fn schedule_next() {
    let scheduler = scheduler_mut();
    let table = process_table();
let decision = scheduler.tick(&[]);
    if !decision.is_idle() && decision.selected_pid != current_pid() {
        context_switch(table, decision.selected_pid);
    }
}

/// SYSCALL entry point — Windows/msvc uses the COFF implementation in
/// `context.asm` (ml64). Bare-metal targets (`x86_64-unknown-none`) have no
/// external assembler, so the ELF/System V implementation is inline asm below.
/// The register-frame layout must match `SyscallFrame` exactly.
#[cfg(target_os = "windows")]
unsafe extern "C" {
    pub fn syscall_entry() -> !;
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        // Swap to the kernel GS base, stash the user RSP in the per-CPU area
        // and switch to the kernel stack.
        "swapgs",
        "mov gs:[0], rsp",
        "mov rsp, gs:[8]",
        // Save the register frame (push order must match SyscallFrame).
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rsi",
        "push rdi",
        "push rbp",
        "push rbx",
        "push rdx",
        "push rcx",
        "push rax",
        // Dispatch (System V ABI: frame pointer in RDI).
        "mov rdi, rsp",
        "call {dispatch}",
        // Restore the frame.
        "pop rax",
        "pop rcx",
        "pop rbx",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",
        "swapgs",
        "sysretq",
        dispatch = sym syscall_dispatch,
    );
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
unsafe fn syscall_dispatch(_frame: &SyscallFrame) {
    // TODO: Implement syscall dispatch
    log::debug!("Syscall dispatch");
}

struct SyscallFrame {
    rax: u64, rcx: u64, rdx: u64, rbx: u64,
    rbp: u64, rsi: u64, rdi: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}
