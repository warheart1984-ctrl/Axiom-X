//! Process Management for Axiom-X x86_64
//!
//! Process model: x_i(t) state vector with registers, address space, metrics.
//! Context switch: save/restore CPU context with evidence logging.
//!
//! Status: `skeleton` — core structures defined; assembly stubs TODO.

use core::arch::asm;
use core::arch::naked_asm;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};
use heapless::Vec;
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::VirtAddr;
use axiom_x_math::scheduler_math::{SchedMetrics, SchedProfile};

/// Maximum processes
pub const MAX_PROCESSES: usize = 256;

/// Kernel stack size per process (16 KiB)
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;

/// User stack size (1 MiB default)
pub const DEFAULT_USER_STACK_SIZE: usize = 1024 * 1024;

/// Process states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessState {
    New = 0,
    Runnable = 1,
    Running = 2,
    Blocked = 3,
    Terminated = 4,
}

/// CPU context saved on context switch (x86_64 System V ABI)
/// Matches the layout expected by assembly stubs
#[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::IntoBytes)]
#[repr(C, packed)]
pub struct CpuContext {
    // Callee-saved registers (preserved across function calls)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,

    // Return address (rip at context switch point)
    pub rip: u64,

    // Caller-saved registers (saved by kernel on syscall/interrupt)
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,

    // Stack pointer
    pub rsp: u64,

    // RFLAGS
    pub rflags: u64,

    // Segment registers (usually fixed in long mode)
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,

    // FS/GS base (for thread-local storage)
    pub fs_base: u64,
    pub gs_base: u64,

    // Control registers (for address space switch)
    pub cr3: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            r15: 0, r14: 0, r13: 0, r12: 0, rbx: 0, rbp: 0,
            rip: 0,
            rdi: 0, rsi: 0, rdx: 0, rcx: 0, rax: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            rsp: 0,
            rflags: 0x202, // IF=1, bit 1=1 (reserved)
            cs: 0x08,      // Kernel code segment
            ss: 0x10,      // Kernel data segment
            ds: 0x10, es: 0x10, fs: 0x10, gs: 0x10,
            fs_base: 0, gs_base: 0,
            cr3: 0,
        }
    }
}

impl CpuContext {
    /// Create initial context for a new process
    pub fn new_user(entry: u64, user_stack: u64, cr3: u64) -> Self {
        Self {
            rip: entry,
            rsp: user_stack,
            rflags: 0x202, // IF=1
            cs: crate::gdt::USER_CS, // ring-3 code (0x23)
            ss: crate::gdt::USER_DS, // ring-3 data (0x1B)
            ds: crate::gdt::USER_DS, es: crate::gdt::USER_DS,
            fs: crate::gdt::USER_DS, gs: crate::gdt::USER_DS,
            cr3,
            ..Default::default()
        }
    }

    /// Create initial context for kernel thread
    pub fn new_kernel(entry: u64, kernel_stack: u64, cr3: u64) -> Self {
        Self {
            rip: entry,
            rsp: kernel_stack,
            rflags: 0x202,
            cs: 0x08,
            ss: 0x10,
            ds: 0x10, es: 0x10, fs: 0x10, gs: 0x10,
            cr3,
            ..Default::default()
        }
    }
}

/// Process descriptor (the state vector x_i(t))
#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    pub state: ProcessState,
    pub ctx: CpuContext,
    pub metrics: SchedMetrics,
    pub profile: SchedProfile,
    pub time_slice_ns: u64,
    pub affinity: Option<usize>,

    /// Kernel RSP pointing at this thread's saved `TrapFrame` while it is
    /// not running (see `sched`).
    pub saved_rsp: u64,
    /// While `Blocked` in `nanosleep`: the PIT tick at which to wake (0 = none).
    pub wake_tick: u64,

    // Memory management
    pub page_table_root: PhysFrame<Size4KiB>,
    pub kernel_stack_top: VirtAddr,
    pub user_stack_top: Option<VirtAddr>,

    // File descriptor table (simplified)
    pub fd_table: Vec<FileDescriptor, 64>,

    // Signal handling (simplified)
    pub signal_mask: u64,
    pub pending_signals: u64,

    // Parent/child for waitpid
    pub parent_pid: Option<u32>,
    pub exit_code: Option<i32>,

    // Evidence/logging
    pub last_syscall: Option<SyscallRecord>,

    // Governance
    pub arena_id: &'static str,
    pub authority: &'static str,
    pub intent: &'static str,
}

/// File descriptor (simplified)
#[derive(Debug, Clone, Copy)]
pub struct FileDescriptor {
    pub inode: u64,
    pub flags: u32,
    pub offset: u64,
}

/// Syscall record for evidence
#[derive(Debug, Clone, Copy)]
pub struct SyscallRecord {
    pub number: u64,
    pub args: [u64; 6],
    pub return_value: i64,
    pub timestamp_ns: u64,
}

/// Global process table
///
/// One spinlock over the process slice; lookups scan by PID (at most
/// `MAX_PROCESSES` entries). Every lock is taken with interrupts disabled
/// and released before they are restored: a thread preempted while holding
/// the lock would otherwise deadlock any syscall that needs it, since
/// syscalls run with interrupts off and spin forever.
pub struct ProcessTable {
    next_pid: AtomicU32,
    processes: Mutex<Vec<Process, MAX_PROCESSES>>,
}

/// Disable interrupts, returning whether they were enabled.
#[inline]
fn irq_save() -> bool {
    #[cfg(target_os = "none")]
    {
        let was = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();
        was
    }
    #[cfg(not(target_os = "none"))]
    {
        false
    }
}

#[inline]
fn irq_restore(was_enabled: bool) {
    #[cfg(target_os = "none")]
    if was_enabled {
        x86_64::instructions::interrupts::enable();
    }
    #[cfg(not(target_os = "none"))]
    let _ = was_enabled;
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            next_pid: AtomicU32::new(1),
            processes: Mutex::new(Vec::new()),
        }
    }

    /// Heap-allocate an empty table without building it on the stack first.
    ///
    /// The table is ~MAX_PROCESSES * size_of::<Process>() (hundreds of KiB),
    /// far larger than a boot stack, so `Box::new(Self::new())` overflows it.
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        // SAFETY: all-zero is a valid empty state for every field: AtomicU32
        // (0), spin::Mutex (unlocked), heapless::Vec (len 0, uninit buffer).
        let table = unsafe { alloc::boxed::Box::<Self>::new_zeroed().assume_init() };
        table.next_pid.store(1, Ordering::SeqCst);
        table
    }

    /// Allocate new PID
    pub fn alloc_pid(&self) -> u32 {
        self.next_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// Run `f` on the process vector under the lock, interrupts off.
    fn locked<R>(&self, f: impl FnOnce(&mut Vec<Process, MAX_PROCESSES>) -> R) -> R {
        let irq = irq_save();
        let r = f(&mut self.processes.lock());
        irq_restore(irq);
        r
    }

    /// Add a process to the table
    pub fn add_process(&self, mut proc: Process) -> Result<u32, &'static str> {
        self.locked(|processes| {
            if processes.len() >= MAX_PROCESSES {
                return Err("process table full");
            }
            let pid = self.alloc_pid();
            proc.pid = pid;
            processes.push(proc).map_err(|_| "processes push failed")?;
            Ok(pid)
        })
    }

    /// Get mutable reference to process by PID
    pub fn get_mut(&self, pid: u32) -> Option<ProcessGuard> {
        let irq = irq_save();
        let processes = self.processes.lock();
        match processes.iter().position(|p| p.pid == pid) {
            Some(index) => Some(ProcessGuard { processes: ManuallyDrop::new(processes), index, irq }),
            None => {
                drop(processes);
                irq_restore(irq);
                None
            }
        }
    }

    /// Get process by index (for scheduler)
    pub fn get_by_index(&self, index: usize) -> Option<ProcessGuard> {
        let irq = irq_save();
        let processes = self.processes.lock();
        if index >= processes.len() {
            drop(processes);
            irq_restore(irq);
            return None;
        }
        Some(ProcessGuard { processes: ManuallyDrop::new(processes), index, irq })
    }

    /// Lock the process slice without spinning. Interrupt handlers use this:
    /// if the interrupted code holds the lock, they must back off rather
    /// than deadlock.
    pub fn try_lock_processes(&self) -> Option<spin::MutexGuard<'_, Vec<Process, MAX_PROCESSES>>> {
        self.processes.try_lock()
    }

    /// Get process count
    pub fn count(&self) -> usize {
        self.locked(|p| p.len())
    }

    /// Access all processes under the table lock
    pub fn with_locked<R>(&self, f: impl FnOnce(&[Process]) -> R) -> R {
        self.locked(|p| f(p))
    }

    /// Remove a process record (e.g. a reaped zombie) and return it.
    pub fn remove(&self, pid: u32) -> Option<Process> {
        self.locked(|processes| {
            let index = processes.iter().position(|p| p.pid == pid)?;
            Some(processes.remove(index))
        })
    }
}

/// Guard for process access: holds the table lock with interrupts off;
/// on drop releases the lock first, then restores the interrupt flag.
pub struct ProcessGuard<'a> {
    processes: ManuallyDrop<spin::MutexGuard<'a, Vec<Process, MAX_PROCESSES>>>,
    index: usize,
    irq: bool,
}

impl Drop for ProcessGuard<'_> {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.processes) };
        irq_restore(self.irq);
    }
}

impl<'a> ProcessGuard<'a> {
    pub fn get(&self) -> &Process {
        &self.processes[self.index]
    }

    pub fn get_mut(&mut self) -> &mut Process {
        &mut self.processes[self.index]
    }
}

/// Global current PID (for context switch)
static CURRENT_PID: AtomicU32 = AtomicU32::new(0);

/// Get current PID
pub fn current_pid() -> u32 {
    CURRENT_PID.load(Ordering::SeqCst)
}

/// Set current PID
pub fn set_current_pid(pid: u32) {
    CURRENT_PID.store(pid, Ordering::SeqCst);
}

/// Context switch orchestration
pub fn context_switch(table: &ProcessTable, next_pid: u32) -> ! {
    let current_pid = CURRENT_PID.load(Ordering::SeqCst);

    // Save current context
    if current_pid != 0 && current_pid != next_pid {
        if let Some(mut guard) = table.get_mut(current_pid) {
            let proc = guard.get_mut();
            if proc.state == ProcessState::Running {
                unsafe { save_context(&mut proc.ctx) };
                proc.state = ProcessState::Runnable;
            }
        }
    }

    // Load next context. Copy it out so the table lock is released before
    // jumping: restore_context never returns, and a guard held across it
    // would deadlock the next timer tick in `with_locked`.
    let next = table.get_mut(next_pid).map(|mut guard| {
        let proc = guard.get_mut();
        proc.state = ProcessState::Running;
        (proc.ctx, proc.page_table_root)
    });
    if let Some((ctx, root)) = next {
        CURRENT_PID.store(next_pid, Ordering::SeqCst);

        // Switch address space (CR3)
        unsafe { switch_address_space(root) };

        // Restore context and jump to user/kernel code
        unsafe { restore_context(&ctx) };
    }

    // Should never reach here
    loop {
        unsafe { asm!("hlt") };
    }
}

/// Save current CPU context to `ctx`.
///
/// Windows/msvc targets use the COFF implementation in `context.asm` (ml64),
/// linked via `build.rs`. Bare-metal targets (`x86_64-unknown-none`) have no
/// external assembler available, so the ELF/System V ABI implementation is
/// provided inline as naked functions. `CpuContext` is `#[repr(C, packed)]`
/// with fixed offsets shared by all three implementations.
#[cfg(not(all(target_arch = "x86_64", not(target_os = "windows"))))]
unsafe extern "C" {
    pub fn save_context(ctx: *mut CpuContext);
    pub fn restore_context(ctx: *const CpuContext) -> !;
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[unsafe(naked)]
pub unsafe extern "C" fn save_context(ctx: *mut CpuContext) {
    // System V ABI: first argument in RDI.
    naked_asm!(
        // Callee-saved registers
        "mov [rdi + 0x00], r15",
        "mov [rdi + 0x08], r14",
        "mov [rdi + 0x10], r13",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], rbx",
        "mov [rdi + 0x28], rbp",
        // Return address (pushed by the call) -> rip slot
        "mov rax, [rsp]",
        "mov [rdi + 0x30], rax",
        // Caller-saved registers (values at the scheduling point)
        "mov [rdi + 0x38], rdi",
        "mov [rdi + 0x40], rsi",
        "mov [rdi + 0x48], rdx",
        "mov [rdi + 0x50], rcx",
        "mov [rdi + 0x58], rax",
        "mov [rdi + 0x60], r8",
        "mov [rdi + 0x68], r9",
        "mov [rdi + 0x70], r10",
        "mov [rdi + 0x78], r11",
        // Stack pointer (pointing past the return address)
        "lea rax, [rsp + 8]",
        "mov [rdi + 0x80], rax",
        // RFLAGS
        "pushfq",
        "pop rax",
        "mov [rdi + 0x88], rax",
        // Segment registers
        "mov [rdi + 0x90], cs",
        "mov [rdi + 0x92], ss",
        "mov [rdi + 0x94], ds",
        "mov [rdi + 0x96], es",
        "mov [rdi + 0x98], fs",
        "mov [rdi + 0x9a], gs",
        // FS/GS base (IA32_FS_BASE = 0xC0000100, IA32_GS_BASE = 0xC0000101)
        "mov ecx, 0xC0000100",
        "rdmsr",
        "shl rdx, 32",
        "or rax, rdx",
        "mov [rdi + 0x9c], rax",
        "mov ecx, 0xC0000101",
        "rdmsr",
        "shl rdx, 32",
        "or rax, rdx",
        "mov [rdi + 0xa4], rax",
        // CR3 (address space)
        "mov rax, cr3",
        "mov [rdi + 0xac], rax",
        "ret",
    );
}

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
#[unsafe(naked)]
pub unsafe extern "C" fn restore_context(ctx: *const CpuContext) -> ! {
    naked_asm!(
        // CR3 first: switch address space while still reading from RDI.
        "mov rax, [rdi + 0xac]",
        "mov cr3, rax",
        // FS base
        "mov ecx, 0xC0000100",
        "mov rax, [rdi + 0x9c]",
        "mov rdx, rax",
        "shr rdx, 32",
        "wrmsr",
        // GS base
        "mov ecx, 0xC0000101",
        "mov rax, [rdi + 0xa4]",
        "mov rdx, rax",
        "shr rdx, 32",
        "wrmsr",
        // Segment registers
        "mov ds, word ptr [rdi + 0x94]",
        "mov es, word ptr [rdi + 0x96]",
        "mov fs, word ptr [rdi + 0x98]",
        "mov gs, word ptr [rdi + 0x9a]",
        // Callee-saved registers
        "mov r15, [rdi + 0x00]",
        "mov r14, [rdi + 0x08]",
        "mov r13, [rdi + 0x10]",
        "mov r12, [rdi + 0x18]",
        "mov rbx, [rdi + 0x20]",
        "mov rbp, [rdi + 0x28]",
        // Caller-saved registers (RDI kept as ctx pointer until last)
        "mov r11, [rdi + 0x78]",
        "mov r10, [rdi + 0x70]",
        "mov r9, [rdi + 0x68]",
        "mov r8, [rdi + 0x60]",
        "mov rax, [rdi + 0x58]",
        "mov rcx, [rdi + 0x50]",
        "mov rdx, [rdi + 0x48]",
        "mov rsi, [rdi + 0x40]",
        // Switch to the target stack, then build the IRETQ frame on it.
        // iretq pops RIP, CS, RFLAGS, RSP, SS (in that order).
        "mov rsp, [rdi + 0x80]",
        "movzx rax, word ptr [rdi + 0x92]",
        "push rax",
        "mov rax, [rdi + 0x80]",
        "push rax",
        "mov rax, [rdi + 0x88]",
        "push rax",
        "movzx rax, word ptr [rdi + 0x90]",
        "push rax",
        "mov rax, [rdi + 0x30]",
        "push rax",
        "mov rdi, [rdi + 0x38]",
        "iretq",
    );
}
#[inline]
unsafe fn switch_address_space(root: PhysFrame<Size4KiB>) {
    Cr3::write(root, Cr3::read().1);
}

/// Initialize process for first run (kernel thread)
pub fn init_kernel_process(
    table: &ProcessTable,
    entry: u64,
    stack_top: VirtAddr,
    page_table_root: PhysFrame<Size4KiB>,
) -> Result<u32, &'static str> {
    let ctx = CpuContext::new_kernel(entry, stack_top.as_u64(), page_table_root.start_address().as_u64());
    let proc = Process {
        pid: 0, // Will be set by add_process
        state: ProcessState::New,
        ctx,
        metrics: SchedMetrics::default(),
        profile: SchedProfile::Batch,
        time_slice_ns: 10_000_000,
        affinity: Some(0),
        saved_rsp: 0,
        wake_tick: 0,
        page_table_root,
        kernel_stack_top: stack_top,
        user_stack_top: None,
        fd_table: Vec::new(),
        signal_mask: 0,
        pending_signals: 0,
        parent_pid: None,
        exit_code: None,
        last_syscall: None,
        arena_id: "system",
        authority: "kernel-root",
        intent: "kernel-init",
    };
    table.add_process(proc)
}

/// Initialize user process
pub fn init_user_process(
    table: &ProcessTable,
    entry: u64,
    user_stack_top: VirtAddr,
    kernel_stack_top: VirtAddr,
    page_table_root: PhysFrame<Size4KiB>,
) -> Result<u32, &'static str> {
    let ctx = CpuContext::new_user(entry, user_stack_top.as_u64(), page_table_root.start_address().as_u64());
    let proc = Process {
        pid: 0,
        state: ProcessState::New,
        ctx,
        metrics: SchedMetrics::default(),
        profile: SchedProfile::Interactive,
        time_slice_ns: 5_000_000,
        affinity: Some(0),
        saved_rsp: 0,
        wake_tick: 0,
        page_table_root,
        kernel_stack_top,
        user_stack_top: Some(user_stack_top),
        fd_table: Vec::new(),
        signal_mask: 0,
        pending_signals: 0,
        parent_pid: None,
        exit_code: None,
        last_syscall: None,
        arena_id: "user",
        authority: "user-default",
        intent: "user-process",
    };
    table.add_process(proc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_context_default() {
        let ctx = CpuContext::default();
        assert_eq!(ctx.rflags, 0x202);
        assert_eq!(ctx.cs, 0x08);
    }

    #[test]
    fn test_cpu_context_user() {
        let ctx = CpuContext::new_user(0x400000, 0x7FFFFFFFFFFF, 0x100000);
        assert_eq!(ctx.rip, 0x400000);
        assert_eq!(ctx.rsp, 0x7FFFFFFFFFFF);
        // sysret layout: user data at 0x18, user code at 0x20 (RPL 3).
        assert_eq!({ ctx.cs }, 0x23);
        assert_eq!({ ctx.ss }, 0x1B);
    }

    #[test]
    fn test_cpu_context_kernel() {
        let ctx = CpuContext::new_kernel(0xFFFF800000000000, 0xFFFF800000100000, 0x100000);
        assert_eq!(ctx.rip, 0xFFFF800000000000);
        assert_eq!(ctx.cs, 0x08);
    }

    #[test]
    fn test_process_table() {
        let table = ProcessTable::new();
        assert_eq!(table.count(), 0);

        let ctx = CpuContext::default();
        let proc = Process {
            pid: 0,
            state: ProcessState::New,
            ctx,
            metrics: SchedMetrics::default(),
            profile: SchedProfile::Batch,
            time_slice_ns: 10_000_000,
            affinity: Some(0),
            page_table_root: PhysFrame::containing_address(x86_64::PhysAddr::new(0x100000)),
            kernel_stack_top: VirtAddr::new(0xFFFF800000100000),
            user_stack_top: None,
            fd_table: Vec::new(),
            signal_mask: 0,
            pending_signals: 0,
            parent_pid: None,
            exit_code: None,
            last_syscall: None,
        };

        let pid = table.add_process(proc).unwrap();
        assert_eq!(pid, 1);
        assert_eq!(table.count(), 1);

        let mut guard = table.get_mut(pid).unwrap();
        assert_eq!(guard.get().pid, pid);
        assert_eq!(guard.get().state, ProcessState::New);

        guard.get_mut().state = ProcessState::Runnable;
        drop(guard);

        let guard = table.get_mut(pid).unwrap();
        assert_eq!(guard.get().state, ProcessState::Runnable);
    }

    #[test]
    fn test_pid_allocation() {
        let table = ProcessTable::new();
        let pid1 = table.alloc_pid();
        let pid2 = table.alloc_pid();
        assert_eq!(pid2, pid1 + 1);
    }
}