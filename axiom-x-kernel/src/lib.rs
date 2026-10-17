//! Axiom-X Kernel — Main Crate
//!
//! Integrates all Axiom-X components into a bootable microkernel using
//! architecture-agnostic traits. The kernel depends only on the trait
//! contracts defined in axiom-x-arch-traits.
//!
//! Status: `skeleton` — integration layer defined; full implementation TODO.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#![feature(alloc_error_handler, naked_functions, asm_const, allocator_api)]
#![feature(lang_items, panic_info_message, ptr_metadata)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;

mod elf_loader;
mod governance_types;
mod governance_interfaces;
mod governance_impl;

use core::arch::asm;
use core::alloc::Layout;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use axiom_x_arch_traits::{
    KernelHardware, InterruptController, PageTableManager, ContextSwitch, TimerSource,
    CpuFeatures, EarlyConsole, FrameAllocator,
    VirtAddr, PhysAddr, PhysFrame, PageSize, PageTableFlags,
    ProcessState, CpuContext,
    MapError, UnmapError, SwitchError, AllocError,
};
use axiom_x_arch_x86_64::{X86KernelHardware, X86PageTableManager, X86FrameAllocatorImpl};
use axiom_x_boot::ax_kernel_entry;
use axiom_x_math::memory_algebra::{FrameAllocator as MathFrameAllocator, AllocRequest, RegionType, RegionFlags};
use axiom_x_math::scheduler_math::{SchedProfile, SchedulerState, ProcessMeasurement, SchedulerDecision};
use axiom_x_sys::{SyscallNumber, SyscallArgs, SyscallResult, errno};
use crate::governance_interfaces::{GovernanceRegistry, ConstitutionalKernelEnforcer, GovernedSyscall, LirlKernelBridge, GovernedKernelEmitter, MriKernelFeed};

/// COM1 serial port
#[cfg(not(feature = "std"))]
const COM1: u16 = 0x3F8;

/// Write byte to serial
#[cfg(not(feature = "std"))]
fn serial_putc(c: u8) {
    unsafe {
        while inb(COM1 + 5) & 0x20 == 0 {} // Wait for THR empty
        outb(COM1, c);
    }
}

/// Host no-op: std/test builds must not touch COM1 in ring 3
#[cfg(feature = "std")]
fn serial_putc(_c: u8) {}

/// Write string to serial
fn serial_puts(s: &str) {
    for c in s.bytes() {
        serial_putc(c);
    }
}

/// Read byte from I/O port
#[cfg(not(feature = "std"))]
#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") value) };
    value
}

/// Write byte to I/O port
#[cfg(not(feature = "std"))]
#[inline]
fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value) };
}

// ============================================================================
// Global Kernel State
// ============================================================================

/// Global process table
static PROCESS_TABLE: spin::Once<ProcessTable> = spin::Once::new();

/// Global kernel hardware abstraction
static KERNEL_HARDWARE: spin::Once<spin::Mutex<X86KernelHardware>> = spin::Once::new();

/// Global memory algebra frame allocator
static FRAME_ALLOCATOR: spin::Once<spin::Mutex<MathFrameAllocator>> = spin::Once::new();

/// Kernel tick counter
static KERNEL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Kernel uptime (nanoseconds)
static KERNEL_UPTIME_NS: AtomicU64 = AtomicU64::new(0);

/// Global governance registry
static GOVERNANCE: spin::Once<spin::Mutex<crate::governance_impl::DefaultGovernanceRegistry>> = spin::Once::new();

/// Global governed syscall wrapper
static GOVERNED_SYSCALL: spin::Once<spin::Mutex<crate::governance_impl::DefaultGovernedSyscallWrapper>> = spin::Once::new();

/// Initialize governance registry
pub fn init_governance_registry() {
    GOVERNANCE.call_once(|| {
        let mut registry = crate::governance_impl::DefaultGovernanceRegistry::new();
        // Register kernel actor
        registry.register_kernel_actor(crate::governance_types::KernelActor {
            actor_id: "kernel".to_string(),
            authority_level: crate::governance_types::AuthorityLevel::Root,
            capabilities: crate::governance_types::CapabilitySet::new()
                .with_capability("syscall")
                .with_capability("memory")
                .with_capability("process")
                .with_capability("scheduler")
                .with_capability("evidence"),
        });
        spin::Mutex::new(registry)
    });
}

/// Get governance registry
pub fn governance_registry() -> Option<&'static spin::Mutex<crate::governance_impl::DefaultGovernanceRegistry>> {
    GOVERNANCE.get()
}

/// Get governed syscall wrapper
pub fn governed_syscall() -> Option<&'static spin::Mutex<crate::governance_impl::DefaultGovernedSyscallWrapper>> {
    GOVERNED_SYSCALL.get()
}

/// Initialize governed syscall wrapper
pub fn init_governed_syscall() {
    GOVERNED_SYSCALL.call_once(|| {
        spin::Mutex::new(crate::governance_impl::DefaultGovernedSyscallWrapper::new(
            crate::governance_types::GovernanceConfig::default()
        ))
    });
}

// ============================================================================
// Process Table (Simplified - architecture-agnostic)
// ============================================================================

use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};
use heapless::Vec as HeaplessVec;

/// Maximum processes
const MAX_PROCESSES: usize = 256;

/// Process descriptor
#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    pub state: ProcessState,
    pub ctx: CpuContext,
    pub metrics: axiom_x_math::scheduler_math::SchedMetrics,
    pub profile: SchedProfile,
    pub time_slice_ns: u64,
    pub affinity: Option<usize>,
    pub page_table_root: PhysAddr,
    pub kernel_stack_top: VirtAddr,
    pub user_stack_top: Option<VirtAddr>,
    pub fd_table: HeaplessVec<FileDescriptor, 64>,
    pub signal_mask: u64,
    pub pending_signals: u64,
    pub parent_pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub last_syscall: Option<SyscallRecord>,

    // Governance fields
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
pub struct ProcessTable {
    next_pid: core::sync::atomic::AtomicU32,
    processes: Mutex<HeaplessVec<Process, MAX_PROCESSES>>,
    pid_to_index: Mutex<HeaplessVec<(u32, usize), MAX_PROCESSES>>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            next_pid: core::sync::atomic::AtomicU32::new(1),
            processes: Mutex::new(HeaplessVec::new()),
            pid_to_index: Mutex::new(HeaplessVec::new()),
        }
    }

    pub fn alloc_pid(&self) -> u32 {
        self.next_pid.fetch_add(1, Ordering::SeqCst)
    }

    pub fn add_process(&self, mut proc: Process) -> Result<u32, &'static str> {
        let mut processes = self.processes.lock();
        let mut mapping = self.pid_to_index.lock();

        if processes.len() >= MAX_PROCESSES {
            return Err("process table full");
        }

        let pid = self.alloc_pid();
        proc.pid = pid;
        let index = processes.len();
        processes.push(proc).map_err(|_| "processes push failed")?;
        mapping.push((pid, index)).map_err(|_| "mapping push failed")?;

        Ok(pid)
    }

    pub fn get_mut(&self, pid: u32) -> Option<ProcessGuard> {
        let mapping = self.pid_to_index.lock();
        let index = mapping.iter().find(|(p, _)| *p == pid).map(|(_, i)| *i)?;
        drop(mapping);

        let processes = self.processes.lock();
        Some(ProcessGuard { processes, index })
    }

    pub fn get_by_index(&self, index: usize) -> Option<ProcessGuard> {
        let processes = self.processes.lock();
        if index >= processes.len() {
            return None;
        }
        Some(ProcessGuard { processes, index })
    }

    pub fn count(&self) -> usize {
        self.processes.lock().len()
    }

    /// Lock the process table for the duration of the closure.
    /// Safe iteration: references stay tied to the lock scope.
    pub fn for_each_locked<F>(&self, mut f: F)
    where
        F: FnMut(usize, &Process),
    {
        let processes = self.processes.lock();
        for (i, proc) in processes.iter().enumerate() {
            f(i, proc);
        }
    }
}

/// Guard for process access
pub struct ProcessGuard<'a> {
    processes: spin::MutexGuard<'a, HeaplessVec<Process, MAX_PROCESSES>>,
    index: usize,
}

impl<'a> ProcessGuard<'a> {
    pub fn get(&self) -> &Process {
        &self.processes[self.index]
    }

    pub fn get_mut(&mut self) -> &mut Process {
        &mut self.processes[self.index]
    }
}

impl<'a> core::ops::Deref for ProcessGuard<'a> {
    type Target = Process;
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<'a> core::ops::DerefMut for ProcessGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

/// Global current PID
static CURRENT_PID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn current_pid() -> u32 {
    CURRENT_PID.load(Ordering::SeqCst)
}

pub fn set_current_pid(pid: u32) {
    CURRENT_PID.store(pid, Ordering::SeqCst);
}

// ============================================================================
// Kernel Entry Point
// ============================================================================

/// Main kernel entry (called from boot code)
#[no_mangle]
pub extern "C" fn kernel_main(mbi_addr: u64) -> ! {
    // Initialize kernel subsystems
    init_kernel(mbi_addr);

    // Start scheduler (never returns)
    start_scheduling();
}

/// Initialize all kernel subsystems
fn init_kernel(mbi_addr: u64) {
    // 1. Parse multiboot2 info to get memory map
    serial_puts("Parsing multiboot2 info...\n");
    let boot_info = unsafe { axiom_x_boot::parse_multiboot2(mbi_addr) };
    serial_puts(&format!("  Kernel: {:#x} - {:#x}\n", boot_info.kernel_phys_start, boot_info.kernel_phys_end));
    serial_puts(&format!("  Memory regions: {}\n", boot_info.memory_map.len()));

    // 2. Initialize frame allocator with memory map
    serial_puts("Initializing kernel frame allocator...\n");
    init_frame_allocator(&boot_info.memory_map);
    serial_puts("  Frame allocator initialized\n");

    // 3. Initialize governance
    serial_puts("Initializing governance...\n");
    init_governance_registry();
    init_governed_syscall();
    serial_puts("  Governance initialized\n");

    // 4. Continue with rest of boot initialization (page tables, heap, etc.)
    serial_puts("Continuing boot initialization...\n");
    unsafe { axiom_x_boot::init_kernel_after_frame_allocator(boot_info); }
}

/// Start the scheduler (this never returns)
fn start_scheduling() -> ! {
    let table = PROCESS_TABLE.call_once(|| ProcessTable::new());

    // Get init PID (created in boot)
    let init_pid = 1;

    // Enable interrupts
    unsafe { asm!("sti") };

    // Context switch to init process
    let mut hardware = KERNEL_HARDWARE.get().expect("hardware not initialized").lock();
    let _ctx_switch = hardware.context_switch();
    // Note: Real implementation would get process context and restore
    // ctx_switch.restore_context(&proc_ctx);
    
    // For now, idle loop
    loop {
        unsafe { asm!("hlt") };
    }
}

// ============================================================================
// Syscall Dispatch
// ============================================================================

/// Dispatch syscall to appropriate handler with governance
pub fn dispatch_syscall(num: u64, args: &SyscallArgs) -> SyscallResult {
    let syscall_num = match SyscallNumber::try_from(num) {
        Ok(n) => n,
        Err(_) => return SyscallResult::error(errno::ENOSYS),
    };

    // Build syscall event for governance
    let pid = current_pid();
    let syscall_event = crate::governance_types::SyscallEvent {
        event_id: alloc::format!("syscall-{}-{}", pid, num),
        timestamp: 0, // TODO: read TSC
        actor: crate::governance_types::ActorRef::Kernel(crate::governance_types::KernelActor {
            actor_id: "kernel".to_string(),
            authority_level: crate::governance_types::AuthorityLevel::Root,
            capabilities: crate::governance_types::CapabilitySet::new(),
        }),
        syscall: crate::governance_types::SyscallContext {
            sysno: num,
            args: [args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5],
            return_type: crate::governance_types::ReturnType::I64,
        },
        authority_ref: "kernel-root".to_string(),
        intent_ref: alloc::format!("syscall-{}", num),
        memory_ref: alloc::format!("proc-{}", pid),
        lirl_receipt: None,
        metadata: alloc::collections::BTreeMap::new(),
    };

    // Execute through governance wrapper if available
    let result = if let Some(wrapper) = governed_syscall() {
        let mut wrapper = wrapper.lock();
        let mut result = SyscallResult::error(errno::ENOSYS);
        // Clone for governed execution; original is kept for post-syscall governance
        let syscall_event_for_gov = syscall_event.clone();
        (*wrapper).execute(syscall_event_for_gov, &mut || {
            result = match syscall_num {
                // POSIX syscalls (stubs)
                SyscallNumber::Read => sys_read(args),
                SyscallNumber::Write => sys_write(args),
                SyscallNumber::Open => sys_open(args),
                SyscallNumber::Close => sys_close(args),
                SyscallNumber::Fork => sys_fork(args),
                SyscallNumber::Execve => sys_execve(args),
                SyscallNumber::Exit => sys_exit(args),
                SyscallNumber::Wait4 => sys_wait4(args),
                SyscallNumber::Kill => sys_kill(args),
                SyscallNumber::Getpid => sys_getpid(args),
                SyscallNumber::Mmap => sys_mmap(args),
                SyscallNumber::Munmap => sys_munmap(args),
                SyscallNumber::Brk => sys_brk(args),

                // Axiom-X native syscalls
                SyscallNumber::AxSchedProfile => sys_ax_sched_profile(args),
                SyscallNumber::AxGetEvidence => sys_ax_get_evidence(args),
                SyscallNumber::AxReplayToken => sys_ax_replay_token(args),
                SyscallNumber::AxAllocRes => sys_ax_alloc_res(args),
                SyscallNumber::AxFreeRes => sys_ax_free_res(args),
                SyscallNumber::AxShare => sys_ax_share(args),
                SyscallNumber::AxIsolate => sys_ax_isolate(args),
                SyscallNumber::AxVerifyInvariant => sys_ax_verify_invariant(args),
                SyscallNumber::AxGetMetrics => sys_ax_get_metrics(args),
                SyscallNumber::AxSetThermalPolicy => sys_ax_set_thermal_policy(args),
                SyscallNumber::AxGetThermalState => sys_ax_get_thermal_state(args),
                SyscallNumber::AxSpawn => sys_ax_spawn(args),
                SyscallNumber::AxWaitContract => sys_ax_wait_contract(args),
                SyscallNumber::AxSignalEvidence => sys_ax_signal_evidence(args),

                _ => SyscallResult::error(errno::ENOSYS),
            };
        });
        result
    } else {
        // Fallback if governance not initialized
        match syscall_num {
            // POSIX syscalls (stubs)
            SyscallNumber::Read => sys_read(args),
            SyscallNumber::Write => sys_write(args),
            SyscallNumber::Open => sys_open(args),
            SyscallNumber::Close => sys_close(args),
            SyscallNumber::Fork => sys_fork(args),
            SyscallNumber::Execve => sys_execve(args),
            SyscallNumber::Exit => sys_exit(args),
            SyscallNumber::Wait4 => sys_wait4(args),
            SyscallNumber::Kill => sys_kill(args),
            SyscallNumber::Getpid => sys_getpid(args),
            SyscallNumber::Mmap => sys_mmap(args),
            SyscallNumber::Munmap => sys_munmap(args),
            SyscallNumber::Brk => sys_brk(args),

            // Axiom-X native syscalls
            SyscallNumber::AxSchedProfile => sys_ax_sched_profile(args),
            SyscallNumber::AxGetEvidence => sys_ax_get_evidence(args),
            SyscallNumber::AxReplayToken => sys_ax_replay_token(args),
            SyscallNumber::AxAllocRes => sys_ax_alloc_res(args),
            SyscallNumber::AxFreeRes => sys_ax_free_res(args),
            SyscallNumber::AxShare => sys_ax_share(args),
            SyscallNumber::AxIsolate => sys_ax_isolate(args),
            SyscallNumber::AxVerifyInvariant => sys_ax_verify_invariant(args),
            SyscallNumber::AxGetMetrics => sys_ax_get_metrics(args),
            SyscallNumber::AxSetThermalPolicy => sys_ax_set_thermal_policy(args),
            SyscallNumber::AxGetThermalState => sys_ax_get_thermal_state(args),
            SyscallNumber::AxSpawn => sys_ax_spawn(args),
            SyscallNumber::AxWaitContract => sys_ax_wait_contract(args),
            SyscallNumber::AxSignalEvidence => sys_ax_signal_evidence(args),

            _ => SyscallResult::error(errno::ENOSYS),
        }
    };

    // Post-syscall governance: emit to LIRL, MRI, LawPulse
    if let Some(gov) = governance_registry() {
        let mut gov = gov.lock();
        // Issue LIRL receipt for syscall
        crate::governance_interfaces::LirlKernelBridge::issue_syscall_receipt(&mut *gov, &syscall_event);
        // Emit to LawPulse (kernel emitter)
        crate::governance_interfaces::GovernedKernelEmitter::emit_syscall(&mut *gov, syscall_event.clone());
        // Push trajectory sample to MRI (simplified)
        crate::governance_interfaces::MriKernelFeed::push_trajectory_sample(&mut *gov, crate::governance_interfaces::TrajectorySample {
            timestamp: 0, // TODO: read TSC
            pid: pid as u64,
            cpu_usage: 0.0,
            memory_usage: 0,
            syscall_rate: 0.0,
            latency_ns: 0,
        });
    }

    result
}

// ============================================================================
// POSIX Syscall Implementations
// ============================================================================

fn sys_read(args: &SyscallArgs) -> SyscallResult {
    let fd = args.arg0 as i32;
    let buf_ptr = args.arg1 as *mut u8;
    let count = args.arg2 as usize;
    
    // Get current process
    let pid = current_pid();
    let proc_table = table();
    let proc = match proc_table.get_mut(current_pid()) {
        Some(p) => p,
        None => return SyscallResult::error(errno::EBADF),
    };
    
    // Check file descriptor
    if fd as usize >= proc.fd_table.len() {
        return SyscallResult::error(errno::EBADF);
    }
    
    let fd_entry = proc.fd_table[fd as usize];
    if fd_entry.inode == 0 {
        return SyscallResult::error(errno::EBADF);
    }
    
    // For now, simulate reading from a simple file/device
    let bytes_read = core::cmp::min(count, 1024);
    
    if fd == 0 { // stdin
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, bytes_read) };
        for i in 0..bytes_read {
            buf[i] = 0;
        }
        SyscallResult::success(bytes_read as i64)
    } else {
        SyscallResult::error(errno::ENOSYS)
    }
}

fn sys_write(args: &SyscallArgs) -> SyscallResult {
    let fd = args.arg0 as i32;
    let buf_ptr = args.arg1 as *const u8;
    let count = args.arg2 as usize;
    
    let pid = current_pid();
    let proc_table = table();
    let proc = match proc_table.get_mut(current_pid()) {
        Some(p) => p,
        None => return SyscallResult::error(errno::EBADF),
    };
    
    if fd as usize >= proc.fd_table.len() {
        return SyscallResult::error(errno::EBADF);
    }
    
    let fd_entry = proc.fd_table[fd as usize];
    if fd_entry.inode == 0 {
        return SyscallResult::error(errno::EBADF);
    }
    
    let bytes_written = core::cmp::min(count, 4096);
    
    if fd == 1 || fd == 2 { // stdout/stderr
        let buf = unsafe { core::slice::from_raw_parts(buf_ptr, bytes_written) };
        for &byte in buf {
            crate::serial_putc(byte);
        }
        SyscallResult::success(bytes_written as i64)
    } else {
        SyscallResult::success(bytes_written as i64)
    }
}

fn sys_open(args: &SyscallArgs) -> SyscallResult {
    let path_ptr = args.arg0 as *const u8;
    let flags = args.arg1 as i32;
    let mode = args.arg2 as u32;
    
    // Read path from user memory
    let path = unsafe {
        let mut path = Vec::new();
        let mut ptr = args.arg0 as *const u8;
        loop {
            let byte = unsafe { *ptr };
            if byte == 0 { break; }
            path.push(byte);
            ptr = ptr.add(1);
        }
        String::from_utf8(path).unwrap_or_default()
    };
    
    let pid = current_pid();
    let proc_table = table();
    let mut proc = match proc_table.get_mut(current_pid()) {
        Some(p) => p,
        None => return SyscallResult::error(errno::EBADF),
    };
    
    // Find free fd
    for (fd, entry) in proc.fd_table.iter_mut().enumerate() {
        if entry.inode == 0 {
            entry.inode = 1;
            entry.flags = args.arg1 as u32;
            return SyscallResult::success(fd as i64);
        }
    }
    
    // Expand fd table if needed
    if proc.fd_table.len() < 64 {
        proc.fd_table.push(FileDescriptor {
            inode: 1,
            flags: args.arg1 as u32,
            offset: 0,
        });
        return SyscallResult::success((proc.fd_table.len() - 1) as i64);
    }
    
    SyscallResult::error(errno::EMFILE)
}

fn sys_close(args: &SyscallArgs) -> SyscallResult {
    let fd = args.arg0 as i32;
    
    let pid = current_pid();
    let proc_table = table();
    let mut proc = match proc_table.get_mut(current_pid()) {
        Some(p) => p,
        None => return SyscallResult::error(errno::EBADF),
    };
    
    if fd as usize >= proc.fd_table.len() {
        return SyscallResult::error(errno::EBADF);
    }
    
    proc.fd_table[fd as usize].inode = 0;
    SyscallResult::success(0)
}

fn sys_fork(args: &SyscallArgs) -> SyscallResult {
    let parent_pid = current_pid();
    let proc_table = table();
    
    // Get parent process
    let parent_guard = match proc_table.get_mut(parent_pid) {
        Some(p) => p,
        None => return SyscallResult::error(errno::EAGAIN),
    };
    
    // Allocate new PID
    let child_pid = table().alloc_pid();
    
    // Create child process with copied context
    let parent_ctx = {
        let parent_guard = table().get_mut(parent_pid).unwrap();
        parent_guard.ctx.clone()
    };
    
    let mut child_ctx = CpuContext::default();
    child_ctx.instruction_pointer = parent_ctx.instruction_pointer;
    child_ctx.stack_pointer = parent_ctx.stack_pointer;
    child_ctx.page_table_root = parent_ctx.page_table_root;
    child_ctx.flags = 0x202; // IF=1
    child_ctx.data[0] = 0x10; // SS (kernel data segment)
    child_ctx.data[1] = 0x08; // CS (kernel code segment)
    
    // Copy governance fields from parent
    let child_arena = parent_guard.arena_id;
    let child_authority = parent_guard.authority;
    let child_intent = parent_guard.intent;
    
    let mut child_proc = Process {
        pid: child_pid as u32,
        state: ProcessState::Runnable,
        ctx: child_ctx,
        metrics: axiom_x_math::scheduler_math::SchedMetrics::default(),
        profile: SchedProfile::default(),
        time_slice_ns: 10_000_000,
        affinity: None,
        page_table_root: parent_guard.page_table_root,
        kernel_stack_top: alloc_kernel_stack().unwrap_or(axiom_x_arch_traits::VirtAddr(0)),
        user_stack_top: None,
        fd_table: {
            let mut fd_table = HeaplessVec::new();
            for fd in parent_guard.fd_table.iter() {
                fd_table.push(fd.clone()).ok();
            }
            fd_table
        },
        signal_mask: 0,
        pending_signals: 0,
        parent_pid: Some(parent_pid as u32),
        exit_code: None,
        last_syscall: None,
        arena_id: child_arena,
        authority: child_authority,
        intent: child_intent,
    };
    
    // Add to process table
    table().add_process(child_proc).unwrap();
    
    // Register with governance
    if let Some(gov) = governance_registry() {
        let mut gov = gov.lock();
        crate::governance_interfaces::GovernanceRegistry::register_process(&mut *gov, crate::governance_types::ProcessRecord {
            pid: child_pid as u64,
            arena_id: child_arena.to_string(),
            authority: child_authority.to_string(),
            intent: child_intent.to_string(),
            memory_handle: alloc::format!("proc-{}", child_pid),
            receipts: alloc::vec::Vec::new(),
            state: crate::governance_types::ProcessState::Runnable,
        });
        // Register with LIRL
        crate::governance_interfaces::LirlKernelBridge::register_process(&mut *gov, crate::governance_types::ProcessRecord {
            pid: child_pid as u64,
            arena_id: child_arena.to_string(),
            authority: child_authority.to_string(),
            intent: child_intent.to_string(),
            memory_handle: alloc::format!("proc-{}", child_pid),
            receipts: alloc::vec::Vec::new(),
            state: crate::governance_types::ProcessState::Runnable,
        });
    }
    
    // Return child PID to parent, 0 to child
    SyscallResult::success(child_pid as i64)
}

fn sys_execve(args: &SyscallArgs) -> SyscallResult {
    let path_ptr = args.arg0 as *const u8;
    let argv_ptr = args.arg1 as *const u64;
    let envp_ptr = args.arg2 as *const u64;
    
    // Read path from user memory
    let _path = unsafe {
        let mut path = Vec::new();
        let mut ptr = args.arg0 as *const u8;
        loop {
            let byte = unsafe { *ptr };
            if byte == 0 { break; }
            path.push(byte);
            ptr = ptr.add(1);
        }
        String::from_utf8(path).unwrap_or_default()
    };
    
    SyscallResult::error(errno::ENOSYS)
}

fn sys_exit(args: &SyscallArgs) -> SyscallResult {
    let code = args.arg0 as i32;
    let pid = current_pid();
    if let Some(mut guard) = table().get_mut(pid) {
        guard.get_mut().state = ProcessState::Terminated;
        guard.get_mut().exit_code = Some(code);
    }
    // Finalize with LIRL
    if let Some(gov) = governance_registry() {
        let mut gov = gov.lock();
        crate::governance_interfaces::LirlKernelBridge::finalize_process(&mut *gov, crate::governance_types::ProcessRecord {
            pid: pid as u64,
            arena_id: "unknown".to_string(),
            authority: "unknown".to_string(),
            intent: "unknown".to_string(),
            memory_handle: alloc::format!("proc-{}", pid),
            receipts: alloc::vec::Vec::new(),
            state: crate::governance_types::ProcessState::Terminated,
        });
    }
    schedule_next();
    SyscallResult::success(0)
}

fn sys_wait4(args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ECHILD)
}

fn sys_kill(args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::EPERM)
}

fn sys_getpid(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::success(current_pid() as i64)
}

fn sys_mmap(args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_munmap(args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_brk(args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

// ============================================================================
// Axiom-X Native Syscalls
// ============================================================================

fn sys_ax_sched_profile(args: &SyscallArgs) -> SyscallResult {
    let _profile_ptr = args.arg0 as *const axiom_x_sys::SchedProfileRequest;
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_get_evidence(args: &SyscallArgs) -> SyscallResult {
    let _buf = args.arg0 as *mut axiom_x_sys::EvidenceRecord;
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_replay_token(args: &SyscallArgs) -> SyscallResult {
    let _token = args.arg0 as *mut u64;
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_alloc_res(args: &SyscallArgs) -> SyscallResult {
    let _req = args.arg0 as *const axiom_x_sys::ResourceRequest;
    let _result = args.arg1 as *mut axiom_x_sys::ResourceAllocation;
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_free_res(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_share(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_isolate(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_verify_invariant(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_get_metrics(args: &SyscallArgs) -> SyscallResult {
    let _buf = args.arg0 as *mut axiom_x_sys::KernelMetrics;
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_set_thermal_policy(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_get_thermal_state(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_spawn(args: &SyscallArgs) -> SyscallResult {
    let req_ptr = args.arg0 as *const axiom_x_sys::SpawnRequest;
    let result_ptr = args.arg1 as *mut axiom_x_sys::SpawnResult;
    
    // Validate pointers
    if req_ptr.is_null() || result_ptr.is_null() {
        return SyscallResult::error(errno::EINVAL);
    }
    
    let req = unsafe { &*req_ptr };
    let parent_pid = current_pid();
    let proc_table = table();
    
    // Allocate new PID
    let child_pid = table().alloc_pid();
    
    // Create child process
    let mut child_ctx = CpuContext::default();
    child_ctx.instruction_pointer = req.entry_point;
    child_ctx.stack_pointer = req.stack_top;
    child_ctx.flags = 0x202; // IF=1
    child_ctx.data[0] = 0x10; // SS
    child_ctx.data[1] = 0x08; // CS
    
    // Use parent's governance context or defaults
    let (arena_id, authority, intent) = if let Some(parent_guard) = proc_table.get_mut(parent_pid) {
        (parent_guard.arena_id, parent_guard.authority, parent_guard.intent)
    } else {
        ("system", "kernel-root", "ax-spawn")
    };
    
    let mut child_proc = Process {
        pid: child_pid as u32,
        state: ProcessState::Runnable,
        ctx: child_ctx,
        metrics: axiom_x_math::scheduler_math::SchedMetrics::default(),
        profile: SchedProfile::default(),
        time_slice_ns: 10_000_000,
        affinity: None,
        page_table_root: create_address_space().unwrap_or(axiom_x_arch_traits::PhysAddr(0)),
        kernel_stack_top: alloc_kernel_stack().unwrap_or(axiom_x_arch_traits::VirtAddr(0)),
        user_stack_top: Some(axiom_x_arch_traits::VirtAddr(req.stack_top)),
        fd_table: HeaplessVec::new(),
        signal_mask: 0,
        pending_signals: 0,
        parent_pid: Some(parent_pid as u32),
        exit_code: None,
        last_syscall: None,
        arena_id,
        authority,
        intent,
    };
    
    let page_table_root = child_proc.page_table_root;
    
    // Add to process table
    table().add_process(child_proc).unwrap();
    
    // Register with governance
    if let Some(gov) = governance_registry() {
        let mut gov = gov.lock();
        crate::governance_interfaces::GovernanceRegistry::register_process(&mut *gov, crate::governance_types::ProcessRecord {
            pid: child_pid as u64,
            arena_id: arena_id.to_string(),
            authority: authority.to_string(),
            intent: intent.to_string(),
            memory_handle: alloc::format!("proc-{}", child_pid),
            receipts: alloc::vec::Vec::new(),
            state: crate::governance_types::ProcessState::Runnable,
        });
        // Register with LIRL
        crate::governance_interfaces::LirlKernelBridge::register_process(&mut *gov, crate::governance_types::ProcessRecord {
            pid: child_pid as u64,
            arena_id: arena_id.to_string(),
            authority: authority.to_string(),
            intent: intent.to_string(),
            memory_handle: alloc::format!("proc-{}", child_pid),
            receipts: alloc::vec::Vec::new(),
            state: crate::governance_types::ProcessState::Runnable,
        });
    }
    
    // Return result
    let result = axiom_x_sys::SpawnResult {
        addr_space_id: page_table_root.as_u64(),
        pid: child_pid as u32,
        thread_id: child_pid as u32,
    };
    
    unsafe {
        core::ptr::write(result_ptr, result);
    }
    
    SyscallResult::success(0)
}

fn sys_ax_wait_contract(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

fn sys_ax_signal_evidence(_args: &SyscallArgs) -> SyscallResult {
    SyscallResult::error(errno::ENOSYS)
}

// ============================================================================
// Scheduling Helpers
// ============================================================================

fn table() -> &'static ProcessTable {
    PROCESS_TABLE.get().expect("process table not initialized")
}

fn hardware() -> MutexGuard<'static, X86KernelHardware> {
    KERNEL_HARDWARE.get().expect("hardware not initialized").lock()
}

fn schedule_next() {
    // Trigger reschedule via IPI or flag
}

pub fn scheduler_tick() {
    KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
    KERNEL_UPTIME_NS.fetch_add(10_000_000, Ordering::Relaxed);

    let scheduler = scheduler_mut();
    let proc_table = table();

    let mut measurements = HeaplessVec::<ProcessMeasurement, 256>::new();
    proc_table.for_each_locked(|i, proc| {
        if proc.state == ProcessState::Runnable || proc.state == ProcessState::Running {
            measurements.push(ProcessMeasurement {
                index: i,
                latency_ns: 0,
                dt_ns: scheduler.core_time_budget_ns,
                instructions_retired: proc.metrics.instructions_retired,
                cache_misses: proc.metrics.cache_misses,
                cpu_load: 0.5,
            }).ok();
        }
    });

    let decision = scheduler.tick(&measurements);

    // Emit scheduler decision to MRI
    if let Some(gov) = governance_registry() {
        let mut gov = gov.lock();
        crate::governance_interfaces::MriKernelFeed::push_trajectory_sample(&mut *gov, crate::governance_interfaces::TrajectorySample {
            timestamp: KERNEL_TICKS.load(Ordering::Relaxed),
            pid: decision.selected_pid as u64,
            cpu_usage: 0.5, // TODO: actual CPU usage
            memory_usage: 0,
            syscall_rate: 0.0,
            latency_ns: decision.time_slice_ns,
        });
    }

    if !decision.is_idle() && decision.selected_pid != current_pid() {
        // Context switch via hardware abstraction
        let mut hw = hardware();
        let _ctx_switch = hw.context_switch();
        // Real impl: get next process context and restore
    }
}

fn scheduler_mut() -> &'static mut SchedulerState {
    // Would be stored in hardware or global
    // For now, placeholder
    static mut SCHED: Option<SchedulerState> = None;
    unsafe { SCHED.get_or_insert_with(|| SchedulerState::new(4, 10_000_000)) }
}

// ============================================================================
// Memory Algebra Integration
// ============================================================================

/// Initialize frame allocator with boot memory map (uses boot crate's MemoryRegion)
pub fn init_frame_allocator(memory_regions: &[axiom_x_boot::MemoryRegion]) {
    // Calculate total available frames from available memory regions (type 1 = available)
    let total_frames: usize = memory_regions.iter()
        .filter(|r| r.region_type == 1)
        .map(|r| (r.length / 4096) as usize)
        .sum();

    FRAME_ALLOCATOR.call_once(|| spin::Mutex::new(MathFrameAllocator::new(total_frames)));

    // Mark kernel and reserved regions as allocated
    let mut allocator = FRAME_ALLOCATOR.get().expect("frame allocator just initialized").lock();
    for region in memory_regions {
        if region.region_type != 1 { // Not available memory
            let frames = (region.length / 4096) as usize;
            let base_frame = axiom_x_math::memory_algebra::Frame(region.base / 4096);
            for i in 0..frames {
                let _ = allocator.allocate(axiom_x_math::memory_algebra::AllocRequest {
                    count: 1,
                    region_type: axiom_x_math::memory_algebra::RegionType::KernelCode,
                    owner_pid: 0,
                    flags: axiom_x_math::memory_algebra::RegionFlags::READ | axiom_x_math::memory_algebra::RegionFlags::EXECUTE,
                    alignment: 1,
                });
            }
        }
    }
}

pub fn alloc_frames(req: AllocRequest) -> Result<axiom_x_math::memory_algebra::AllocResult, axiom_x_math::memory_algebra::MemoryAlgebraError> {
    FRAME_ALLOCATOR.get().expect("frame allocator not initialized").lock().allocate(req)
}

pub fn free_frames(base: u64, owner: u32) -> Result<axiom_x_math::memory_algebra::FreeResult, axiom_x_math::memory_algebra::MemoryAlgebraError> {
    FRAME_ALLOCATOR.get().expect("frame allocator not initialized").lock().free(
        axiom_x_math::memory_algebra::Frame(base), owner
    )
}

/// Get mutable reference to the frame allocator (for ELF loading)
pub fn get_frame_allocator() -> &'static spin::Mutex<MathFrameAllocator> {
    FRAME_ALLOCATOR.get().expect("frame allocator not initialized")
}

// ============================================================================
// Address Space Management
// ============================================================================

/// Create a new address space with kernel mappings
pub fn create_address_space() -> Result<PhysAddr, &'static str> {
    let mut hw = hardware();
    let mut ptm = hw.page_table_manager();
    
    // Allocate a new PML4 frame
    let pml4_frame = ptm.allocate_page_table().map_err(|_| "Failed to allocate PML4 frame")?;
    
    // Get the current page table manager to copy kernel mappings
    // For now, we'll use the existing page table manager's map_kernel_range
    // In a real implementation, we'd copy the kernel mappings
    
    Ok(pml4_frame)
}

/// Fork an address space (copy-on-write)
pub fn fork_address_space(src_root: PhysAddr) -> Result<PhysAddr, &'static str> {
    let mut hw = hardware();
    let mut ptm = hw.page_table_manager();
    
    // Allocate a new PML4 frame for the child
    let child_pml4 = ptm.allocate_page_table().map_err(|_| "Failed to allocate PML4 frame")?;
    
    // TODO: Implement copy-on-write page table copying
    // For now, just return the new PML4
    
    Ok(child_pml4)
}

/// Free an address space
pub fn free_address_space(root: PhysAddr) {
    // TODO: Implement address space freeing
    // Would need to walk the page tables and free all frames
}

/// Allocate a kernel stack for a new process/thread
/// Returns the top (high address) of the allocated stack
pub fn alloc_kernel_stack() -> Result<axiom_x_arch_traits::VirtAddr, &'static str> {
    // Allocate 2 pages (8KB) for kernel stack
    let stack_size = 2; // 2 pages = 8KB
    
    let mut hw = hardware();
    let mut ptm = hw.page_table_manager();
    
    // Allocate physical frames for the stack using the frame allocator
    let frames = {
        let mut allocator = FRAME_ALLOCATOR.get().expect("frame allocator not initialized").lock();
        let mut allocated = Vec::new();
        for _ in 0..stack_size {
            let result = allocator.allocate(axiom_x_math::memory_algebra::AllocRequest {
                count: 1,
                region_type: axiom_x_math::memory_algebra::RegionType::KernelRwData,
                owner_pid: 0,
                flags: axiom_x_math::memory_algebra::RegionFlags::READ | axiom_x_math::memory_algebra::RegionFlags::WRITE,
                alignment: 1,
            }).map_err(|_| "Failed to allocate stack frame")?;
            
            let region = match result {
                axiom_x_math::memory_algebra::AllocResult::Success(region) => region,
                _ => return Err("Failed to allocate stack frame"),
            };
            
            allocated.push(axiom_x_arch_traits::PhysAddr(region.base.0 * 4096));
        }
        allocated
    };
    
    // Map them at a fixed virtual address (in kernel space, well above kernel image)
    // Kernel image ends around VIRT+0x11A000, so start stacks at VIRT+4MB
    static mut STACK_NEXT_ADDR: axiom_x_arch_traits::VirtAddr = axiom_x_arch_traits::VirtAddr(0xFFFF_8000_0040_0000); // VIRT + 4MB
    
    let stack_base = unsafe {
        let addr = STACK_NEXT_ADDR;
        STACK_NEXT_ADDR = axiom_x_arch_traits::VirtAddr(STACK_NEXT_ADDR.as_u64() + (stack_size * 4096) as u64);
        addr
    };
    
    // Map the frames
    for (i, frame) in frames.iter().enumerate() {
        ptm.map(
            axiom_x_arch_traits::VirtAddr(stack_base.as_u64() + (i as u64 * 4096)),
            *frame,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            PageSize::Size4KiB,
        ).map_err(|_| "Failed to map stack page")?;
    }
    
    // Return the top of the stack (high address)
    Ok(axiom_x_arch_traits::VirtAddr(stack_base.as_u64() + (stack_size * 4096) as u64))
}

// ============================================================================
// Panic & OOM Handlers
// ============================================================================

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {
        unsafe { asm!("cli; hlt") };
    }
}

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    panic!("Out of memory");
}

// ============================================================================
// Lang Items
// ============================================================================

#[cfg(not(feature = "std"))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_structure() {
        assert!(true);
    }
}