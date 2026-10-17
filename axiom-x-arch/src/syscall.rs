//! `int 0x80` system call path (ring 3 -> ring 0).
//!
//! ABI (Linux x86_64 numbering, legacy-gate transport):
//! RAX = number, RDI/RSI/RDX = args 0-2, result in RAX (negative errno on
//! failure). Implemented: `write` (1) to fd 1/2 (COM1), `exit` (60).
//! Everything else returns `-ENOSYS`.
//!
//! User pointers are validated by walking the active page tables: every page
//! of the buffer must be present and user-accessible at every level, so a
//! kernel or unmapped address gets `-EFAULT` instead of faulting the kernel.
//!
//! Status: `partial` — exercised by the ring-3 programs at boot in QEMU.

use core::arch::naked_asm;
use spin::Once;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};

use crate::process::{current_pid, ProcessState, SyscallRecord};

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 60;

pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const ENOSYS: i64 = 38;

/// Exclusive upper bound of the canonical lower (user) half.
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;
/// Largest single `write`; keeps one syscall from monopolising the CPU.
pub const MAX_WRITE_LEN: u64 = 4096;

/// Registers saved by `int80_entry`, lowest address first, followed by the
/// interrupt frame the CPU pushed. Order must match the pushes below.
#[repr(C)]
pub struct SyscallFrame {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    // Pushed by the CPU on the ring 3 -> 0 transition.
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

/// Called when a user process ends, normally (`exit`) or because the kernel
/// killed it (fault in ring 3). Never returns: it decides what runs next.
pub type ProcessEndHook = fn(pid: u32, code: i32) -> !;

static PROCESS_END_HOOK: Once<ProcessEndHook> = Once::new();

pub fn set_process_end_hook(hook: ProcessEndHook) {
    PROCESS_END_HOOK.call_once(|| hook);
}

/// Mark the current process terminated and hand control to the end hook.
pub fn end_current_process(code: i32) -> ! {
    let pid = current_pid();
    if let Some(mut guard) = crate::interrupts::process_table().get_mut(pid) {
        let proc = guard.get_mut();
        proc.state = ProcessState::Terminated;
        proc.exit_code = Some(code);
    }
    match PROCESS_END_HOOK.get() {
        Some(hook) => hook(pid, code),
        None => loop {
            unsafe { core::arch::asm!("cli; hlt") };
        },
    }
}

/// IDT entry for vector 0x80. The gate must have DPL 3 so ring 3 may use it.
#[unsafe(naked)]
pub unsafe extern "C" fn int80_entry() -> ! {
    naked_asm!(
        // CPU pushed SS, RSP, RFLAGS, CS, RIP (40 bytes) onto the 16-byte
        // aligned RSP0; 15 pushes (120 bytes) bring RSP back to 16-byte
        // alignment for the call.
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "cld",
        "mov rdi, rsp",
        "call {dispatch}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        dispatch = sym syscall_dispatch,
    );
}

extern "C" fn syscall_dispatch(frame: &mut SyscallFrame) {
    let (nr, a0, a1, a2) = (frame.rax, frame.rdi, frame.rsi, frame.rdx);
    let pid = current_pid();

    let result: i64 = match nr {
        SYS_WRITE => sys_write(a0, a1, a2),
        SYS_EXIT => {
            log_syscall(pid, "exit", nr, a0, 0);
            end_current_process(a0 as i32);
        }
        _ => -ENOSYS,
    };

    if let Some(mut guard) = crate::interrupts::process_table().get_mut(pid) {
        guard.get_mut().last_syscall = Some(SyscallRecord {
            number: nr,
            args: [a0, a1, a2, frame.r10, frame.r8, frame.r9],
            return_value: result,
            timestamp_ns: 0,
        });
    }
    log_syscall(pid, name_of(nr), nr, a0, result);
    frame.rax = result as u64;
}

fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd != 1 && fd != 2 {
        return -EBADF;
    }
    let len = len.min(MAX_WRITE_LEN);
    if !user_range_accessible(buf, len, false) {
        return -EFAULT;
    }
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    for &b in bytes {
        crate::serial_write_byte(b);
    }
    len as i64
}

fn name_of(nr: u64) -> &'static str {
    match nr {
        SYS_WRITE => "write",
        SYS_EXIT => "exit",
        _ => "unknown",
    }
}

/// One evidence line per decision, on the kernel serial console.
fn log_syscall(pid: u32, name: &str, nr: u64, a0: u64, result: i64) {
    use core::fmt::Write;
    let _ = writeln!(
        crate::SerialPort,
        "[syscall] pid={} {}(nr={}, a0={:#x}) -> {}",
        pid, name, nr, a0, result
    );
}

/// True when every byte of `[start, start + len)` lies in the user half and
/// is mapped present + user-accessible (+ writable if `write`) in the
/// current address space.
pub fn user_range_accessible(start: u64, len: u64, write: bool) -> bool {
    if len == 0 {
        return start < USER_SPACE_END;
    }
    let end = match start.checked_add(len) {
        Some(e) if e <= USER_SPACE_END => e,
        _ => return false,
    };
    let mut page = start & !0xFFF;
    while page < end {
        if !user_page_accessible(page, write) {
            return false;
        }
        page += 0x1000;
    }
    true
}

fn user_page_accessible(virt: u64, write: bool) -> bool {
    let mut need = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if write {
        need |= PageTableFlags::WRITABLE;
    }
    // Page tables are reached through the boot identity map (first 1 GiB).
    let mut table = Cr3::read().0.start_address().as_u64() as *const PageTable;
    let shifts = [39u64, 30, 21, 12];
    for (level, shift) in shifts.iter().enumerate() {
        let table_ref: &PageTable = unsafe { &*table };
        let entry = &table_ref[((virt >> shift) & 0x1FF) as usize];
        if !entry.flags().contains(need) {
            return false;
        }
        let is_leaf = level == 3 || (level > 0 && entry.flags().contains(PageTableFlags::HUGE_PAGE));
        if is_leaf {
            return true;
        }
        table = entry.addr().as_u64() as *const PageTable;
    }
    false
}
