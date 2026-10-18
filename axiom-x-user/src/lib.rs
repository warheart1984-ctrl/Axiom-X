//! Axiom-X user-space runtime.
//!
//! System calls go through `int 0x80` with the Linux x86_64 numbering the
//! kernel implements: RAX = number, RDI/RSI/RDX = arguments, RAX = result
//! (negative errno on failure). `entry!` provides `_start`; `println!`
//! formats without an allocator.
//!
//! Status: `partial` — used by the test programs loaded as ELF modules.

#![no_std]

use core::arch::asm;
use core::fmt;

pub use axiom_x_capability::Rights;
pub use axiom_x_ledger as ledger;

pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const SCHED_YIELD: u64 = 24;
    pub const NANOSLEEP: u64 = 35;
    pub const GETPID: u64 = 39;
    pub const EXIT: u64 = 60;
    pub const WAIT4: u64 = 61;
    pub const CLOCK_GETTIME: u64 = 228;
    /// Axiom-X: list processes (needs `Rights::EVIDENCE`).
    pub const AX_PROC_LIST: u64 = 521;
    /// Axiom-X: start a boot module by name as a child process.
    pub const AX_SPAWN_MODULE: u64 = 520;
    /// Axiom-X `AxGetEvidence`: read a ledger record (needs `Rights::EVIDENCE`).
    pub const AX_GET_EVIDENCE: u64 = 501;
}

/// errno values the kernel returns (negated).
pub mod errno {
    pub const EPERM: i64 = 1;
    pub const ENOENT: i64 = 2;
    pub const ENOEXEC: i64 = 8;
    pub const ECHILD: i64 = 10;
    pub const EINVAL: i64 = 22;

    pub fn name(e: i64) -> &'static str {
        match -e {
            EPERM => "EPERM",
            ENOENT => "ENOENT",
            ENOEXEC => "ENOEXEC",
            ECHILD => "ECHILD",
            EINVAL => "EINVAL",
            _ => "?",
        }
    }
}

/// Raw three-argument system call.
///
/// # Safety
/// Pointer arguments must be valid for the call `nr` makes with them.
#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    // The kernel's entry stub preserves every register except RAX.
    asm!(
        "int 0x80",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        options(nostack)
    );
    ret
}

/// `read(fd, buf)`: blocks until at least one byte is available (fd 0 =
/// console; needs `Rights::RECV`). Returns bytes read or `-errno`.
pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    unsafe { syscall3(nr::READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

/// Clock ids for `clock_gettime`.
pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;
/// The RTC read directly (1 s resolution).
pub const CLOCK_REALTIME_COARSE: u64 = 5;
/// PIT ticks x 10 ms since the scheduler started.
pub const CLOCK_MONOTONIC_COARSE: u64 = 6;

/// Nanoseconds from `clock`, or `-errno`.
pub fn clock_ns(clock: u64) -> Result<u64, i64> {
    let mut ts = [0i64; 2];
    let r = unsafe { syscall3(nr::CLOCK_GETTIME, clock, ts.as_mut_ptr() as u64, 0) };
    if r < 0 { Err(r) } else { Ok(ts[0] as u64 * 1_000_000_000 + ts[1] as u64) }
}

/// One process as `AX_PROC_LIST` reports it.
#[derive(Clone, Copy)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: u32,
    pub state: u32,
    pub rights: u64,
    pub name: [u8; 16],
}

impl ProcInfo {
    pub fn name(&self) -> &str {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.name[..n]).unwrap_or("?")
    }

    pub fn state_name(&self) -> &'static str {
        match self.state {
            0 => "new",
            1 => "ready",
            2 => "running",
            3 => "blocked",
            4 => "zombie",
            _ => "?",
        }
    }
}

/// Fill `out` with the process table; returns how many entries, or `-errno`.
pub fn proc_list(out: &mut [ProcInfo]) -> i64 {
    const ENTRY: usize = 48;
    let mut buf = [0u8; ENTRY * 32];
    let max = out.len().min(32);
    let r = unsafe { syscall3(nr::AX_PROC_LIST, buf.as_mut_ptr() as u64, max as u64, 0) };
    if r < 0 {
        return r;
    }
    for i in 0..r as usize {
        let e = &buf[i * ENTRY..(i + 1) * ENTRY];
        let u32_at = |o: usize| u32::from_le_bytes(e[o..o + 4].try_into().unwrap());
        out[i] = ProcInfo {
            pid: u32_at(0),
            parent: u32_at(4),
            state: u32_at(8),
            rights: u64::from_le_bytes(e[16..24].try_into().unwrap()),
            name: e[24..40].try_into().unwrap(),
        };
    }
    r
}

pub fn write(fd: u64, buf: &[u8]) -> i64 {
    unsafe { syscall3(nr::WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }
}

pub fn exit(code: i32) -> ! {
    unsafe { syscall3(nr::EXIT, code as u64, 0, 0) };
    // `exit` never returns; if it did, refuse to continue.
    loop {
        core::hint::spin_loop();
    }
}

/// Start the boot module `name` as a child holding `rights`, which must be a
/// subset of the caller's own (else `-EPERM`); returns its PID or `-errno`.
pub fn spawn(name: &str, rights: Rights) -> i64 {
    unsafe { syscall3(nr::AX_SPAWN_MODULE, name.as_ptr() as u64, name.len() as u64, rights.bits()) }
}

/// Number of records ever appended to the kernel ledger.
pub fn evidence_count() -> Result<u64, i64> {
    let r = unsafe { syscall3(nr::AX_GET_EVIDENCE, u64::MAX, 0, 0) };
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// Ledger record `seq` with the digest the kernel computed for it.
pub fn evidence(seq: u64) -> Result<(ledger::Record, ledger::Digest), i64> {
    let mut buf = [0u8; ledger::RECORD_LEN + 32];
    let r = unsafe { syscall3(nr::AX_GET_EVIDENCE, seq, buf.as_mut_ptr() as u64, buf.len() as u64) };
    if r < 0 {
        return Err(r);
    }
    let rec = ledger::Record::decode(buf[..ledger::RECORD_LEN].try_into().unwrap());
    let digest: ledger::Digest = buf[ledger::RECORD_LEN..].try_into().unwrap();
    Ok((rec, digest))
}

/// How a child ended, decoded from the `wait4` status word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    Exited(i32),
    Signaled(i32),
}

impl ExitStatus {
    pub fn from_raw(status: i32) -> Self {
        if status & 0x7f == 0 {
            ExitStatus::Exited((status >> 8) & 0xff)
        } else {
            ExitStatus::Signaled(status & 0x7f)
        }
    }
}

/// `wait4(pid, &status, 0, NULL)`: `pid` = -1 for any child. Blocks until a
/// child ends; returns `(pid, status)` or `Err(-errno)`.
pub fn wait(pid: i64) -> Result<(u32, ExitStatus), i64> {
    let mut status: i32 = 0;
    let r = unsafe { syscall3(nr::WAIT4, pid as u64, &mut status as *mut i32 as u64, 0) };
    if r < 0 { Err(r) } else { Ok((r as u32, ExitStatus::from_raw(status))) }
}

pub fn getpid() -> u32 {
    unsafe { syscall3(nr::GETPID, 0, 0, 0) as u32 }
}

pub fn yield_now() {
    unsafe { syscall3(nr::SCHED_YIELD, 0, 0, 0) };
}

/// Block for at least `ms` milliseconds (the kernel rounds up to 10 ms ticks).
pub fn sleep_ms(ms: u64) -> i64 {
    let ts: [i64; 2] = [(ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64];
    unsafe { syscall3(nr::NANOSLEEP, ts.as_ptr() as u64, 0, 0) }
}

/// Standard output (fd 1). Each `write_str` is one `write` syscall, so
/// `println!` buffers a line first to keep it in one console write.
pub struct Stdout;

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if write(1, s.as_bytes()) < 0 { Err(fmt::Error) } else { Ok(()) }
    }
}

/// `print!` without a trailing newline (same buffering as `println!`).
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut line = $crate::LineBuf::new();
        let _ = write!(line, $($arg)*);
        line.flush();
    }};
}

/// Fixed-size line buffer so a formatted line reaches the console in one
/// syscall (lines longer than the buffer are truncated).
pub struct LineBuf {
    buf: [u8; 256],
    len: usize,
}

impl LineBuf {
    pub const fn new() -> Self {
        Self { buf: [0; 256], len: 0 }
    }
    pub fn flush(&mut self) {
        write(1, &self.buf[..self.len]);
        self.len = 0;
    }
}

impl fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut line = $crate::LineBuf::new();
        let _ = writeln!(line, $($arg)*);
        line.flush();
    }};
}

/// Define `_start`: align the stack per the SysV ABI, run `main() -> i32`,
/// and `exit` with its result.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(naked)]
        #[no_mangle]
        #[link_section = ".text._start"]
        pub unsafe extern "C" fn _start() -> ! {
            core::arch::naked_asm!(
                "and rsp, -16",
                "call {start}",
                "ud2",
                start = sym __axiom_start,
            );
        }

        extern "C" fn __axiom_start() -> ! {
            let code: i32 = $main();
            $crate::exit(code)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("[user panic] {}", info);
    exit(101)
}
