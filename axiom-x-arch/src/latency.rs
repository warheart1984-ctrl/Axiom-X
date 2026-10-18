//! Interrupt-latency measurement: how long the kernel keeps interrupts off,
//! per code path, and how far apart scheduler ticks actually arrive.
//!
//! A tick (10 ms) is lost when interrupts stay off for longer than one tick
//! period: the timer can hold only one pending interrupt. So the two tables
//! here are the cause and the symptom:
//!
//! - **regions**: every *outermost* interrupts-off region (one entered with
//!   interrupts on), timed with the TSC: each system call (the `int 0x80`
//!   gate clears IF for the whole call), the timer handler, and kernel code
//!   that wraps itself in `irq_off` (ATA commands, file-system operations,
//!   kernel serial output, ledger appends). Nested regions are not counted
//!   again, so each row's time is time the timer really could not interrupt.
//! - **tick gaps**: TSC time between consecutive timer interrupts.
//!
//! Single CPU: the counters are only touched with interrupts off.
//!
//! Status: `partial` — measurement only; it changes no behaviour.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Kernel regions wrapped in `irq_off` (system calls are tracked by number).
#[derive(Clone, Copy)]
pub enum Site {
    Timer = 0,
    AtaCommand,
    FsOperation,
    KernelSerial,
    LedgerAppend,
    Allocator,
}

const KERNEL_SITES: [&str; 6] = ["timer tick", "ata command", "fs operation", "kernel serial", "ledger append", "allocator"];

/// System calls with their own row; everything else shares "syscall other".
const SYSCALLS: [(u64, &str); 18] = [
    (0, "sys read"),
    (1, "sys write"),
    (24, "sys sched_yield"),
    (35, "sys nanosleep"),
    (39, "sys getpid"),
    (60, "sys exit"),
    (61, "sys wait4"),
    (228, "sys clock_gettime"),
    (501, "sys ax_get_evidence"),
    (520, "sys ax_spawn_module"),
    (521, "sys ax_proc_list"),
    (530, "sys ax_fs_list"),
    (531, "sys ax_fs_read"),
    (532, "sys ax_fs_write"),
    (533, "sys ax_fs_delete"),
    (534, "sys ax_fs_install"),
    (535, "sys ax_fs_info"),
    (522, "sys ax_latency"),
];

const ROWS: usize = KERNEL_SITES.len() + SYSCALLS.len() + 1;

struct Row {
    count: AtomicU64,
    total: AtomicU64,
    max: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_ROW: Row = Row { count: AtomicU64::new(0), total: AtomicU64::new(0), max: AtomicU64::new(0) };
static TABLE: [Row; ROWS] = [EMPTY_ROW; ROWS];

fn row_name(i: usize) -> &'static str {
    if i < KERNEL_SITES.len() {
        KERNEL_SITES[i]
    } else if i < KERNEL_SITES.len() + SYSCALLS.len() {
        SYSCALLS[i - KERNEL_SITES.len()].1
    } else {
        "sys other"
    }
}

fn syscall_row(nr: u64) -> usize {
    KERNEL_SITES.len() + SYSCALLS.iter().position(|&(n, _)| n == nr).unwrap_or(SYSCALLS.len())
}

fn add(row: usize, cycles: u64) {
    let r = &TABLE[row];
    r.count.fetch_add(1, Relaxed);
    r.total.fetch_add(cycles, Relaxed);
    if cycles > r.max.load(Relaxed) {
        r.max.store(cycles, Relaxed);
    }
}

pub fn now() -> u64 {
    crate::clock::rdtsc()
}

/// Record a system call that started at TSC `t0` (call just before the
/// trap stub's `iretq`).
pub fn end_syscall(nr: u64, t0: u64) {
    add(syscall_row(nr), now().wrapping_sub(t0));
}

/// Record the timer handler that started at `t0`.
pub fn end_timer(t0: u64) {
    add(Site::Timer as usize, now().wrapping_sub(t0));
}

/// `without_interrupts`, timed when it is the outermost region.
pub fn irq_off<R>(site: Site, f: impl FnOnce() -> R) -> R {
    let outermost = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::without_interrupts(|| {
        let t0 = now();
        let r = f();
        if outermost {
            add(site as usize, now().wrapping_sub(t0));
        }
        r
    })
}

// --- tick gaps -----------------------------------------------------------

/// Upper bounds (ms) of the gap histogram buckets; the last is open-ended.
const GAP_BOUNDS_MS: [u64; 5] = [15, 25, 50, 100, 500];
static GAPS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static GAP_MAX: AtomicU64 = AtomicU64::new(0);
static LAST_TICK: AtomicU64 = AtomicU64::new(0);
/// Ticks that should have arrived inside long gaps (gap / 10 ms - 1).
static LOST: AtomicU64 = AtomicU64::new(0);

/// Called at the start of every timer interrupt.
pub fn on_tick(t: u64) {
    let last = LAST_TICK.swap(t, Relaxed);
    let hz = crate::clock::tsc_hz();
    if last == 0 || hz == 0 {
        return;
    }
    let gap = t.wrapping_sub(last);
    let ms = gap * 1000 / hz;
    let b = GAP_BOUNDS_MS.iter().position(|&ub| ms < ub).unwrap_or(GAP_BOUNDS_MS.len());
    GAPS[b].fetch_add(1, Relaxed);
    if gap > GAP_MAX.load(Relaxed) {
        GAP_MAX.store(gap, Relaxed);
    }
    let tick = hz / 100;
    if gap > tick + tick / 2 {
        LOST.fetch_add((gap + tick / 2) / tick - 1, Relaxed);
    }
}

pub fn reset() {
    for r in &TABLE {
        r.count.store(0, Relaxed);
        r.total.store(0, Relaxed);
        r.max.store(0, Relaxed);
    }
    for g in &GAPS {
        g.store(0, Relaxed);
    }
    GAP_MAX.store(0, Relaxed);
    LOST.store(0, Relaxed);
    LAST_TICK.store(0, Relaxed);
}

/// Writes into a byte buffer, truncating.
pub struct BufWriter<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Human-readable report, worst regions first.
pub fn report(w: &mut impl Write) {
    let hz = crate::clock::tsc_hz().max(1);
    let us = |c: u64| c * 1_000_000 / hz;
    let _ = writeln!(w, "interrupts-off regions (outermost only), worst first:");
    let _ = writeln!(w, "  {:<20} {:>8} {:>10} {:>10} {:>10}", "region", "count", "avg us", "max us", "total ms");
    let mut order: [usize; ROWS] = core::array::from_fn(|i| i);
    order.sort_unstable_by_key(|&i| core::cmp::Reverse(TABLE[i].max.load(Relaxed)));
    for &i in &order {
        let r = &TABLE[i];
        let n = r.count.load(Relaxed);
        if n == 0 {
            continue;
        }
        let total = r.total.load(Relaxed);
        let _ = writeln!(
            w,
            "  {:<20} {:>8} {:>10} {:>10} {:>10}",
            row_name(i),
            n,
            us(total / n),
            us(r.max.load(Relaxed)),
            us(total) / 1000
        );
    }
    let g: [u64; 6] = core::array::from_fn(|i| GAPS[i].load(Relaxed));
    let ticks: u64 = g.iter().sum();
    let _ = writeln!(
        w,
        "tick gaps ({} ticks): <15ms {}, 15-25 {}, 25-50 {}, 50-100 {}, 100-500 {}, >=500 {}; max {} ms; ~{} ticks lost",
        ticks,
        g[0],
        g[1],
        g[2],
        g[3],
        g[4],
        g[5],
        GAP_MAX.load(Relaxed) * 1000 / hz,
        LOST.load(Relaxed)
    );
}
