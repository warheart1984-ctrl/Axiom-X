//! Time: CMOS real-time clock (wall clock, 1 s resolution) and the TSC
//! (high-resolution monotonic clock), calibrated against RTC second edges.
//!
//! At boot `init` waits for an RTC second boundary, records the TSC there
//! and the RTC time of that new second, then measures TSC cycles across
//! the following boundary. Afterwards:
//!
//! - monotonic time  = (TSC - boot TSC) / TSC rate
//! - wall-clock time = boot RTC time + monotonic time
//!
//! Neither depends on the PIT, so they can be used to check how faithfully
//! the PIT tick count tracks real time (`timer_check`).
//!
//! The RTC carries no time zone: QEMU defaults to UTC, Hyper-V presents
//! the host's local time. Calibration error is bounded by how quickly a
//! second edge is noticed (a few microseconds of polling).
//!
//! Status: `partial` — exercised under QEMU (TCG) and Hyper-V.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{inb, outb};

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

/// TSC cycles per second (0 until calibrated).
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// TSC value at the RTC second edge used as the time origin.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);
/// UNIX time (seconds) of that edge, from the RTC.
static BOOT_UNIX: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn cmos_read(reg: u8) -> u8 {
    // Bit 7 keeps NMIs disabled while the index register is selected.
    outb(CMOS_ADDR, reg | 0x80);
    inb(CMOS_DATA)
}

fn update_in_progress() -> bool {
    cmos_read(0x0A) & 0x80 != 0
}

/// Calendar time as the RTC reports it.
pub type RtcTime = axiom_x_ledger::civil::DateTime;

fn raw_rtc() -> [u8; 7] {
    while update_in_progress() {}
    [cmos_read(0x00), cmos_read(0x02), cmos_read(0x04), cmos_read(0x07), cmos_read(0x08), cmos_read(0x09), cmos_read(0x32)]
}

/// Read the RTC, retrying until two consecutive reads agree (a read that
/// straddles an update can otherwise mix two different seconds).
pub fn read_rtc() -> RtcTime {
    let mut a = raw_rtc();
    loop {
        let b = raw_rtc();
        if a == b {
            break;
        }
        a = b;
    }
    let status_b = cmos_read(0x0B);
    let binary = status_b & 0x04 != 0;
    let h24 = status_b & 0x02 != 0;
    let bcd = |v: u8| if binary { v } else { (v & 0x0F) + (v >> 4) * 10 };
    let pm = a[2] & 0x80 != 0;
    let mut hour = bcd(a[2] & 0x7F);
    if !h24 {
        // 12-hour mode: 12 AM is 0, 12 PM stays 12.
        hour %= 12;
        if pm {
            hour += 12;
        }
    }
    let century = bcd(a[6]);
    let yy = bcd(a[5]) as u32;
    // Use the century register when it holds a plausible value.
    let year = if (19..=29).contains(&century) { century as u32 * 100 + yy } else { 2000 + yy };
    RtcTime { year, month: bcd(a[4]), day: bcd(a[3]), hour, minute: bcd(a[1]), second: bcd(a[0]) }
}

/// Spin until the RTC second changes; return the TSC at the change and
/// the new second's time.
fn wait_second_edge() -> (u64, RtcTime) {
    let start = cmos_read(0x00);
    loop {
        if cmos_read(0x00) != start && !update_in_progress() {
            let tsc = rdtsc();
            return (tsc, read_rtc());
        }
    }
}

/// Calibrate the TSC against two RTC second edges (takes 1-2 seconds) and
/// set the time origin. Call once, early, with interrupts off.
pub fn init() -> (RtcTime, u64) {
    let (t0, now) = wait_second_edge();
    let (t1, _) = wait_second_edge();
    let hz = t1.wrapping_sub(t0).max(1);
    BOOT_TSC.store(t0, Ordering::SeqCst);
    BOOT_UNIX.store(now.unix_seconds(), Ordering::SeqCst);
    TSC_HZ.store(hz, Ordering::SeqCst);
    (now, hz)
}

pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

/// UNIX time (seconds) of the time origin, per the RTC.
pub fn boot_unix() -> u64 {
    BOOT_UNIX.load(Ordering::Relaxed)
}

/// Nanoseconds since the time origin, from the TSC (0 before `init`).
pub fn monotonic_ns() -> u64 {
    let hz = tsc_hz();
    if hz == 0 {
        return 0;
    }
    let cycles = rdtsc().wrapping_sub(BOOT_TSC.load(Ordering::Relaxed));
    ((cycles as u128 * 1_000_000_000) / hz as u128) as u64
}

/// Wall-clock nanoseconds since the UNIX epoch.
pub fn realtime_ns() -> u64 {
    boot_unix() * 1_000_000_000 + monotonic_ns()
}

/// One line comparing three clocks since the time origin: PIT ticks (10 ms
/// each), the TSC, and the RTC itself. If the PIT loses ticks, its time
/// falls behind the other two.
pub fn timer_check(pit_ticks: u64) -> (u64, u64, u64) {
    let pit_ms = pit_ticks * 10;
    let tsc_ms = monotonic_ns() / 1_000_000;
    let rtc_s = read_rtc().unix_seconds().saturating_sub(boot_unix());
    (pit_ms, tsc_ms, rtc_s)
}
