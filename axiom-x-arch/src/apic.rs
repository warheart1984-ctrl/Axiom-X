//! Local APIC timer: the scheduler tick when the CPU has a local APIC, with
//! the 8253/8254 PIT as the fallback (`axiom.timer=pit`).
//!
//! Why: on Hyper-V (Generation 1) about two thirds of the PIT's 100 Hz
//! interrupts never reached the kernel (`clocks`: PIT / TSC = 0.36, see
//! `evidence/HYPERV-EVIDENCE-2026-10-18.md`). The local APIC timer is the
//! per-CPU timer modern kernels use. Its rate is not known in advance, so
//! it is calibrated against the TSC (itself calibrated against the RTC).
//!
//! The xAPIC registers are memory-mapped at the physical base from
//! `IA32_APIC_BASE`; the boot crate maps that page (identity, uncached)
//! before calling `start_timer`.
//!
//! Status: `partial` — single CPU, periodic mode, xAPIC only (no x2APIC,
//! no TSC-deadline mode, no IO-APIC: the other IRQs stay on the 8259 PIC).

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use x86_64::registers::model_specific::Msr;

/// IDT vector of the APIC timer (above the remapped PIC range 0x20..0x2F).
pub const TIMER_VECTOR: u8 = 0x30;
/// Spurious-interrupt vector (low nibble must be 0xF on older APICs).
pub const SPURIOUS_VECTOR: u8 = 0xFF;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

const REG_TPR: usize = 0x080;
const REG_EOI: usize = 0x0B0;
const REG_SVR: usize = 0x0F0;
const REG_LVT_TIMER: usize = 0x320;
const REG_INITIAL_COUNT: usize = 0x380;
const REG_CURRENT_COUNT: usize = 0x390;
const REG_DIVIDE: usize = 0x3E0;

const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
const DIVIDE_BY_16: u32 = 0x3;

/// Which interrupt drives `sched::TICKS`.
pub const SOURCE_PIT: u8 = 0;
pub const SOURCE_APIC: u8 = 1;
pub static SOURCE: AtomicU8 = AtomicU8::new(SOURCE_PIT);

static BASE: AtomicU64 = AtomicU64::new(0);

/// Physical base of this CPU's local APIC, if CPUID reports one.
pub fn base_phys() -> Option<u64> {
    let has_apic = raw_cpuid::CpuId::new().get_feature_info().is_some_and(|f| f.has_apic());
    if !has_apic {
        return None;
    }
    Some(unsafe { Msr::new(IA32_APIC_BASE).read() } & 0x000F_FFFF_FFFF_F000)
}

fn read(reg: usize) -> u32 {
    unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) as usize + reg) as *const u32) }
}

fn write(reg: usize, v: u32) {
    unsafe { core::ptr::write_volatile((BASE.load(Ordering::Relaxed) as usize + reg) as *mut u32, v) }
}

/// End of interrupt for the APIC timer (or any APIC-delivered vector).
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Result of calibrating and starting the timer.
#[derive(Clone, Copy, Debug)]
pub struct TimerReport {
    /// APIC timer counts (after the divide-by-16) per second.
    pub counts_per_s: u64,
    /// Initial count programmed for one tick.
    pub per_tick: u32,
}

/// Enable the local APIC at `base` (identity-mapped, uncached) and start a
/// periodic timer at `hz`, calibrated against the TSC over 50 ms. Call with
/// interrupts off, after `clock::init`. On success the timer is the tick
/// source: the caller must mask IRQ0 at the PIC.
pub fn start_timer(base: u64, hz: u32) -> Result<TimerReport, &'static str> {
    let tsc_hz = crate::clock::tsc_hz();
    if tsc_hz == 0 || hz == 0 {
        return Err("TSC not calibrated");
    }
    BASE.store(base, Ordering::Relaxed);
    unsafe {
        let mut msr = Msr::new(IA32_APIC_BASE);
        let v = msr.read();
        if v & APIC_GLOBAL_ENABLE == 0 {
            msr.write(v | APIC_GLOBAL_ENABLE);
        }
    }
    write(REG_SVR, 0x100 | SPURIOUS_VECTOR as u32); // software enable
    write(REG_TPR, 0); // accept every priority
    write(REG_DIVIDE, DIVIDE_BY_16);

    // Calibrate: one-shot, masked, from the maximum count, for 50 ms of TSC.
    write(REG_LVT_TIMER, LVT_MASKED | TIMER_VECTOR as u32);
    write(REG_INITIAL_COUNT, u32::MAX);
    let window = tsc_hz / 20;
    let t0 = crate::clock::rdtsc();
    while crate::clock::rdtsc().wrapping_sub(t0) < window {
        core::hint::spin_loop();
    }
    let counted = (u32::MAX - read(REG_CURRENT_COUNT)) as u64;
    write(REG_INITIAL_COUNT, 0); // stop
    if counted == 0 {
        return Err("APIC timer did not count");
    }
    let counts_per_s = counted * 20;
    let per_tick = counts_per_s / hz as u64;
    if per_tick == 0 || per_tick > u32::MAX as u64 {
        return Err("APIC timer rate out of range");
    }

    write(REG_LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(REG_INITIAL_COUNT, per_tick as u32);
    SOURCE.store(SOURCE_APIC, Ordering::SeqCst);
    Ok(TimerReport { counts_per_s, per_tick: per_tick as u32 })
}

/// End of interrupt for the scheduler tick, whichever device raised it.
pub fn tick_eoi() {
    if SOURCE.load(Ordering::Relaxed) == SOURCE_APIC {
        eoi();
    } else {
        crate::outb(0x20, 0x20);
    }
}

pub fn source_name() -> &'static str {
    if SOURCE.load(Ordering::Relaxed) == SOURCE_APIC { "local APIC timer" } else { "PIT" }
}
