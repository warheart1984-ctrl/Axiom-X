# Scheduler tick: local APIC timer — evidence (2026-10-18)

**Status: `partial`.** Verified in QEMU (TCG). **Not yet verified on Hyper-V**, where the problem was found.

## Problem

On Hyper-V Gen 1, `clocks` reported `PIT / TSC = 0.359` (`HYPERV-EVIDENCE-2026-10-18.md`): about two thirds of the 100 Hz PIT interrupts never arrived. The TSC and the RTC agreed with each other, so the TSC, not the PIT, was the reliable reference.

## Change

- **`apic.rs`:** a local APIC timer in periodic mode at 100 Hz on vector 0x30. It is calibrated against the TSC over 50 ms; the TSC itself is calibrated against the RTC.
  - When it starts, IRQ0 (the PIT) is masked at the PIC.
  - The PIT remains the fallback when there is no APIC, when calibration fails, or with `axiom.timer=pit`.
  - Both sources use the same scheduler entry; `apic::tick_eoi` acknowledges whichever device raised the tick.
- **Boot evidence:** init measures the tick rate against the TSC for 1 s and logs it:
  `[clock] tick check (<source>): N ticks in T s (TSC) = R Hz, expected 100 Hz`.
- **Ledger persistence:** the shell loop now times its 5 s interval with the TSC instead of counting ticks, so lost interrupts no longer stretch it.
- **Shell:** `clocks` labels the row `TICK`, since it may be either source.

## QEMU results

| Run | Tick source | Tick check | Log |
|-----|-------------|------------|-----|
| self-tests, stdin held open | local APIC (`0xfee00000`) | 101 ticks in 1.006 s = **100.3 Hz** | `apic-tick-qemu-2026-10-18.log` |
| `axiom.timer=pit axiom.selftest=off` | PIT (fallback) | 101 ticks in 1.002 s = **100.7 Hz** | `pit-fallback-qemu-2026-10-18.log` |

- **Self-test boot with the APIC tick:**
  - lifecycle, ledger audit and reclamation all PASS;
  - `clocks` between two readings 20.4 s apart (TSC) counted 19.85 s of ticks, about 97%;
  - the remaining gap comes from the self-test bursts (long interrupt-off work in the debug build).
- **Under the `SHELL_INPUT` harness (stdin at EOF), the whole-run ratio drops to about 0.30.** This is the QEMU starvation artifact noted earlier, not a kernel effect: the 1 s tick check in the same run still measured about 98–100 Hz.
- **TCG's APIC count rate varies from run to run** (8.8 M to 62.7 M counts/s). Calibrating against the TSC absorbs this.

## Pending on Hyper-V

The Hyper-V ISO is `evidence/axiom-x-hyperv.iso`, built with an empty command line, so the self-tests run first. Its sha256 is `59a50e8f5efa8167fd90fd82822d39908c127e0c9d5e6d1080b83b0953d2dc70`; it contains a kernel with sha256 `2c9d72dab2360024946319e228ff6b39d810e6234e3cad4aba89f92998aab3d9`.

To pass on Hyper-V:

1. The `Tick:` line names the local APIC timer.
2. The tick check reads about 100 Hz.
3. `clocks` after a minute shows `TICK / TSC` close to 1, minus the roughly 1 s start offset.

If the APIC tick also loses interrupts there, the next suspect is long stretches with interrupts disabled. Examples are syscalls, which run with IF=0 under an interrupt gate, and polled PIO and serial output in the debug build.
