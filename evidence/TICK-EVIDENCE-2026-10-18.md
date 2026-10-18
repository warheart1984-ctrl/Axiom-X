# Scheduler tick: local APIC timer — evidence (2026-10-18)

**Status: `partial`.** The tick rate is verified in QEMU (TCG) and on Hyper-V Gen 1, where the problem was found. It is single-CPU and xAPIC only.

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

## Hyper-V result, 08:00 run (`hyperv-serial-2026-10-18-0800.log`)

Run with `-Interactive -UseLedger -Cleanup`. The ISO was `evidence/axiom-x-hyperv.iso` (sha256 `59a50e8f…dc70`), built with self-tests on.

| Check | Before (PIT, 07:31) | After (APIC, 08:00) |
|-------|---------------------|---------------------|
| `Tick:` | PIT | `local APIC timer at 100 Hz (APIC base 0xfee00000, 12502900 counts/s, 125029 per tick)` |
| 1 s tick check | (none) | 101 ticks in 1.004 s = **100.5 Hz** |
| `clocks` at about 1 min | TICK/TSC **0.359** | 0.901 (includes self-tests and the ~1 s start offset) |
| `clocks` at about 3.4 min | (none) | 0.954 |
| Between the two `clocks` | (none) | 135.2 s of ticks in 137.9 s of TSC = **98.0%** |

- **Boot suite on Hyper-V:** lifecycle, ledger audit and reclamation PASS in both rounds.
- **File system on Hyper-V (IDE 0:1):**
  - the blank disk was formatted;
  - write, `install elf-hello /bin/hello` and `run /bin/hello` (exit 0), `ls` and `df` all worked;
  - `cat hello.txt` → ENOENT was correct: the typed names were `hello.tx` and `hello.txt.`.
  - `/bin/hello` has the same SHA-256 (`42e3d209…`) as in the QEMU runs.
- **Off-machine:** `ledger-tool fs-verify evidence/fs.img evidence/ledger.img <key>` gives **PASS**:
  - the ledger has 11768 records from genesis, 12 boots, and 88 archived checkpoints, all signed;
  - the FS table matches its root, and all 3 files match their SHA-256;
  - the root `70ff3ef5…` is the newest anchor (record #11598).

### Remaining gap

About 2% of ticks are still lost while busy. The likely cause is long stretches with interrupts disabled: syscalls run under an interrupt gate, and the debug build does polled PIO and serial output. This is not yet investigated.
