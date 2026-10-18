# Interrupt latency — measurement pass (2026-10-18)

**Status: `partial`.** This adds measurement only; no behaviour changes. Numbers are from QEMU TCG (`latency-qemu-2026-10-18.log`). TCG inflates absolute times, especially port I/O, so the ranking matters more than the microseconds. The same workload was then run on Hyper-V (see below).

## Why ticks are lost

A tick is lost when interrupts stay off for longer than one tick period (10 ms), because the timer can hold only one pending interrupt. The kernel keeps interrupts off in three ways:

1. **Every system call.** `int 0x80` enters through an interrupt gate, so IF=0 for the whole call.
2. **The timer handler**, including the scheduler.
3. **Kernel code using `without_interrupts`**: ATA commands, file-system operations, kernel serial output, ledger appends and the allocators.

## What was added

- **`latency.rs`** times every *outermost* interrupts-off region with the TSC, with one row per system call and per kernel site. Nested regions are not counted twice. It also keeps a histogram of TSC time between ticks and an estimate of lost ticks.
- **Syscall `AX_LATENCY` (522)** returns the report as text and can reset the counters. It needs EVIDENCE.
- **Shell `lat [reset]`** shows the report.
- **After the boot self-tests**, the report is printed to serial with a `[latency]` prefix and then reset.

## Results (QEMU TCG)

### Interactive workload

The workload ran after `lat reset`:
- `install elf-hello /bin/h` and `install elf-audit /bin/audit`;
- `write a.txt …`;
- `run /bin/h` and `run elf-audit +evidence`;
- `ledger` and `ps`.

| Region | Count | Max | Total |
|--------|------:|----:|------:|
| `sys ax_fs_install` | 2 | **336 ms** | 577 ms |
| `sys ax_fs_write` | 1 | **78 ms** | 77 ms |
| `sys write` (console output) | 159 | **71 ms** | 249 ms |
| `sys ax_spawn_module` | 2 | **57 ms** | 78 ms |
| `ata command` (one sector) | 231 | 8.4 ms | 1096 ms |
| timer tick | 1914 | 0.7 ms | 170 ms |

Tick gaps over 1913 ticks: max **341 ms**, about **76 ticks lost**, roughly 4% of the workload's ticks.

### Self-tests

These run with every syscall traced to serial.

| Region | Max |
|--------|----:|
| `sys ax_spawn_module` | 45 ms |
| `sys write` | 45 ms |
| `sys exit` | 36 ms |
| `ata command` | 28 ms |
| `sys getpid` | 12 ms |

`sys getpid` should be trivial. Its time is the per-syscall **trace line written to serial inside the call**. Tick gaps: max 47 ms, about 86 lost.

## Results (Hyper-V Gen 1, `hyperv-serial-2026-10-18-0906.log`)

Run with `-Interactive -UseLedger -Cleanup` and the ISO above. The tick is the APIC timer at 100.1 Hz (1 s check). The workload was the same as in QEMU, typed in vmconnect.

| Region (interactive workload) | QEMU max | Hyper-V max |
|---|---:|---:|
| `sys ax_fs_install` | 336 ms | **806 ms** |
| `sys ax_spawn_module` | 57 ms | **391 ms** |
| `sys ax_fs_write` | 78 ms | **221 ms** |
| `sys write` | 71 ms | **207 ms** |
| `ata command`: average per sector | 4.7 ms | **11.8 ms** |
| max tick gap | 341 ms | **806 ms** |

- **ATA cost.** About 12 ms per 512-byte sector is roughly 43 KB/s. The driver moves each sector as 256 single `inw`/`outw` port accesses, and on Hyper-V's emulated IDE each access is a trap to the host.
- **Self-tests.**
  - `sys ax_get_evidence` reached 370 ms: the audit reads older records back from the ledger disk, with interrupts off.
  - ATA commands reached 223 ms.
  - Over 4843 ticks, about 542 were lost.
- **Console only** (`lat reset`, then `help` three times, then `lat`):
  - `sys write` reached 304 ms;
  - max tick gap 37 ms;
  - about 55 of 765 ticks were lost, roughly 7%.

  The emulated COM port drains far slower than 115200 baud.
- **Host scheduling.** One window showed a 194 ms `timer tick`, although the handler is tiny. This is most likely the host descheduling the vCPU while the TSC kept running. The kernel cannot remove that, so the target is a bound on the kernel's own regions, not on gaps.
- **Disks after the run.** `ledger-tool fs-verify evidence/fs.img evidence/ledger.img <key>` gives **PASS**:
  - 14727 records from genesis, 13 boots, 117 archived signed checkpoints;
  - 6 files, all matching their SHA-256;
  - the root `19202806…` is the newest anchor (record #13522).
  - `/bin/h` differs from `/bin/hello` because `elf-hello` was rebuilt against the newer user library.

## Diagnosis, ranked

1. **Whole-file FS operations under one interrupts-off lock** (`with_fs`): install, write and read.
   - The cost is a full file of PIO, SHA-256 and a 16-sector table commit with two cache flushes, all with IF=0.
   - This is the single worst region.
2. **Synchronous, polled serial output with interrupts off.** This covers `sys write`, the syscall trace, and kernel `serial_print`.
   - At 115200 baud, each byte takes about 87 µs.
   - So a 1 KiB write holds interrupts off for about 90 ms, even on real hardware.
3. **Program spawn**: ELF validation, loading and page allocation, plus the file read for `/path` programs.
4. **ATA commands one sector at a time with polling.** Each command is short except cache flushes; in QEMU writethrough mode, a flush becomes a host sync.

## Fix plan (not implemented here)

The Hyper-V run confirms the ranking. It moves the disk up, and adds a cheap step 0:

0. **Faster ATA transfers.** Move each sector with one `rep insw`/`rep outsw`; emulators can often batch a string I/O instruction into one exit. Then transfer several sectors per command. Re-measure `ata command` with `lat`.
1. **Serial TX ring buffer.** `write` copies into a kernel buffer and returns. The UART drains the buffer from its transmit-empty interrupt (IRQ4 is already wired), or from the tick. This removes cause 2 for both user and kernel output.
2. **Interrupts on inside long system calls.** File-system work and spawn would run with IF=1 under a lock that does not disable interrupts. ATA would disable interrupts per command only.
   - This needs the shared kernel structures to be safe against preemption. That is the same locking work SMP needs, done first on one CPU.
3. **Re-measure** with `lat` in QEMU and on Hyper-V. The target is a worst-case interrupts-off time under one tick: under 10 ms, so no ticks are lost.

## Other notes

- **`run elf-audit +evidence` from the shell reports `FAIL` (exit 1). This is expected.**
  - Its pass condition needs denies *and* faults inside its 400-record window, and the self-tests provide those.
  - The interactive window had `denies 0, faults 0`.
  - The chain check and the forged-record check both passed. The boot-time audits PASS.
- **The Hyper-V ISO is rebuilt with this kernel:** `evidence/axiom-x-hyperv.iso`, sha256 `2adcb20078a5bd1e943c10b686dd0386fb2a048c46940d6f6ff2a25bf5929063`. The kernel's sha256 is `e8ed8ee9003a08111dcd90bd3b885487c227cd9cf75da2910bd1a5a57d70c604`.
- **Host tests:** 66 pass.

## Fixes 0 and 1, plus the VGA mirror: QEMU re-measure (`latency-after-qemu-2026-10-18.log`)

### Changes

- **ATA:** each sector is now moved with one `rep insw` / `rep outsw` instead of 256 single port accesses.
- **Serial transmit ring** (16 KiB, `console::serial_out`):
  - output is queued, and the THR-empty interrupt (IRQ4) sends the next byte;
  - the timer tick also sends one byte, in case an interrupt was missed;
  - before the scheduler runs, and on panic (`serial_sync`), bytes are written directly;
  - when the ring is full, the oldest byte is sent synchronously, and `TX_OVERFLOW_SYNC` counts these.
- **VGA mirror.** Even with buffered serial output, `sys write` still peaked at 101 ms, and the cause was the VGA mirror:
  - every newline scrolled by copying the whole screen through emulated video memory (2000 reads plus 2000 writes);
  - every byte also set the hardware cursor (four port writes).

  The screen now scrolls in hardware by moving the CRTC start address: one line of writes per newline, and a full copy only when the window reaches the end of the 32 KiB text memory. The cursor is set at most once per tick.
  - The VGA screenshot after many screens of scrolling is correct: `vga-scroll-2026-10-18.png`.

### Results (same QEMU workloads as before)

| Measure | Before | After |
|---|---:|---:|
| Self-tests: `sys write` max | 45 ms | **14 ms** |
| Self-tests: max tick gap / ticks lost | 47 ms / 86 | **29 ms / 6** |
| Workload: `sys write` max | 71 ms | **20 ms** |
| `help`×3: `sys write` max (QEMU, earlier build) | 101 ms | **18 ms** |
| `help`×3: max tick gap | n/a | **17 ms** (2 of 604 ticks lost) |
| Workload: `sys ax_fs_install` max | 336 ms | 335 ms (not addressed yet) |
| Workload: `ata command` average | 4.7 ms | 4.7 ms |

- **ATA in TCG.** `rep insw` makes no difference under TCG, which still emulates each word. Whether Hyper-V batches the string instruction is the open question for the next Hyper-V run.
- **What's left:** whole-file FS operations and spawn under one interrupts-off region (fix 2).
- **Checks:** self-tests PASS (lifecycle, audit, reclamation); host tests: 66 pass.
- **Hyper-V ISO** rebuilt: `evidence/axiom-x-hyperv.iso`, sha256 `985696a8b4081028298d300dc21e23464ffcc5882e1ac05cde186452ca88452c`; kernel sha256 `373fe4bc9fa7739944ec24260898fb839b26486085ff6b7ebd44e7217538f38b`.

## Hyper-V re-measure after fixes 0 and 1 (`hyperv-serial-2026-10-18-0930.log`)

The ISO had sha256 `985696a8…452c`. The workload was the same as before.

| Measure | Hyper-V before | Hyper-V after |
|---|---:|---:|
| `ata command` average per sector | 11.8 ms | **2.4 ms** (string I/O is batched by Hyper-V) |
| `sys ax_fs_install` max | 806 ms | **133 ms** |
| `sys ax_spawn_module` max | 391 ms | **49 ms** |
| `sys ax_fs_write` max | 221 ms | **42 ms** |
| Self-tests: max tick gap / ticks lost | 371 ms / ~542 | **46 ms / ~64** |
| Self-tests: `sys ax_get_evidence` max | 370 ms | **3.8 ms** |
| `help`×3: max tick gap / ticks lost | 37 ms / ~55 of 765 | **22 ms / ~15 of 683** |
| `sys write` max | 304 ms | 162 ms (see below) |

**Remaining `sys write` cost.** The 162 ms writes were the shell printing the `lat` report itself, about 1 KB in one write. The tick-gap counter restarted at the first tick after a reset, so that gap was not counted. The cost came from the transmit path still touching the UART for every byte queued:
- the interrupt-enable write;
- the line-status read;
- sometimes the data write.

On Hyper-V's emulated COM port, each of those accesses is a host exit (roughly 40 µs).

**Disks after the run.** `fs-verify` gives **PASS**:
- 19295 records from genesis, 15 boots, 157 archived signed checkpoints;
- 7 files, all matching their SHA-256;
- the root `1ab9d255…` is the newest anchor (record #18033).

## Serial burst fix (`latency-after2-qemu-2026-10-18.log`)

- **Queueing a byte no longer touches the UART.** The THR-empty interrupt is enabled once per burst (tracked by `TX_IRQ_ON`) and switched off when the ring empties.
- **IRQ4 loops on the interrupt-identification register until nothing is pending.** IRQ4 is edge-triggered at the 8259, and a UART left with something pending keeps its line high, so no new edge arrives.
  - The first version of this fix showed the problem: serial input stalled after 14 bytes in QEMU, while keyboard input still worked.
  - The loop is bounded. When the bound is reached, it stops the transmit interrupt and the tick fallback restarts it.
- **The tick fallbacks run every 10th tick:** keyboard byte, receive drain and transmit kick. The cursor update still runs every tick, and only when the cursor moved.
- **`lat reset` starts the gap clock at the reset**, so the first gap is no longer missed.

### QEMU results

| Measure | After fix 1 | After burst fix |
|---|---:|---:|
| Workload: `sys write` max | 20 ms | **7.0 ms** |
| `help`×3: `sys write` max | 18 ms | **4.9 ms** |
| `help`×3: max tick gap / ticks lost | 17 ms / 2 | 21 ms / 2 |
| Self-tests: `sys write` max | 14 ms | 12 ms |

- **Checks:**
  - the full interactive session (install, write, run from `/path`, audit, `ledger`, `ps`, `lat`) arrived and ran intact;
  - all 16 commands of the scripted-input harness (`fs-input-1.txt`) arrived intact;
  - self-tests PASS;
  - host tests: 66 pass.
- **The largest remaining region is the whole-file FS operation:** `ax_fs_install` at about 330 ms in QEMU and 133 ms on Hyper-V. Fix 2 addresses it.
- **Hyper-V ISO** rebuilt: sha256 `d411d47767955c267d15ff871de134f84cce79f9ca84ed1bf0471d3372dd0185`; kernel sha256 `6341bf73d66239c21f032b6569e73f8aca2b087b63b5f851a0ef3bed208f743c`.

## Hyper-V check of the serial burst fix (`hyperv-serial-2026-10-18-0945.log`)

This run used the current build. Typed input echoed normally in vmconnect throughout.

| Measure | Hyper-V 09:30 (fix 1) | Hyper-V 09:45 (burst fix) |
|---|---:|---:|
| `help`×3: `sys write` max | 162 ms | **3.7 ms** |
| Workload: `sys write` max | 106 ms | **2.0 ms** |
| Self-tests: `sys write` max | 26 ms | **1.4 ms** |
| Self-tests: `kernel serial` max | 46 ms | **6.1 ms** |
| Self-tests: `sys ax_spawn_module` max | 24 ms | **1.3 ms** (its cost was the trace line inside the call) |
| Workload: `sys ax_fs_install` max | 133 ms | 136 ms (unchanged, as expected) |
| Workload: `sys ax_fs_write` max | 42 ms | 45 ms |
| Workload: `sys ax_spawn_module` max (from `/path`) | 49 ms | 29 ms |
| `ata command` average (workload) | 2.4 ms | 2.3 ms |
| Self-tests: max tick gap / ticks lost | 46 ms / ~64 | 39 ms / ~67 |
| `help`×3: max tick gap / ticks lost | 22 ms / ~15 | 45 ms / ~19 |

**Console output is no longer a latency source on Hyper-V:** every `write` stays under 4 ms. What remains:

1. **Whole-file FS operations under one interrupts-off region:** install 136 ms, write 45 ms, spawn from a file 29 ms. Fix 2 addresses these.
2. **Single ATA commands up to about 34 ms** (self-tests: ledger persistence, cache flushes). With interrupts on between commands, as in ledger persistence, these are the remaining kernel-side bound.
3. **The `timer tick` region sometimes runs 42–62 ms, against an average of 77–124 µs.** In the `help` round, the 45 ms maximum gap equals the 45 ms maximum `timer tick`. The handler does a few port and MMIO accesses and a scheduler pass; this looks like the host descheduling the vCPU while the TSC runs. That is not a kernel cost, but it is not proven either. One way to check: the TSC deadline ↔ steal-time interface (Hyper-V enlightenments) is not used yet.

**Disks after the run.** `fs-verify` gives **PASS**:
- 22336 records from genesis, 16 boots, 190 archived signed checkpoints;
- 7 files, all matching their SHA-256;
- the root `d0e19342…` is the newest anchor (record #21126).
