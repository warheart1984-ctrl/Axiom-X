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
