# Axiom-X boot evidence — 2026-10-17

**Claim:** the debug kernel boots under QEMU (TCG) via GRUB Multiboot2, reaches
64-bit Rust, builds its own page tables and heap, loads the IDT, remaps the PIC,
context-switches into PID 1 (a kernel thread on its own stack, IF=1), and keeps
servicing PIT timer interrupts with no CPU exceptions for 30 s.

**Status:** `partial` — boot-to-kernel-thread is demonstrated. Not demonstrated:
ring 3 / userspace, syscalls (dispatch is a TODO), preemptive switching between
two threads, release build, real hardware.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 `grub-mkrescue` ISO, `multiboot2 /boot/kernel.elf` |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), target `x86_64-unknown-none` |
| Kernel | debug build, sha256 `464c3de186c25c597514741acc91f1fd085986b176deb0e18a5e751bf406dcc4` |

## Reproduce

```bash
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 30
```

## Files

- `boot-serial-2026-10-17.log`: COM1 output from the 30 s run (no int tracing)
- `boot-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` log (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run, with `-d int` trace

## Observed

- Serial reaches `Starting scheduler...`, then `PID 1 (init) running on its own stack; interrupts enabled`.
- `init heartbeat` climbs to 2400+ timer wakes in 30 s (about 80/s; nominally 100 Hz, TCG is slower).
- With `-d int`: 1452 timer IRQs (vector 0x20), 0 `check_exception`, in 20 s.
- QEMU exit 124 means it was killed by `timeout` while still running; no triple fault.

## Bugs fixed to get here (each was a hard stop)

1. Link error: `kernel_rust_entry` defined twice (lib `export_name` plus bin dispatcher).
2. Trampoline PD fill used a ×4 stride for 8-byte entries, so PD[0] pointed above RAM and the CPU faulted right after `CR0.PG`.
3. Panic handler used `format!` before the heap existed, so a panic inside it recursed until the stack overflowed.
4. Boot logging used `format!` before heap init (added an allocation-free `serial_print!`).
5. MB2 kernel bounds counted `.debug_*` sections at address 0 (switched to the linker-script bounds).
6. `NO_EXECUTE` page bits were set without `EFER.NXE`, which is a reserved-bit #PF on the first heap write.
7. PIC never remapped, so IRQ0 arrived as vector 8 ("double fault").
8. `sti` ran in `init_arch` before the scheduler existed.
9. `ProcessTable` (536 KB) and `SchedulerState` (38 KB) were built on a 16 KiB boot stack that sits directly above the boot page tables, so overflow corrupted them. Fixed with a heap-zeroed table and a 256 KiB boot stack.
10. PIT at 1000 Hz livelocked: one unoptimized tick takes longer than 1 ms. Now 100 Hz, matching the 10 ms slice.
11. `context_switch` held the process-table spinlock across `restore_context`, which never returns, so the next tick deadlocked.
12. Init's stack top was 16 KiB above unmapped memory, and IRQs run on the interrupted stack. Now 2×256 KiB kernel stacks.

## Known gaps (not fixed)

- No TSS or user GDT segments: ring 3, `IST0` for `int 0x80`, and `sysret` cannot work yet.
- `timer_handler` calls the never-returning `context_switch` from inside the IRQ, abandoning the interrupt frame. Preemption between two threads is untested and likely broken.
- No stack guard pages; bump heap (1 MiB) never frees.
- The release build fails with an LTO bitcode error on this nightly.
- `trampoline.o` is checked in prebuilt; after editing `trampoline.S`, reassemble it with `as --64`.
