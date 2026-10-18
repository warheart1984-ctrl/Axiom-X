# Axiom-X preemption + address-space evidence — 2026-10-17

**Claim:** under QEMU (TCG), the kernel preemptively time-slices kernel
threads and ring-3 processes on the PIT timer. Each process has its own
address space and its own guarded kernel stack. Four user programs are mapped
at the *same* virtual address at once, two of them never yield, and their
output interleaves.

**Status:** `partial`. Demonstrated: trap-frame context switching from the
timer and `int 0x80`, round-robin preemption across ring 0 and ring 3,
per-process PML4 with CR3 switched on each change, TSS.RSP0 switched per
process, guard-paged 64 KiB kernel stacks, a clean process exit and a ring-3
fault kill under concurrency, and atomic console lines. Not demonstrated:
blocking/sleep primitives, freeing of frames, stacks or PML4s for dead
processes, SMP, ELF loading, the `syscall`/`sysret` path.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 ISO, `multiboot2` |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| Kernel | debug, sha256 `1f5967720fe49c6a94460e283c5f3b51a299ce7207c6e466a0cddbbde3a3caf4` |

## Reproduce

```bash
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 25
```

## Files

- `preempt-serial-2026-10-17.log`: COM1 output, 30 s run without interrupt tracing
- `preempt-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` log (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run with the `-d int` CPU trace

## Observed (serial, `-d int` run; per-tick write lines omitted)

```text
[kernel] spawned 'hello' as pid 2: 171 bytes at 0x8000000000, PML4 0x2e7000, kstack top 0xffff800008022000
hello from ring 3                         <- pid 2 preempted init before 'probe' was spawned
[kernel] spawned 'probe' as pid 3: 27 bytes at 0x8000000000, PML4 0x2fd000, ...
[kernel] spawned 'spin-A' as pid 4: 74 bytes at 0x8000000000, PML4 0x313000, ...
[kernel] spawned 'spin-B' as pid 5: 74 bytes at 0x8000000000, PML4 0x329000, ...
ring 3: kernel pointer refused with -EFAULT
[kernel] pid 2 ended with code 0
[kernel] pid=3 killed: page fault in ring 3 at rip=0x800000000a (0xffff800000100000)
[kernel] pid 3 ended with code 139
[user B] tick / [user A] tick ... (alternating)
[kernel] pid 4 ended with code 0
[kernel] pid 5 ended with code 0
[kernel] all user programs finished
  init heartbeat: 100 wakes, 191 ticks, 109 switches
```

In the 30 s run without tracing, the spinner tick order was `ABAABABABB`. Both
spinners busy-loop and never block or yield, so interleaving requires timer
preemption.

## Observed (CPU trace)

- 16/16 `int 0x80` entries came from `cpl=3`.
- 70 timer IRQs interrupted ring-3 code, under 4 distinct user CR3 values (one per process).
- The only CPU exception is the intended `v=0e e=0005 cpl=3` user read of a supervisor page.
- No triple fault; QEMU was still running at the 30 s timeout.

## What changed

- `axiom-x-arch/src/sched.rs` (new):
  - `TrapFrame`; a naked timer entry saves all registers, calls `schedule`, and
    `iretq`s through whichever frame comes back.
  - Round-robin under `try_lock`: a tick that finds the table locked skips the
    switch instead of deadlocking.
  - Each switch activates the next thread: CR3, TSS.RSP0, current PID.
  - Spawn functions build each thread's initial frame; `start` launches the
    first thread; `exit_current` handles exits and kills.
- `int 0x80` shares the trap-entry macro, so `exit` switches to the next thread
  instead of jumping to a hook. The process-end hook is now a notification.
- Removed the old timer handler that called a never-returning `context_switch`
  from inside the IRQ (the abandoned-frame bug) and ran the unused
  `scheduler_math` tick. `scheduler_math` is not wired in: its runnable set was
  never populated, so it always decided "idle".
- `gdt.rs`: TSS is now mutable through `tss_segment_unchecked`; added `set_kernel_stack`.
- Boot: a kernel-stack allocator with an unmapped guard page per 64 KiB stack,
  in PML4 slot 256, whose lower tables all address spaces share.
  `new_address_space()` copies the kernel PML4 and clears the user slot (1).
  init now starts through `sched::start`. The fixed idle/init stack mapping is gone.
- `user.rs`: four programs spawned concurrently, each with its own PML4 and kernel stack.
- Console writes (`serial_print!`, `serial_puts`) run with interrupts off, so a
  preempted thread can no longer interleave a half-written line.

## Known gaps

- Bump allocation: frames, kernel stacks and PML4s of ended processes are never reclaimed.
- No blocking primitives; a thread waiting on something must spin or `hlt`.
- The old `CpuContext`/`context_switch`/`restore_context` path is no longer
  used at boot, but it is still in `process.rs`.
- `syscall`/`sysret` is still unusable: LSTAR points at a stub that expects a
  per-CPU GS area.
