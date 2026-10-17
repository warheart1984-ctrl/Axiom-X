# Axiom-X ring-3 evidence — 2026-10-17

**Claim:** under QEMU (TCG), the kernel runs user programs in ring 3. They
make system calls through an `int 0x80` gate, the kernel validates user
pointers against the page tables, and a ring-3 fault kills only the faulting
process. The kernel keeps running afterwards.

**Status:** `partial`. Demonstrated: GDT with user segments, TSS (RSP0 and
double-fault IST), ring-3 entry via `iretq`, `int 0x80` `write`/`exit`,
`-EFAULT` on a kernel pointer, fault isolation for a direct kernel read,
timer IRQs taken from ring 3. Not demonstrated: per-process address spaces
(all processes share the kernel PML4), the `syscall`/`sysret` fast path,
ELF loading, preemption between processes, SMP.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 ISO, `multiboot2` |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| Kernel | debug, sha256 `a1bd7f098d88226170179d60eef74a8e4395db31244a2d85e8826be88ea0a155` |

## Reproduce

```bash
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 20
```

## Files

- `ring3-serial-2026-10-17.log`: COM1 output, 30 s run without interrupt tracing
- `ring3-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run with the `-d int` CPU trace

## Observed (serial)

```text
[kernel] starting user program 'hello' as pid 2 (171 bytes at 0x8000000000, ring 3)
hello from ring 3
[syscall] pid=2 write(nr=1, a0=0x1) -> 18
[syscall] pid=2 write(nr=1, a0=0x1) -> -14
ring 3: kernel pointer refused with -EFAULT
[syscall] pid=2 write(nr=1, a0=0x1) -> 44
[syscall] pid=2 exit(nr=60, a0=0x0) -> 0
[kernel] pid 2 ended with code 0
[kernel] starting user program 'probe' as pid 3 (27 bytes at 0x8000000000, ring 3)
[kernel] pid=3 killed: page fault in ring 3 at rip=0x800000000a (0xffff800000100000)
[kernel] pid 3 ended with code 139
[kernel] all user programs finished; idling
  idle heartbeat: 100 timer wakes   (continues to 2300 in 30 s)
```

## Observed (CPU trace, `-d int`, 20 s run)

- All 4 `int 0x80` (vector 0x80) entries came from `cpl=3` with `CS=0x23`, `SS=0x1b`.
- 8 timer IRQs (vector 0x20) were taken in ring 3 and returned, so the TSS.RSP0 path works.
- The only CPU exception is the intended one: `v=0e e=0005 cpl=3`, a user-mode read of a
  present supervisor page at `CR2=0xffff800000100000`.

## What was added

- `axiom-x-arch/src/gdt.rs`: kernel GDT (0x08/0x10 kernel, 0x1B/0x23 user, 0x28 TSS),
  TSS with a 256 KiB RSP0 stack and a 32 KiB double-fault IST stack.
- `axiom-x-arch/src/syscall.rs`: naked `int80_entry`, dispatcher (`write` to COM1 for
  fd 1/2, `exit`, otherwise `-ENOSYS`), page-table-walk validation of user buffers, a
  per-syscall evidence line, and `last_syscall` recorded on the process.
- IDT: `0x80` gate at DPL 3, with no IST. The old gate pointed at an IST slot that had
  no TSS behind it.
- Page fault / GPF: a fault from ring 3 kills the process (code 128+SIGSEGV). A
  kernel-mode fault now panics instead of returning into the same faulting instruction.
- STAR written through the validating `Star::write`. The old raw value implied user
  CS 0x2B. User contexts now use CS 0x23 / SS 0x1B (they were swapped).
- Boot: user mappings propagate `USER_ACCESSIBLE` to intermediate tables and refuse to
  split huge pages; `axiom-x-boot/src/user.rs` embeds the two programs and runs them.

## Known gaps

- Shared address space: user pages are mapped in the kernel PML4. Kernel pages are
  supervisor-only, so ring 3 cannot touch them (shown above), but processes are not
  isolated from each other.
- `syscall`/`sysret`: LSTAR still points at an entry stub that expects a per-CPU GS
  area that doesn't exist. A user `syscall` instruction would crash the kernel. Use
  `int 0x80`.
- One RSP0 stack, single CPU; a terminated process's table slot is never reclaimed.
