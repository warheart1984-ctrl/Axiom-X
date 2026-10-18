# Axiom-X ELF user space + reclamation evidence — 2026-10-17

**Claim:** under QEMU (TCG), the kernel loads statically linked Rust ELF
programs that GRUB passes in as Multiboot2 modules. It validates them,
rejects a W^X-violating image, maps segments with their declared
permissions, and runs them in ring 3 alongside the embedded test programs.
`nanosleep` blocks a process until its tick deadline, and `sched_yield` and
`getpid` work. Init reaps ended processes; running the full program set
twice ends with identical frames-in-use, so teardown returns every frame a
process allocated.

**Status:** `partial`. Demonstrated: ELF64 `ET_EXEC` validation and loading
(page-aligned, W^X, image window, bss zero-fill), Multiboot2 module
handover (module memory reserved from the allocator), blocking sleep, yield,
getpid, a free-list frame allocator, and reaping of address spaces and
guarded kernel stacks with slot reuse. Not demonstrated: `fork`/`exec`/`wait`
from user space, argv/env, dynamic linking, demand paging, freeing the
heap, SMP.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 ISO: `multiboot2 /boot/kernel.elf` + `module2` per user program |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| kernel.elf | sha256 `619ebb2ca3178d3a790dd47bfba375bdbdd4be1961c526e62d7ff410a0103d5c` |
| elf-hello | sha256 `3a317951409cfbfbc426da46416163a92b2c6f4dc3f21f9d27ee7e3e94afc473` |
| elf-fast | sha256 `74a74200eeec82506a8f39b6fcbb9b1ff1e584d263bc2b40902720be093a4db4` |
| elf-slow | sha256 `34651b837fd903cd9be8d671cb3d02ac58da3cbb0feb9ae9cf0d65a22053dc5b` |

## Reproduce

```bash
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none && cd ..
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 30
```

`qemu-boot.sh` also builds the negative fixture `elf-bad-wx`: `elf-hello`
with its text `PT_LOAD` patched to RWX.

## Files

- `elf-serial-2026-10-17.log`: COM1 output, 30 s run without interrupt tracing
- `elf-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` log (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run with the `-d int` CPU trace

## Observed

```text
  Boot modules: 4
[kernel] === round 1: frames in use 280 ===
[kernel] loaded ELF 'elf-fast' as pid 6: 16800 bytes, 3 segments, 4 pages, entry 0x8000000000, PML4 0xa12000
[kernel] loaded ELF 'elf-hello' as pid 7: 16880 bytes, 3 segments, 5 pages, entry 0x8000000000, ...
[kernel] ELF 'elf-bad-wx' rejected: segment is both writable and executable (W^X)
[elf-hello] pid 7: Rust ELF running in ring 3
[elf-hello] .data initialized: true, .bss zeroed: true
[elf-hello] back after sched_yield, exiting
[elf-fast] pid 6 woke 1/5 at ~100 ms (sleep -> 0)   ... interleaved with [elf-slow] wakes
[kernel] round 1: 7 processes started, 7 reaped, 176 frames freed; frames in use 280 -> 280
[kernel] === round 2: frames in use 280 ===
[kernel] round 2: 7 processes started, 7 reaped, 176 frames freed; frames in use 280 -> 280
[kernel] reclamation check: PASS (frames in use after each round: 280)
```

- Round 2's PML4s are frames freed in round 1 (for example `0xa11000`, `0x9f4000`).
- The embedded programs still pass in both rounds: `hello`, the `-EFAULT` probe,
  and `probe`, killed by its ring-3 page fault. Their two `#PF`s (`cpl=3`,
  `e=0005`) are the only CPU exceptions in the trace.
- Sleep wake order in the clean run: fast 1, fast 2, slow 1, fast 3, slow 2,
  fast 4, fast 5. Sleepers block (they never spin) and wake after their
  deadline. A woken thread rejoins the round-robin queue behind the two
  CPU-bound spinners, so a wake can lag by a few 10 ms slices, and that lag
  accumulates across `elf-fast`'s iterations. Exact deadline ordering is not
  claimed.

## What was added

- `axiom-x-user/` (new, standalone crate): `int 0x80` syscall library
  (`write`, `exit`, `getpid`, `sched_yield`, `nanosleep`), allocation-free
  `println!`, an `entry!` macro with a naked, SysV-aligned `_start`, and a
  panic handler that exits with code 101. `user.ld` produces explicit W^X
  segments (text R-X, rodata R--, data+bss RW-). Three test programs.
- `axiom-x-boot/src/elf.rs`: ELF64 validation (`ET_EXEC`, x86-64, page-aligned,
  inside the image window, no W+X, no overlap, entry inside an executable
  segment) and a page-by-page loader that zero-fills bss.
- Syscalls: `getpid` (39), `sched_yield` (24), `nanosleep` (35, timespec validated
  through the page tables, rounded up to 10 ms ticks). Sleep marks the thread
  `Blocked` with a wake tick; the scheduler wakes due sleepers on each tick.
- Frame allocator: a free list threaded through freed frames, and a
  `frames_in_use` counter. The kernel image and GRUB modules are excluded, and
  allocation is clamped to the identity-mapped first 1 GiB.
- Reaping, done by init: free a dead process's user page tables, the frames
  they map, and its PML4 (the shared kernel half is never touched); unmap and
  free its kernel stack and recycle the guarded slot. A dying thread cannot do
  this itself, because it is standing on that stack and address space.
- Process table: a single lock with PID lookup by scan.
  - Fixes `remove()`, which shifted the vector without updating the separate
    pid→index map, so every lookup after a removal returned the wrong process.
  - All locking now happens with interrupts off. A preempted lock holder could
    previously deadlock any syscall spinning on the lock with interrupts off.

## Findings outside this change

- Root cause of the kernel's release-build failure ("failed to load bitcode"):
  `.cargo/config.toml` forces `-C code-model=large`, and its release profile
  enables LTO. The prebuilt `core` for `x86_64-unknown-none` uses a different
  code model, so LTO cannot merge the bitcode. User programs build with
  `CARGO_PROFILE_RELEASE_LTO=false`. The kernel's release profile is unchanged.
- `code-model=large` emits `.ltext`/`.lrodata`/`.ldata`/`.lbss`. Unless a
  linker script names them, they land as orphans, and in the user layout code
  ended up in a read-only, no-execute segment. `user.ld` names them explicitly.

## Known gaps

- No user-visible process creation (`fork`/`exec`/`spawn`) or `wait`; init decides what runs.
- The early heap is still a bump allocator (it never frees). Only frames and stacks are reclaimed.
- `syscall`/`sysret` is still unusable (LSTAR stub without a per-CPU GS area).
