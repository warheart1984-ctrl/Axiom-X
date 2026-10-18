# Axiom-X process lifecycle evidence — 2026-10-17

**Claim:** under QEMU (TCG), a user-space init program creates child
processes with `AX_SPAWN_MODULE` and reaps them with a Linux-compatible
`wait4`. Children report clean exits and signal deaths correctly. Spawn
failures return `-ENOENT` / `-ENOEXEC`. With nothing left to wait for,
`wait4` returns `-ECHILD`. Teardown through `wait4` returns every frame, so
two full rounds end with identical frames in use.

**Status:** `partial`. Demonstrated: user-initiated process creation from
named boot modules, parent/child tracking, blocking `wait4` (specific PID
and any child) with restart semantics, Linux status encoding (exit codes and
signal 11), reaping by the parent, and kernel reaping of its own children.
Implemented but not exercised: re-parenting of orphans to the kernel
reaper. Not implemented: `fork`, `exec` of a path, argv/env, a filesystem,
process groups, `WNOHANG`, the declared `AxSpawn` (511) `SpawnRequest` ABI.

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 ISO: kernel + `module2` per user program (+ `elf-bad-wx` fixture) |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| kernel.elf | sha256 `448f3c1a34f460cdfeadb2037c9bc720b8231f42423dca5e96cf7e19a1e43b3a` |
| elf-init | sha256 `64a2c0c6a5a5f59b7c3b10ec542e28053598a97952f498a8a01e4e4924e3d3f5` |
| elf-crash | sha256 `3cea81733f422abb7523cc94e428e7ea342e9c37d77aaddecc2b43b7433c4013` |

## Reproduce

```bash
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none && cd ..
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 30
```

## Files

- `lifecycle-serial-2026-10-17.log`: COM1 output, 30 s run without interrupt tracing
- `lifecycle-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` log (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run with the `-d int` CPU trace

## Observed (round 1, `-d int` run)

```text
[kernel] loaded ELF 'elf-init' as pid 6 (parent 0): 20944 bytes, 3 segments, 5 pages, ...
[init] user-space init running as pid 6
[kernel] loaded ELF 'elf-hello' as pid 7 (parent 6): ...
[init] spawn elf-hello -> pid 7
[init] spawn elf-fast -> pid 8
[init] spawn elf-slow -> pid 9
[init] spawn elf-crash -> pid 10
[kernel] ELF 'elf-bad-wx' rejected: segment is both writable and executable (W^X)
[init] spawn elf-bad-wx -> -8 (ENOEXEC)
[kernel] pid=10 killed: page fault in ring 3 at rip=0x800000119b (0xffff800000100000)
[kernel] pid 10 (parent 6) killed by signal 11
[init] spawn no-such-program -> -2 (ENOENT)
[kernel] pid 7 (parent 6) exited with code 0
[init] reaped pid 7: exited with code 0          <- wait(7) blocked before pid 7 exited, then restarted
[init] reaped pid 10: killed by signal 11
[init] reaped pid 8: exited with code 0
[init] reaped pid 9: exited with code 0
[init] all children reaped: 4/4 (exit 0: 3, signaled: 1); expected spawn failures: 2/2; wait(-1) now -> Err(-10)
[init] process-lifecycle check: PASS
[kernel] round 1: kernel started 5, kernel reaped 5 (118 frames); 1 process records left; frames in use 280 -> 280
```

Round 2 repeats with `PASS`, followed by
`reclamation check: PASS (frames in use after each round: 280)`. The one
remaining process record is the kernel init thread.

CPU trace: the only exceptions are 4 user-mode page faults (`cpl=3`,
`e=0005`, `CR2=0xffff800000100000`): the embedded `probe` and `elf-crash`,
once per round. All are intended.

## What changed

- `syscall.rs`:
  - `wait4` (61): `pid` = -1 or a child PID, status written to validated user
    memory, `-ECHILD` / `-EINVAL` / `-EFAULT`. It blocks in the same critical
    section as the check, so a wake-up can't be missed. It restarts by
    rewinding RIP over the 2-byte `int 0x80`, so no partial state survives the
    block.
  - `AX_SPAWN_MODULE` (520): name copied from validated user memory, created
    through a boot-crate spawn hook.
  - `mark_ended` now atomically marks the zombie, re-parents its children to
    the kernel, and wakes a parent blocked in `wait4`.
  - Exit codes are stored as `code >= 0` (exit) or `-signal` (kill). A ring-3
    fault records SIGSEGV (-11) instead of the old 139.
- Hooks from boot into arch: process end (now with parent), spawn, release
  (free address space and kernel stack).
- `user.rs`: the kernel starts only the embedded regression programs and
  `elf-init`. A round ends when every process except kernel init has ended.
  The kernel reaps only zombies without a user parent.
- `axiom-x-user`: `spawn`, `wait` with `ExitStatus` decoding, errno names,
  `elf-init` (lifecycle checks) and `elf-crash`.

## Notes

- `AX_SPAWN_MODULE = 520` is new. The declared `AxSpawn = 511` in
  `axiom-x-sys` takes a `SpawnRequest` with a caller-chosen entry point and
  stack. It stays `declared`: a user-chosen entry into a kernel-loaded image
  needs a contract/validation design first.
- `axiom-x-sys` is unchanged. Its enum doesn't list 520 yet.
