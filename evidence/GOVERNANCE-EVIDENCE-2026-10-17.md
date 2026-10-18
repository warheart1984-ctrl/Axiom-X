# Axiom-X governance evidence — 2026-10-17

**Claim:** under QEMU (TCG), the kernel enforces capability rights on every
system call, and rights only flow down the process tree. Every governed
decision is appended to a SHA-256 hash-chained ledger. A user-space
auditor independently re-verifies that chain from the genesis record and
detects a forged record.

Mapping to the AGENTS.md core principles, at kernel level:

| Principle | Kernel mechanism | Tag |
|-----------|------------------|-----|
| No dispatch without authority | each syscall is checked against the right it needs; `-EPERM` otherwise | `enforced` (runtime gate + QEMU test) |
| No execution without a parent | every process records its parent: the kernel for init and regression programs, otherwise the spawning process; rights are a subset of the parent's | `enforced` |
| Every allowed dispatch appends a ledger event | allow, deny, block, create, exit, kill and reap are all appended to the SHA-256 chain | `enforced` |
| Registered authority **+ signature** (ACC) | rights are capability bits; **no signatures** | `declared` (not implemented) |
| No schedule without intent + CCR | not implemented in the kernel | `declared` |

## Environment

| Item | Value |
|------|-------|
| Emulator | QEMU 8.2.2 (Ubuntu-24.04 WSL2), TCG, `-m 256M` |
| Loader | GRUB 2 ISO: kernel + `module2` per user program (+ `elf-bad-wx` fixture) |
| Toolchain | rustc 1.101.0-nightly (5d8fec066 2026-10-16), `x86_64-unknown-none` |
| kernel.elf | sha256 `faa0abdc42cbbd38b58826c75da624aabb88537366aa7d5bb601776a2fb86c40` |
| elf-init | sha256 `d1a457228d76ce475e88d499920dffc14d85b064ca8620650388b2e690a56131` |
| elf-audit | sha256 `429b0b1d088dcd6fda41321ce9c07c8ce0615814771ebd627329fa4ec3826d74` |
| elf-noperm | sha256 `d68794598391027c30eff8691fd3946bb1a9ff37693578c7418fc473c6b0a597` |

## Reproduce

```bash
cargo test                       # 42 host tests, incl. axiom-x-ledger (NIST SHA-256 vectors, chain, tamper)
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none && cd ..
wsl -d Ubuntu-24.04 sh ./qemu-boot.sh 60
```

## Files

- `governance-serial-2026-10-17.log`: COM1 output, 45 s run without interrupt tracing
- `governance-qemu-2026-10-17.log`: QEMU `cpu_reset,guest_errors` log (only the 2 power-on resets)
- `serial-mb2.log` / `qemu-mb2.log`: latest `qemu-boot.sh` run with the `-d int` CPU trace

## Rights in this run

| Process | Granted by | Rights |
|---------|-----------|--------|
| embedded hello/probe/spin-A/spin-B | kernel | `SEND` |
| `elf-init` | kernel | `SEND SPAWN DELEGATE EVIDENCE` |
| `elf-hello`, `elf-fast`, `elf-slow`, `elf-crash` | elf-init | `SEND` |
| `elf-noperm` | elf-init | none |
| `elf-audit` | elf-init | `SEND EVIDENCE` |

## Observed

```text
[init] spawn elf-noperm rights 0x0 -> pid 11
[syscall] pid=11 write(nr=1, a0=0x1) -> -1                 <- no SEND: refused
[syscall] pid=11 ax_spawn_module(nr=520, ...) -> -1        <- no SPAWN: refused
[init] spawn elf-hello rights 0x2000080 -> -1 (EPERM)      <- escalation: init lacks IO_PORT
[init] reaped pid 11: exited with code 0                   <- elf-noperm saw both refusals
[audit] pid 12: verifying ledger records 0..98 (of 98)
[audit] chain intact: 98 records, head 3f8d1673aed8d48f... (denies 5, faults 2, creates 11, reaps 5)
[audit] forged record 49 detected: yes
[audit] ledger audit: PASS
[init] process-lifecycle check: PASS
[kernel] ledger: 264 records, head d631f7c137f0c123...
[kernel] round 1: ... frames in use 281 -> 281
...
[audit] pid 23: verifying ledger records 0..361 (of 361)
[audit] chain intact: 361 records, head 5047165c318b79e2... (denies 10, faults 4, creates 22, reaps 16)
[audit] ledger audit: PASS
[init] process-lifecycle check: PASS
[kernel] reclamation check: PASS (frames in use after each round: 281)
```

- The round-2 audit verifies every link from genesis (record 0) to record 360.
- Repeatability: 3 consecutive traced boots each passed lifecycle 2/2, audit 2/2 and reclamation.
  The only `EPERM` spawn results were the intended escalation attempts, and there were no
  kernel-mode exceptions. The 4 user-mode faults are `probe` and `elf-crash`, twice each.
- Escalation attempts leave no process behind and are recorded as `PROCESS_CREATE/DENY`.

## What was added or fixed

- `axiom-x-ledger` (new, in `cargo test`):
  - dependency-free SHA-256, checked against the NIST vectors (empty, "abc", the
    two-block message, one million "a") and odd incremental splits;
  - a fixed 96-byte record encoding with a `prev` digest;
  - a `Ledger<N>` ring whose head and sequence continue across eviction;
  - `verify_link` / `verify_window`, with tests for tampering, re-hash forgery and eviction.
- `axiom-x-arch/src/governance.rs`:
  - per-process `Rights`, plus the required-right table: `write`→SEND,
    `AX_SPAWN_MODULE`→SPAWN, `AX_GET_EVIDENCE`→EVIDENCE; self-scoped calls need none;
  - the ledger and its record helpers, numbered like `axiom_x_sys::EvidenceType`.
- Syscall path:
  - a rights gate before every dispatch;
  - `AX_SPAWN_MODULE(name, len, rights)` refuses to grant rights the parent lacks;
  - `AX_GET_EVIDENCE` (the declared `AxGetEvidence = 501`) returns an encoded
    record plus its digest, or the record count;
  - ledger records on allow, deny, block, exit, kill (via `mark_ended`) and reap
    (by `wait4` and by the kernel reaper).
- **Race fixed (found by this test):** a new process became runnable before its
  rights and parent were set. A preempted kernel let `elf-init` run with zero
  rights, which failed closed with a spurious `-EPERM`. Now parent and rights are
  written in the same critical section that sets `Runnable` (`activate_new`).
- `axiom-x-capability` previously did not compile at all:
  - fixed a missing `}` in `build()`, plus a second `next_id` increment that made
    every built capability skip an ID;
  - added the missing `BitOr`/`BitOrAssign`/`BitAnd` for `Rights`;
  - fixed two test bugs (`u64::next()`, and an assertion that an attenuated child
    may delegate);
  - removed the unused `extern crate alloc` and `String`/`Vec`/`BTreeMap` imports,
    which forced an allocator on every user;
  - the principal dependency is now `default-features = false`, so the crate builds
    for bare metal.
- `axiom-x-user`: `spawn(name, rights)`, `evidence()`, `evidence_count()`, and the
  new programs `elf-noperm` and `elf-audit`. Init now grants least privilege per child.

## Known gaps

- `axiom-x-capability-lineage` still does not compile (`DelegationResult` is defined
  twice, and more). The kernel does not use it. Delegation history lives in the ledger
  (`PROCESS_CREATE` records with parent, child and rights), not in that crate.
- No signatures or attestation: "registered authority + signature" (ACC) remains
  `declared`. Nothing proves the ledger to a party outside the machine (no anchoring,
  no signing key).
- The ledger lives in memory (a 1024-record ring); it is not persisted across boots.
- Rights are coarse (one bit per class). Constraints, regions and revocation
  generations from the capability crate are not enforced yet.
