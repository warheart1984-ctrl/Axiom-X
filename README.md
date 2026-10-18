# Axiom-X

A small x86-64 kernel in Rust (`no_std`) in which **governance is runtime behaviour**:
- every system call is checked against the calling program's rights;
- every governed action is appended to a hash-chained, signed evidence ledger;
- the file system is anchored in that ledger.

It boots through GRUB (Multiboot2) in QEMU and on Hyper-V Generation 1. It is a debug build on a single CPU, and it has not run on bare metal.

Axiom-X began as the `axiom-x/` folder of [Sovereign-X Constitutional Compute](G:/Sovereign-X-Constitutional-Compute.git). It applies that project's principles in a kernel: no dispatch without authority, evidence for every action, claims bound to evidence. It was split into its own repository on 2026-10-18 with its full history.

## What exists

Every row is backed by an evidence file in `evidence/`.

| Area | Status | Evidence |
|---|---|---|
| Boot to PID 1, ring 3 programs, `int 0x80` syscalls | enforced | `BOOT-`, `RING3-EVIDENCE-2026-10-17.md` |
| Preemptive scheduler, per-process address spaces, ELF loader (W^X) | enforced | `PREEMPT-`, `ELF-`, `LIFECYCLE-EVIDENCE-2026-10-17.md` |
| Rights checked per syscall; SHA-256 evidence ledger | enforced | `GOVERNANCE-EVIDENCE-2026-10-17.md` |
| Ledger persisted, crash-safe, Ed25519-signed, verified off-machine | enforced | `PERSIST-`, `CRASH-SAFETY-`, `SIGNED-LEDGER-EVIDENCE-2026-10-17.md` |
| Clock, PS/2 keyboard + serial console, interactive shell | partial | `SHELL-`, `HYPERV-EVIDENCE-2026-10-18.md` |
| AXFS file system: copy-on-write, hash-verified, ledger-anchored | partial | `FS-EVIDENCE-2026-10-18.md` |
| Local APIC timer tick (Hyper-V tick loss fixed) | partial | `TICK-EVIDENCE-2026-10-18.md` |
| Interrupt-latency measurement and fixes | partial | `LATENCY-EVIDENCE-2026-10-18.md` |
| Locking audit; preemptible FS/spawn syscalls, sleeping FS lock | partial | `LOCKING-AUDIT-`, `PREEMPT-FS-EVIDENCE-2026-10-18.md` |
| SMP, directories, partial file I/O, bare metal | roadmap | none |

## Build and run

```bash
cargo test
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel --no-default-features --features freestanding
(cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false cargo build --release --target x86_64-unknown-none)
LIVE=1 KERNEL_CMDLINE=axiom.selftest=off sh ./qemu-boot.sh     # in WSL (QEMU + GRUB tools), Ctrl-C to stop
```

- **Hyper-V:** `hyperv-run.ps1`, from an elevated PowerShell. The script's header documents it.
- **Off-machine verification:**
  ```bash
  target/release/ledger-tool verify evidence/ledger.img <pubkey>
  target/release/ledger-tool fs-verify evidence/fs.img evidence/ledger.img <pubkey>
  ```
  `ledger-tool pubkey evidence/ledger.key` prints `<pubkey>`.

## Layout notes

- **Workspace.** Host tests cover the ledger, FS, math, sys and arch-traits crates. The kernel crates (`axiom-x-arch`, `axiom-x-boot`, …) build for `x86_64-unknown-none` only.
- **`axiom-x-kernel`** is an older crate excluded from the workspace. It refers to `../../Wolf-CoG-OS/darz-kernel`, which is not part of this repository.

See `AGENTS.md` for the rules contributors (and agents) follow.
