# AGENTS.md — Axiom-X

> Binding on every AI agent operating in this repository.
> Axiom-X was split out of `Sovereign-X-Constitutional-Compute` (its `axiom-x/` folder, with full history) on 2026-10-18. These rules carry over its evidence discipline; the Sovereign X JavaScript checks do not apply here.

## Precedence

1. Evidence-bound claims: nothing is described as working without a test or a captured run (serial log, `ledger-tool` output) that shows it.
2. This file.
3. LineageStudio agent/skill conventions (`G:\LineageStudio\.cursor\`), where they do not conflict with 1–2.
4. Never claim hardware, photonic or quantum enforcement. Hyper-V is hardware virtualization, not bare metal, and nothing here has booted on bare metal yet.

## Status tags (mandatory)

Use only: `enforced` | `partial` | `declared` | `skeleton` | `roadmap`.

| Tag | Meaning |
|-----|---------|
| enforced | Runtime gate + tests or captured runs pass |
| partial | Implemented with known gaps (say which) |
| declared | Spec / docs only |
| skeleton | Stub surface |
| roadmap | Future intent, not present capability |

## Protected claims

Do not change docs or README to upgrade `declared`/`partial` → `enforced` without adding the tests, runtime gates and evidence (`evidence/*.md` plus logs) in the same change.

## Core principles (this kernel)

1. No system call runs without the right it requires (`governance::required_right`); refusals are recorded.
2. Every governed action appends a record to the SHA-256 evidence ledger; checkpoints are Ed25519-signed.
3. Child processes receive only a subset of their parent's rights.
4. The file system's root hash is anchored in the ledger; a disk that does not match is mounted read-only.

## Secrets and disk images — never commit

- `evidence/ledger.key` (the ledger signing seed), `*.key`
- `*.img`, `*.vhd`, `*.iso`, `evidence/hyperv/`, `*.before-hyperv`

Before every commit, check the staged index for the seed:

```bash
SEED=$(xxd -p -c 32 evidence/ledger.key); git grep --cached -l "$SEED"   # must print nothing
```

Use scratch disk images (`LEDGER_DISK=evidence/tmp/… FS_DISK=evidence/tmp/…`) for experiments. The canonical `evidence/ledger.img` / `evidence/fs.img` pair only advances through deliberate runs. `qemu-boot.sh` creates a **new** signing key if `evidence/ledger.key` is missing, which would start a different signing identity.

## Checks before commit

```bash
cargo test                                                    # host tests
cargo build --target x86_64-unknown-none -p axiom-x-boot --bin kernel \
    --no-default-features --features freestanding             # the kernel
(cd axiom-x-user && CARGO_PROFILE_RELEASE_LTO=false \
    cargo build --release --target x86_64-unknown-none)       # user programs
```

For changes to kernel behaviour, also boot in QEMU (`qemu-boot.sh`, in WSL) and keep the evidence: the self-tests must PASS, and `ledger-tool verify` / `fs-verify` must pass on the disks used.

## Commits

End commit messages with the attribution trailer the session specifies. The user runs anything that needs administrator rights (Hyper-V) themselves.
