# Axiom-X Microkernel — Implementation Roadmap

> **Status Tags**: `enforced` | `partial` | `declared` | `skeleton` | `roadmap`
> **Primary Protocol**: LineageStudio (`G:\LineageStudio`) — not Mandala MRS crew

---

## Executive Summary

Axiom-X is a mathematically-governed microkernel for x86_64 where:
- Every subsystem is expressed as formal mathematics (state vectors, dynamical systems, conservation laws)
- Every kernel decision is justified by a contract and produces an evidence record
- Resources (CPU, memory, I/O, thermal) are conserved quantities — no subsystem creates resources

---

## Current Implementation Status

| Component | Status | Location | Description |
|-----------|--------|----------|-------------|
| **Workspace** | `enforced` | `axiom-x/Cargo.toml` | 8-crate workspace, `default-members` = host-testable crates |
| **Memory Algebra** | `partial` | `axiom-x-math/src/memory_algebra.rs` | Frame allocator, region algebra, invariants (conservation, no aliasing, no overcommit) |
| **Scheduler Math** | `partial` | `axiom-x-math/src/scheduler_math.rs` | Cost function J=αL+βT+γH, thermal model, priority computation, constrained optimization |
| **Process Management** | `skeleton` | `axiom-x-arch/src/process.rs` | Process table, CpuContext, context switch orchestration |
| **Interrupts/IDT** | `skeleton` | `axiom-x-arch/src/interrupts.rs` | IDT setup, exception handlers, timer IRQ, SYSCALL entry |
| **Boot Path** | `skeleton` | `axiom-x-boot/src/lib.rs` | Multiboot2 parsing, early page tables, kernel heap, serial console |
| **Syscall Interface** | `declared` | `axiom-x-sys/src/lib.rs` | POSIX + Axiom-X native syscalls, evidence records, resource contracts |
| **Kernel Integration** | `skeleton` | `axiom-x-kernel/src/lib.rs` | Dispatcher, subsystem initialization |
| **Test Suite** | `partial` | `axiom-x-test/src/lib.rs` | Unit, property-based, integration tests for math invariants |

---

## Phase 1 — Minimal Microkernel (Mathematical Core) ✅ IN PROGRESS

**Goal**: Bootable microkernel that initializes hardware, starts processes, schedules with mathematical cost function, logs evidence.

### Milestone 1.1: Core Infrastructure (`enforced`)
- [x] Cargo workspace with 6 crates
- [x] Memory algebra with conservation invariants
- [x] Scheduler with cost function + thermal constraints
- [x] Process table + context switch skeleton
- [x] IDT + exception handlers + timer IRQ
- [x] Multiboot2 boot path + early page tables
- [x] Syscall interface definition (POSIX + Axiom-X native)
- [x] Test suite for math invariants

### Milestone 1.2: Boot Integration (`partial` → `enforced`)
- [ ] **Assembly boot entry** (`boot.S`) — multiboot2 header, long mode entry, stack setup, call `ax_kernel_entry`
- [ ] **Linker script** (`kernel.ld`) — proper section layout, higher-half kernel mapping
- [ ] **CR3 loading** — switch to kernel page tables at boot
- [ ] **Early console** — VGA + serial output working
- [ ] **Panic handler** — serial dump + register state

### Milestone 1.3: Scheduler Integration (`skeleton` → `enforced`)
- [ ] **Timer interrupt** → `scheduler_tick()` → `context_switch()`
- [ ] **Process creation** — `AX_FORK`/`AX_SPAWN` syscall implementation
- [ ] **Context switch assembly** — `save_context`/`restore_context` in `context.S`
- [ ] **Idle process** — runs `hlt` when no work
- [ ] **Init process** — PID 1, spawns userspace

### Milestone 1.4: Memory Algebra Integration (`partial` → `enforced`)
- [ ] **Page frame allocator** — integrate `FrameAllocator` with boot memory map
- [ ] **Page table manager** — 4-level page table walk, map/unmap
- [ ] **Address space creation** — per-process PML4, copy-on-write
- [ ] **Syscalls** — `AX_MAP`, `AX_UNMAP`, `AX_ALLOC_RES`, `AX_FREE_RES`

### Milestone 1.5: Evidence & Contracts (`declared` → `partial`)
- [ ] **Evidence log buffer** — ring buffer in kernel memory
- [ ] **Syscall evidence** — record every syscall decision
- [ ] **Scheduler evidence** — record every scheduling decision
- [ ] **Contract verification** — check invariants on each decision

---

## Phase 2 — Physics-Aware Extensions (`roadmap`)

**Goal**: Add physical models (power, thermal, latency, bandwidth) that constrain scheduling.

### Milestone 2.1: Thermal & Power Models
- [ ] **ACPI parsing** — read thermal zones, cooling devices
- [ ] **Per-core thermal model** — `T(t+1) = T(t) + α·load - β·cooling`
- [ ] **DVFS integration** — frequency/voltage as control input `u(t)`
- [ ] **Thermal throttling** — scheduler respects `T_core < T_max`
- [ ] **Battery model** (ARM) — drain rate, capacity, shutdown threshold

### Milestone 2.2: Latency & Bandwidth Models
- [ ] **Device channel model** — bandwidth, latency, jitter per device
- [ ] **I/O scheduler** — minimize `J_io = δ·latency + ε·queue_pressure`
- [ ] **Memory bandwidth** — DRAM channels, NUMA awareness
- [ ] **Cache model** — LLC partitioning, cache pressure estimation

### Milestone 2.3: Physics-Integrated Scheduling
- [ ] **Multi-objective optimization** — Pareto frontier of latency/throughput/thermal
- [ ] **Control-theoretic scheduler** — feedback from queue lengths → time slices
- [ ] **Predictive thermal** — anticipate thermal from workload patterns

---

## Phase 3 — Constitutional Governance (`roadmap`)

**Goal**: Policies as contracts, evidence replay, verification hooks.

### Milestone 3.1: Contract Engine
- [ ] **Policy language** — declarative contracts for scheduling, memory, isolation, I/O
- [ ] **Contract compiler** — verify at load time, produce decision procedures
- [ ] **Runtime enforcement** — every kernel decision checks contract

### Milestone 3.2: Evidence & Replay
- [ ] **Structured evidence log** — binary format, indexed by replay token
- [ ] **Replay tool** — userspace tool to replay scheduling/memory decisions
- [ ] **Audit API** — `AX_GET_EVIDENCE`, `AX_REPLAY_TOKEN` syscalls

### Milestone 3.3: Verification Hooks
- [ ] **Invariant checker** — periodic verification of conservation laws
- [ ] **Model checking** — TLA+/Alloy specs for critical paths
- [ ] **Formal proofs** — Rust + Prusti/Kani for memory algebra invariants

---

## Dependency Graph

```
                    ┌─────────────────────┐
                    │   Cargo Workspace   │ ◄── Foundation
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │ Memory Algebra │ │Scheduler Math │ │  Arch/Process │
    │  (axiom-x-math)│ │(axiom-x-math) │ │(axiom-x-arch) │
    └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
            │                 │                 │
            └─────────────────┼─────────────────┘
                              ▼
                   ┌─────────────────────┐
                   │   Boot Path         │ ◄── Requires: arch, math
                   │  (axiom-x-boot)     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   Syscall Interface │ ◄── Requires: arch
                   │   (axiom-x-sys)     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   Kernel Integration│ ◄── Requires: ALL
                   │   (axiom-x-kernel)  │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   Assembly Glue     │ ◄── boot.S, context.S
                   │   (boot.S, ctx.S)   │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   Test Suite        │ ◄── Requires: math, kernel
                   │   (axiom-x-test)    │
                   └─────────────────────┘
```

---

## Immediate Next Steps (This Week)

| Priority | Task | Owner | Est. Effort |
|----------|------|-------|-------------|
| P0 | Write `boot.S` (multiboot2 entry, long mode, call `ax_kernel_entry`) | Builder | 1 day |
| P0 | Write `context.S` (save_context, restore_context assembly) | Builder | 1 day |
| P0 | Write `kernel.ld` (linker script, higher-half layout) | Builder | 0.5 day |
| P0 | Integrate timer IRQ → `scheduler_tick()` → `context_switch()` | Implementor | 1 day |
| P0 | Implement `AX_FORK` / `AX_SPAWN` syscall | Implementor | 1 day |
| P1 | Page table manager (map/unmap, COW) | Implementor | 2 days |
| P1 | Evidence log ring buffer + `AX_GET_EVIDENCE` | Implementor | 1 day |
| P1 | Run in QEMU + verify boot → schedule → syscall | Inspector | 1 day |

---

## Quality Gates (Per AGENTS.md)

The workspace is **two-tier**: host-testable crates (`axiom-x-math`, `axiom-x-sys`,
`axiom-x-arch-traits` — the `default-members`) build/run tests on the host. The
freestanding kernel crates (`axiom-x-arch-x86_64`, `axiom-x-arch`, `axiom-x-boot`,
`axiom-x-kernel`, `axiom-x-test`) use target-specific ABIs (`x86-interrupt`, naked
`gs:` asm) that the Windows/MSVC **host** codegen cannot compile (upstream
rustc/LLVM bugs, e.g. rust-lang/rust#109918 family). They are validated at
type level with `cargo check` and for their real target with
`--target x86_64-unknown-none`.

| Gate | Command | Required |
|------|---------|----------|
| **Build (host)** | `cargo build` (default-members) | ✅ Clean |
| **Tests (host)** | `cargo test` (default-members) | ✅ All pass |
| **Check (all)** | `cargo check --workspace` | ✅ Clean |
| **Build (kernel)** | `cargo build --workspace --target x86_64-unknown-none` | ✅ Clean |
| **Clippy** | `cargo clippy --workspace -- -D warnings` | ✅ Clean |
| **Format** | `cargo fmt --all -- --check` | ✅ Clean |
| **Boot Test** | `qemu-system-x86_64 -kernel target/x86_64-unknown-none/.../axiom-x-kernel` | ✅ Boots to init |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Assembly context switch bugs | High | Critical | Extensive unit tests, QEMU GDB debugging |
| Page table corruption | Medium | Critical | Formal verification of page table walker |
| Thermal model inaccurate | Medium | High | Calibrate on real hardware, conservative defaults |
| Contract engine performance | Low | Medium | Benchmark, optimize hot paths |
| Mandala crew confusion | Low | Low | Follow LineageStudio protocol strictly |

---

## Success Criteria for Phase 1 (MVP)

1. **Boots** on QEMU x86_64 (multiboot2, GRUB, or limine)
2. **Schedules** 2+ processes with mathematical cost function
3. **Handles** `fork`/`exec`/`exit`/`mmap` syscalls
4. **Logs** evidence for every scheduling/memory decision
5. **Passes** all `axiom-x-test` invariants (conservation, no aliasing, thermal)
6. **Zero** `unsafe` blocks outside `arch/`, `boot/`, `context.S`

---

## Long-Term Vision

| Phase | Target | Key Deliverable |
|-------|--------|-----------------|
| **1** | MVP Microkernel | Bootable, mathematically-governed, evidence-producing |
| **2** | Physics-Aware | Thermal/DVFS/I/O models integrated into scheduler |
| **3** | Constitutional | Contract engine, replay, formal verification |
| **4** | Multi-Arch | Flux-A (ARM64), Invariant-R (RISC-V) from same math core |
| **5** | Distributed | Capability-based IPC, network transparency, cluster scheduling |

---

*This roadmap follows LineageStudio conventions. Status tags are mandatory and must not be upgraded without evidence (tests + runtime gates).*