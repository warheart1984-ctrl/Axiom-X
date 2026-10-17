# Axiom-X MVP Plan — Phase 1: Bootable Microkernel for CoGOS

> **Objective**: Reach a bootable microkernel that can host Wolf CoG OS (UL transport + semantic governance).
> **Current State**: All crates compile; `cargo check --workspace` passes; `cargo test` passes for host-testable crates.
> **Blockers**: Assembly entry (boot.S), context.S, kernel.ld, CR3 loading, PIC/IDT host ICE, page table manager, scheduler integration, syscall implementations, evidence logging.

---

## INVENTORY: What Exists vs. What's Missing

| Component | File | Status | MVP Gap |
|-----------|------|--------|---------|
| **Memory Algebra** | `axiom-x-math/src/memory_algebra.rs` | `partial` ✅ | Allocation logic done; needs integration with boot memory map |
| **Scheduler Math** | `axiom-x-math/src/scheduler_math.rs` | `partial` ✅ | Core math done; needs hardware counter integration (PMU/TSC) |
| **Process Model** | `axiom-x-arch/src/process.rs` | `skeleton` | CpuContext ✅; save/restore_context ASM stubs ✅; needs context.S |
| **IDT/Exceptions** | `axiom-x-arch/src/interrupts.rs` | `skeleton` | Handlers defined; `init_idt()` ✅; PIC remap ✅; **host ICE on error-code handlers** |
| **Syscall Dispatch** | `axiom-x-arch/src/interrupts.rs` | `skeleton` | syscall_entry ASM ✅; dispatch table ✅; **all stubs return ENOSYS** |
| **Process Table** | `axiom-x-arch/src/process.rs` | `skeleton` | Add/get/remove ✅; PID alloc ✅; state machine ✅ |
| **Context Switch** | `axiom-x-arch/src/process.rs` | `skeleton` | save/restore_context ASM ✅; CR3 switch ✅; needs context.S |
| **Boot Path** | `axiom-x-boot/src/lib.rs` | `skeleton` | Multiboot2 parse ✅; early page tables ✅; heap ✅; serial ✅; **boot.S MISSING** |
| **Kernel Entry** | `axiom-x-kernel/src/lib.rs` | `skeleton` | kernel_main ✅; init_kernel ✅; start_scheduling ✅; **needs boot.S → ax_kernel_entry** |
| **Syscall Interface** | `axiom-x-sys/src/lib.rs` | `declared` | 500+ syscall numbers ✅; evidence types ✅; **implementations all stubs** |
| **Arch x86_64** | `axiom-x-arch-x86_64/src/lib.rs` | `partial` | IDT controller ✅; PIC ✅; CPU features ✅; **page table traits TODO** |
| **Test Suite** | `axiom-x-test/src/lib.rs` | `partial` | Math tests ✅; **integration tests TODO** |

---

## CRITICAL PATH (Dependency Order)

```
boot.S (assembly entry)
    │
    ├──► kernel.ld (linker script) ──────────────────────┐
    │                                                     │
    ▼                                                     ▼
ax_kernel_entry() ──► init_early_page_tables() ──► CR3 load
    │                                                     │
    ├──► init_serial() ──► early logging                 │
    │                                                     │
    ├──► parse_multiboot2() ──► memory map               │
    │                                                     │
    ├──► init_early_page_tables() ──► identity + higher-half maps
    │                                                     │
    ├──► init_early_heap() ──► global allocator          │
    │                                                     │
    ├──► init_cpu_features() ──► CPUID, MSRs             │
    │                                                     │
    ├──► init_arch() ──► IDT + PIC + SYSCALL MSRs        │
    │         │                                           │
    │         ├──► init_idt() ──► exception handlers     │
    │         ├──► init_pic() ──► IRQ remap              │
    │         ├──► init_syscall() ──► STAR/LSTAR/SFMASK  │
    │         └──► timer_handler ──► scheduler_tick()    │
    │                                                     │
    ├──► init_scheduler() ──► SchedulerState             │
    │                                                     │
    ├──► ProcessTable creation ──► ProcessTable::new()   │
    │                                                     │
    ├──► FrameAllocator ──► MathFrameAllocator from boot │
    │                                                     │
    ├──► idle_process ──► hlt loop                       │
    │                                                     │
    ├──► init_process (PID 1) ──► spawn userspace        │
    │                                                     │
    └──► context_switch(table, init_pid) ──► never returns
```

---

## MVP TASK LIST (Prioritized)

### P0 — Boot Infrastructure (Week 1-2)

| ID | Task | File(s) | Effort | Owner |
|----|------|---------|--------|-------|
| P0-1 | **Write `boot.S`** — Multiboot2 header, long mode entry, stack setup, call `ax_kernel_entry` | `axiom-x/boot.S` | 1 day | Builder |
| P0-2 | **Write `kernel.ld`** — Section layout, higher-half mapping (0xFFFF_8000_0000_0000), stack, .bss | `axiom-x/kernel.ld` | 0.5 day | Builder |
| P0-3 | **CR3 loading in `ax_kernel_entry`** — Verify `Cr3::write(pml4_frame, ...)` works on real hardware | `axiom-x-boot/src/lib.rs:266` | 0.5 day | Implementor |
| P0-4 | **Early console** — VGA text mode + serial (COM1) dual output | `axiom-x-boot/src/lib.rs:289` | 0.5 day | Implementor |
| P0-5 | **Panic handler** — Serial dump + register state (already in boot, verify) | `axiom-x-boot/src/lib.rs:523` | 0.5 day | Inspector |

### P1 — Interrupts & Scheduler Integration (Week 2-3)

| ID | Task | File(s) | Effort | Owner |
|----|------|---------|--------|-------|
| P1-1 | **Fix host ICE for error-code handlers** — Use `set_handler_addr` workaround or feature-gate for host | `axiom-x-arch/src/interrupts.rs` | 1 day | Implementor |
| P1-2 | **Timer interrupt → `scheduler_tick()` → `context_switch()`** — Wire PIT (IRQ0) to scheduler | `axiom-x-arch/src/interrupts.rs:244` | 1 day | Implementor |
| P1-3 | **PIT initialization** — Configure 100-1000Hz timer in `init_arch()` | `axiom-x-arch-x86_64/src/lib.rs` | 0.5 day | Implementor |
| P1-4 | **Idle process** — Proper `hlt` loop with scheduler idle decision | `axiom-x-boot/src/lib.rs:497` | 0.5 day | Implementor |
| P1-5 | **Process creation** — `AX_FORK`/`AX_SPAWN` syscall implementation | `axiom-x-arch/src/interrupts.rs:402` | 2 days | Implementor |
| P1-6 | **Context switch assembly** — Move `save_context`/`restore_context` to `context.S` (separate .S file) | `axiom-x-arch/src/process.rs:332` | 1 day | Builder |

### P2 — Memory & Syscalls (Week 3-4)

| ID | Task | File(s) | Effort | Owner |
|----|------|---------|--------|-------|
| P2-1 | **Page frame allocator** — Integrate `MathFrameAllocator` with boot memory map | `axiom-x-kernel/src/lib.rs:479` | 1 day | Implementor |
| P2-2 | **Page table manager** — 4-level walk, map/unmap, `PageTableFlags` | `axiom-x-arch-x86_64/src/lib.rs` | 2 days | Implementor |
| P2-3 | **Address space creation** — Per-process PML4, copy-on-write | `axiom-x-arch/src/process.rs:147` | 2 days | Implementor |
| P2-4 | **Core POSIX syscalls** — `fork`, `execve`, `exit`, `mmap`, `munmap`, `brk`, `read`, `write`, `open`, `close` | `axiom-x-arch/src/interrupts.rs:456` | 3 days | Implementor |
| P2-5 | **Axiom-X native syscalls** — `AX_ALLOC_RES`, `AX_FREE_RES`, `AX_SPAWN`, `AX_SCHED_PROFILE`, `AX_GET_EVIDENCE` | `axiom-x-kernel/src/lib.rs:357` | 2 days | Implementor |

### P3 — Evidence & Contracts (Week 4)

| ID | Task | File(s) | Effort | Owner |
|----|------|---------|--------|-------|
| P3-1 | **Evidence log buffer** — Ring buffer in kernel memory | `axiom-x-kernel/src/lib.rs` | 1 day | Implementor |
| P3-2 | **Syscall evidence** — Record every syscall decision (already structured) | `axiom-x-arch/src/interrupts.rs:379` | 1 day | Implementor |
| P3-3 | **Scheduler evidence** — Record every scheduling decision (already logged) | `axiom-x-arch/src/interrupts.rs:276` | 0.5 day | Implementor |
| P3-4 | **Contract verification** — Check invariants on each decision | `axiom-x-kernel/src/lib.rs` | 1 day | Inspector |

### P4 — CoGOS Integration Prep (Week 4-5)

| ID | Task | File(s) | Effort | Owner |
|----|------|---------|--------|-------|
| P4-1 | **UL verb handler** — New syscall for UL intent dispatch | `axiom-x-sys/src/lib.rs:511` | 1 day | Implementor |
| P4-2 | **Sigil injection** — OS-injected sigil at exec (map to `AxSpawn` contract_id) | `axiom-x-arch/src/interrupts.rs:402` | 1 day | Implementor |
| P4-3 | **Error propagation envelope** — UL code + LawPulse ID + mapped OS error | `axiom-x-sys/src/lib.rs:783` | 1 day | Implementor |

---

## CONSTITUTIONAL CONSTRAINTS (Per AGENTS.md)

| Principle | Application |
|-----------|-------------|
| **P1: No execution without intent** | Every task above has declared purpose (MVP boot, CoGOS integration) |
| **P2: No state change without evidence** | Each implementation must produce `EvidenceRecord` |
| **P3: No authority without contract** | Stay within crate boundaries; no modifying governance files |
| **P4: Replayable reality** | Deterministic tests; no time-dependent behavior in core logic |
| **P5: Sovereign independence** | No vendor lock-in; pure Rust, multiboot2, x86_64 crate only |

**Agent Rules Enforcement**:
- R1: Declare before act — this plan IS the declaration
- R2: Never modify governance files — not needed for MVP
- R3: Preserve evidence chains — all new code must use `EvidenceRecord`
- R5: Respect the math — frame allocator uses conservation invariants; scheduler uses cost function
- R6: Test before commit — `cargo test` must pass
- R10: Constitution over convenience — no shortcuts on `unsafe` blocks

---

## TEST STRATEGY

| Tier | Command | Scope |
|------|---------|-------|
| **Tier 1 (Host)** | `cargo test` | math (24), sys (5), arch-traits (5) — **GREEN** |
| **Tier 2 (Type-check)** | `cargo check --workspace` | All 8 crates — **GREEN** |
| **Tier 3 (Kernel target)** | `cargo build --workspace --target x86_64-unknown-none --no-default-features --features freestanding` | Requires feature gating on std deps (nalgebra, etc.) |
| **Tier 4 (QEMU)** | `qemu-system-x86_64 -kernel target/x86_64-unknown-none/debug/axiom-x-kernel` | Boot → scheduler → init → shell |

---

## IMMEDIATE NEXT STEPS (This Week)

1. **Create `boot.S`** — Minimal multiboot2 entry (see `axiom-x-boot/src/lib.rs:559` for documented template)
2. **Create `kernel.ld`** — Higher-half layout with 16 KiB stack
3. **Add `x86_64-unknown-none` target** — `rustup target add x86_64-unknown-none` (already in rust-toolchain.toml)
4. **Fix host ICE** — Feature-gate error-code interrupt handlers for `std` builds; use `set_handler_addr` workaround
5. **Move `save_context`/`restore_context` to `context.S`** — Separate assembly file for naked functions

---

## COGOS INTEGRATION MILESTONE

| Phase | Target | Description |
|-------|--------|-------------|
| **MVP** | axiom-x boots → idle → init → shell | Pure Rust microkernel |
| **CoGOS-α** | UL verb handler + sigil injection | `AxSpawn` → sigil injection |
| **CoGOS-β** | wine-wolf-bridge port | LD_PRELOAD shim → axiom-x syscall |
| **CoGOS-γ** | Full semantic control plane | K32 plane + LawPulse on axiom-x |

---

## RISK REGISTER

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Assembly context switch bugs | High | Critical | Extensive unit tests, QEMU GDB debugging |
| Page table corruption | Medium | Critical | Formal verification of page table walker |
| Host ICE blocks CI | Medium | High | Feature-gate kernel crates for host; CI only runs `cargo check --workspace` on host |
| Thermal model inaccurate | Medium | High | Calibrate on real hardware, conservative defaults |
| nalgebra std dependency blocks kernel target | Medium | Medium | Disable default features, use `libm`/`alloc` only |

---

## SUCCESS CRITERIA (MVP)

1. ✅ **Boots** on QEMU x86_64 (multiboot2 via GRUB/limine)
2. ✅ **Schedules** 2+ processes with mathematical cost function
3. ✅ **Handles** `fork`/`exec`/`exit`/`mmap` syscalls
4. ✅ **Logs** evidence for every scheduling/memory decision
5. ✅ **Zero** `unsafe` blocks outside `arch/`, `boot/`, `context.S`
6. ✅ **Passes** all `axiom-x-test` invariants (conservation, no aliasing, thermal)

---

*This plan follows LineageStudio conventions. Status tags are mandatory and must not be upgraded without evidence (tests + runtime gates).*