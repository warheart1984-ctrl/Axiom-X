# Axiom-X reverse-engineering evidence — Linux kernel mechanisms — 2026-10-28

**Claim:** three kernel mechanisms needed by `partial`/`skeleton` Axiom-X
subsystems were reverse-engineered from the shipping Ubuntu kernel
`7.0.0-39-generic` and reduced to semantics Axiom-X can implement in its own
structures. Semantics lifted; no code ported. Status tag for each mechanism
below describes the *reference understanding*, not Axiom-X capability — nothing
here is implemented in the kernel yet.

| Mechanism | Axiom-X consumer | Reference status |
|-----------|------------------|------------------|
| `__switch_to_asm` + `__switch_to` | `context.S` (missing) | semantics captured — `roadmap` input |
| `entry_SYSCALL_64` | `syscall_entry` stubs (all `ENOSYS`) | semantics captured — `roadmap` input |
| `handle_mm_fault` / `__handle_mm_fault` | page-table traits (TODO) | semantics captured — `roadmap` input |

## Target and method

| Item | Value |
|------|-------|
| ISO source | `ubuntu-26.04.1-desktop-amd64.iso`, `casper/vmlinuz` (kernel `7.0.0-30-generic`, bzImage) |
| Analyzed binary | `vmlinux-7.0.0-39-generic` from `linux-image-unsigned-7.0.0-39-generic-dbgsym_7.0.0-39.39_amd64.ddeb` (ddebs.ubuntu.com) |
| Format | ELF 64-bit x86-64, not stripped, full DWARF |
| sha256 | `a16600565c94dae45d17a237d602aed606e96af504214d86f523ca1dddd429ad` |
| Tool | `objdump -d --disassemble=<sym> --no-show-raw-insn` (WSL2 Ubuntu-24.04) |

**Method honesty note:** the ISO's `vmlinuz` bzImage resisted payload extraction
(zstd/gzip/xz/bzip2/lzma magic-scan all failed to produce ELF); the dbgsym
`.ddeb` route was used instead. Version skew -30 → -39 is immaterial at
mechanism level. REA MCP dropped connection during native analysis; objdump +
DWARF provided the evidence directly.

## 1. Context switch — `__switch_to_asm` @ `0xffffffff81347a00`

The entire hardware switch:

```asm
push rbp; push rbx; push r12; push r13; push r14; push r15   ; callee-saved, OLD stack
mov  %rsp, 0x25f8(%rdi)                                     ; prev->thread.sp  = rsp
mov  0x25f8(%rsi), %rsp                                     ; rsp = next->thread.sp  ← THE switch
mov  0xaf8(%rsi), %rbx                                      ; canary from next
mov  %rbx, %gs:__stack_chk_guard
jmp  +0x52                                                  ; over mitigation nops
pop  %r15; pop %r14; pop %r13; pop %r12; pop %rbx; pop %rbp ; callee-saved, NEW stack
jmp  __switch_to                                            ; tail-call C half
```

`__switch_to` (C half @ `0xffffffff8139dda0`) then: saves/restores `fs`/`gs`
selectors + `rdfsbase`/`rdgsbase` (thread offsets `0x2600`–`0x2610`); `rdpkru`/
`wrpkru` for protection keys (`0x2674`); sets `current_task` and
`cpu_current_top_of_stack = next->stack + 0x3ff0` → `update_task_stack` writes
TSS `rsp0`; normalizes `es`/`ds`/`ss` to kernel data `0x18`; **zeroes all
caller-saved regs before returning** (retbleed/info-leak hygiene); returns
`prev` in `rax`.

**Lift for `context.S`:** the switch IS the `rsp` swap into a per-task `sp`
slot — ~15 instructions. Only callee-saved GPRs belong in the switch.
**Deferred:** FPU/SSE is *not* in the switch — Linux marks
`TIF_NEED_FPU_LOAD` lazily and restores `fpstate` on the return-to-user path.
Axiom-X should flag lazy FPU, not save XMM in the switch.
**Axiom-X addition:** `current_task = next` is the natural hook for a ledger
`SCHEDULE` receipt (no schedule without intent).

## 2. Syscall entry — `entry_SYSCALL_64` @ `0xffffffff81000080`

Hardware contract (`SYSCALL` insn): `rcx`=user RIP, `r11`=user RFLAGS,
`cs`/`ss` from STAR/LSTAR — **`rsp` is NOT switched**.

```asm
swapgs
mov  %rsp, %gs:tss.sp_scratch        ; save user rsp in per-CPU scratch
jmp  +0x1f                           ; KPTI block: and ~0x1800,cr3 → kernel PCID
mov  %gs:cpu_current_top_of_stack,%rsp  ; kernel stack — the __switch_to contract

entry_SYSCALL_64_safe_stack:
push $0x2b; push user_rsp; push %r11; push $0x33; push %rcx   ; 5-word hw frame, by hand

after_hwframe:
push rax rdi rsi rdx rcx $-38(orig_ax=-ENOSYS) r8-r11 rbx rbp r12-r15   ; pt_regs
xor  esi..r15d                   ; zero all scratch regs — speculation hygiene
mov  %rsp,%rdi; movslq %eax,%rsi ; pt_regs*, nr
call do_syscall_64               ; nr → dispatch
test %al,%al → syscall_return_via_sysret | common_interrupt_return
```

Return path restores SPEC_CTRL, pops everything, swaps to trampoline stack,
`swapgs`+`sysret`.

**Lift for `syscall_entry`:** swapgs → save user rsp in per-CPU scratch → load
kernel stack top (TSS `rsp0` — why the context switch maintains it) → build
5-word frame by hand → push pt_regs → **zero scratch regs before C** → call
dispatcher. `do_syscall_64` is exactly where `governance::required_right(nr)`
belongs: `-EPERM` + ledger record on refusal.
**Deferred:** KPTI CR3 switch (`and ~0x1800`) — note its position (before any
kernel stack load); skip for first pass, revisit for Intel bare metal.

## 3. Page fault — `handle_mm_fault` @ `0xffffffff818029e0`

**Two layers, deliberately separated.**

Outer `handle_mm_fault` — policy before tables:
- classify flags (write `0x1`, instruction `0x8`-ish, remote `0x400`)
- **VMA permission check FIRST** — write fault vs `vma->flags` write bits at
  `vma+0x20`; fail fast before touching tables
- PKRU allow check (`__pkru_allows_pkey`)
- accounting hooks (memcg) → Axiom-X's ledger slot
- `call __handle_mm_fault`, then **normalize return into tiny enum**
  (`and ~1`, check `0x400` OOM)

Inner `__handle_mm_fault` @ `0xffffffff818022b0` — the mechanical walk:
- fault frame on stack; `index=(addr-vm_start)>>12+pgoff`; `addr & ~0xfff`
- `pgd = mm->pgd` (offset `0x78`); per level: `entry = tbl[addr>>shift & 0x1ff]`
- `p4d_offset` — **folded to pgd on 4-level**, real on 5-level: the trait
  abstraction Linux solved — same code walks N levels, folded level is identity
- `0x80` (_PAGE_PSE) tested at PUD → 1GB huge path — huge pages are early
  exits *at each level*, not a separate walk
- `phys→virt` via `physical_mask` + `page_offset_base` — kernel needs a linear
  map for table memory

**Lift for page-table traits:** (1) permission-check before walk; (2)
levelwise walk with early exits; (3) foldable intermediate level so
4-vs-5-level is config, not code; (4) return codes collapse to a small enum at
the policy boundary.

## What was deliberately left

- All C code — ambient-authority assumptions throughout; incompatible with the
  rights model.
- Speculation mitigations (SPEC_CTRL wrmsr, retpoline thunks, KPTI) — noted at
  their positions for when Axiom-X hits bare Intel metal.
- PKU/PKRU — no protection keys in Axiom-X.
- Paravirt indirection (`pv_ops`) — QEMU TCG target doesn't need it.

## Reproduce

```bash
# vmlinux from dbgsym:
curl -LO https://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-7.0.0-39-generic-dbgsym_7.0.0-39.39_amd64.ddeb
ar x linux-image-unsigned-*.ddeb && tar -xf data.tar.xz usr/lib/debug/boot/
objdump -d --disassemble=__switch_to_asm --no-show-raw-insn usr/lib/debug/boot/vmlinux-7.0.0-39-generic
objdump -d --start-address=0xffffffff81000080 --stop-address=0xffffffff81000170 --no-show-raw-insn usr/lib/debug/boot/vmlinux-7.0.0-39-generic
objdump -d --disassemble=__handle_mm_fault --no-show-raw-insn usr/lib/debug/boot/vmlinux-7.0.0-39-generic
```

## Files

- `D:\vmlinux-7.0.0-39-generic` — analyzed binary (506,825,440 bytes)
- `D:\linux-vmlinux-7.0.0-39.ddeb` — source package (2,090,376,628 bytes)
- `D:\ubuntu-26.04.1-desktop-amd64.iso` — live-boot source for traced-boot
  comparison (next phase: QEMU `-d int` traces vs Axiom-X serial)
