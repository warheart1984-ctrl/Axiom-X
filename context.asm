.code

EXTERN syscall_dispatch:PROC

PUBLIC save_context
PUBLIC restore_context
PUBLIC syscall_entry

; MSR constants
IA32_FS_BASE        EQU 0C0000100h
IA32_KERNEL_GS_BASE EQU 0C0000102h   ; inactive (user) GS base while in kernel

; ============================================================
; save_context(ctx: *mut CpuContext)
; Saves current CPU context to the provided CpuContext struct
; ============================================================
; Ordering follows the Linux 7.0.0-39 reference semantics (see
; evidence/RE-LINUX-MECHANISMS-EVIDENCE-2026-10-28.md): caller-saved regs are
; stored BEFORE rax becomes scratch, and the user GS base is the INACTIVE
; slot (KERNEL_GS_BASE), never the kernel's active GS.
save_context PROC
    ; RCX = ctx pointer (Microsoft x64 calling convention)

    ; Caller-saved FIRST: rax must be stored before it becomes scratch for
    ; the return address (storing RIP into ctx.rax loses the real rax).
    MOV [RCX + 58h], RAX
    MOV [RCX + 38h], RDI
    MOV [RCX + 40h], RSI
    MOV [RCX + 48h], RDX
    MOV [RCX + 50h], RCX        ; ctx pointer as the saved rcx value
    MOV [RCX + 60h], R8
    MOV [RCX + 68h], R9
    MOV [RCX + 70h], R10
    MOV [RCX + 78h], R11

    ; R10's slot is written; use it to preserve the ctx pointer across the
    ; RDMSR blocks below (RDMSR consumes RCX).
    MOV R10, RCX

    ; Callee-saved registers
    MOV [R10 + 00h], R15
    MOV [R10 + 08h], R14
    MOV [R10 + 10h], R13
    MOV [R10 + 18h], R12
    MOV [R10 + 20h], RBX
    MOV [R10 + 28h], RBP

    ; RIP (return address on stack at [rsp])
    MOV RAX, [RSP]
    MOV [R10 + 30h], RAX

    ; RSP (past the return address)
    LEA RAX, [RSP + 8]
    MOV [R10 + 80h], RAX

    ; RFLAGS (saved only; iretq applies it on restore)
    PUSHFQ
    POP RAX
    MOV [R10 + 88h], RAX

    ; Segment registers
    MOV [R10 + 90h], CS
    MOV [R10 + 92h], SS
    MOV [R10 + 94h], DS
    MOV [R10 + 96h], ES
    MOV [R10 + 98h], FS
    MOV [R10 + 9Ah], GS

    ; FS base: RDMSR returns EDX:EAX — join high/low into RAX.
    MOV RCX, IA32_FS_BASE
    RDMSR
    SHL RDX, 32
    OR RAX, RDX
    MOV [R10 + 9Ch], RAX

    ; User GS base: the inactive slot (KERNEL_GS_BASE). In kernel mode the
    ; active GS_BASE is the kernel's; the user TLS base lives here.
    MOV RCX, IA32_KERNEL_GS_BASE
    RDMSR
    SHL RDX, 32
    OR RAX, RDX
    MOV [R10 + 0A4h], RAX

    ; CR3
    MOV RAX, CR3
    MOV [R10 + 0ACh], RAX

    RET
save_context ENDP

; ============================================================
; restore_context(ctx: *const CpuContext) -> !
; Restores CPU context from the provided CpuContext struct and jumps to RIP
; ============================================================
; RFLAGS is applied exactly once — by iretq — so no interrupt observes a
; half-restored context. R10 holds the ctx pointer through the WRMSR blocks
; and the register reload (RCX is consumed by both).
restore_context PROC
    ; RCX = ctx pointer — preserve it in R10 immediately.
    MOV R10, RCX

    ; CR3 first: switch address space (ctx is kernel-mapped everywhere)
    MOV RAX, [R10 + 0ACh]
    MOV CR3, RAX

    ; FS base: split the 64-bit value into EDX:EAX for WRMSR.
    MOV RCX, IA32_FS_BASE
    MOV RAX, [R10 + 9Ch]
    MOV RDX, RAX
    SHR RDX, 32
    WRMSR

    ; User GS base -> the inactive slot; swapgs hands it to ring 3.
    MOV RCX, IA32_KERNEL_GS_BASE
    MOV RAX, [R10 + 0A4h]
    MOV RDX, RAX
    SHR RDX, 32
    WRMSR

    ; Segment registers (data segments)
    MOV DS, WORD PTR [R10 + 94h]
    MOV ES, WORD PTR [R10 + 96h]
    MOV FS, WORD PTR [R10 + 98h]
    MOV GS, WORD PTR [R10 + 9Ah]

    ; (No early POPFQ: iretq applies RFLAGS atomically.)

    ; Caller-saved registers (RCX/RDI handled at the end)
    MOV R11, [R10 + 78h]
    MOV R9,  [R10 + 68h]
    MOV R8,  [R10 + 60h]
    MOV RAX, [R10 + 58h]
    MOV RDX, [R10 + 48h]
    MOV RSI, [R10 + 40h]

    ; Callee-saved registers
    MOV R15, [R10 + 00h]
    MOV R14, [R10 + 08h]
    MOV R13, [R10 + 10h]
    MOV R12, [R10 + 18h]
    MOV RBX, [R10 + 20h]
    MOV RBP, [R10 + 28h]

    ; Switch to the target stack, then build the IRETQ frame on it.
    ; iretq pops RIP, CS, RFLAGS, RSP, SS — push in reverse order.
    MOV RSP, [R10 + 80h]
    MOVZX RAX, WORD PTR [R10 + 92h]  ; SS  (0x92 — not 0x20)
    PUSH RAX
    MOV RAX, [R10 + 80h]             ; RSP
    PUSH RAX
    MOV RAX, [R10 + 88h]             ; RFLAGS — applied once, here
    PUSH RAX
    MOVZX RAX, WORD PTR [R10 + 90h]  ; CS  (0x90 — not 0x08)
    PUSH RAX
    MOV RAX, [R10 + 30h]             ; RIP
    PUSH RAX

    ; RDI and RCX last: R10 was the ctx pointer until now.
    MOV RDI, [R10 + 38h]
    MOV RCX, [R10 + 50h]

    IRETQ
restore_context ENDP

; ============================================================
; syscall_entry() -> !
; SYSCALL fast path entry point (assembly)
; ============================================================
syscall_entry PROC
    ; Save user RSP
    SWAPGS
    MOV GS:[0], RSP           ; Save to per-CPU area
    MOV RSP, GS:[8]           ; Load kernel stack

    ; Save registers (same layout as context switch)
    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8
    PUSH RSI
    PUSH RDI
    PUSH RBP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX

    ; Call syscall handler
    MOV RDI, RSP              ; Pass register frame pointer
    CALL syscall_dispatch

    ; Restore registers
    POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP
    POP RDI
    POP RSI
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

    ; Restore user RSP
    MOV RSP, GS:[0]
    SWAPGS
    SYSRET
syscall_entry ENDP

END