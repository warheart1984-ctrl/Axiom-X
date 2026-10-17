.code

EXTERN syscall_dispatch:PROC

PUBLIC save_context
PUBLIC restore_context
PUBLIC syscall_entry

; MSR constants
IA32_FS_BASE  EQU 0C0000100h
IA32_GS_BASE  EQU 0C0000101h

; ============================================================
; save_context(ctx: *mut CpuContext)
; Saves current CPU context to the provided CpuContext struct
; ============================================================
save_context PROC
    ; RCX = ctx pointer (Microsoft x64 calling convention)
    
    ; Save callee-saved registers
    MOV [RCX + 00h], R15
    MOV [RCX + 08h], R14
    MOV [RCX + 10h], R13
    MOV [RCX + 18h], R12
    MOV [RCX + 20h], RBX
    MOV [RCX + 28h], RBP

    ; Save RIP (return address)
    MOV [RCX + 30h], RSP       ; We'll fix RIP below
    MOV RAX, [RSP]
    MOV [RCX + 30h], RAX

    ; Save caller-saved registers
    MOV [RCX + 38h], RDI
    MOV [RCX + 40h], RSI
    MOV [RCX + 48h], RDX
    MOV [RCX + 50h], RCX
    MOV [RCX + 58h], RAX
    MOV [RCX + 60h], R8
    MOV [RCX + 68h], R9
    MOV [RCX + 70h], R10
    MOV [RCX + 78h], R11

    ; Save RSP (after pushing return address)
    LEA RAX, [RSP + 8]
    MOV [RCX + 80h], RAX

    ; Save RFLAGS
    PUSHFQ
    POP RAX
    MOV [RCX + 88h], RAX

    ; Save segment registers
    MOV [RCX + 90h], CS
    MOV [RCX + 92h], SS
    MOV [RCX + 94h], DS
    MOV [RCX + 96h], ES
    MOV [RCX + 98h], FS
    MOV [RCX + 9Ah], GS

    ; Save FS/GS base (using RDMSR for IA32_FS_BASE/GS_BASE)
    MOV RCX, IA32_FS_BASE
    RDMSR
    MOV [RCX + 9Ch], RAX
    MOV [RCX + 0A4h], RAX
    MOV RCX, IA32_GS_BASE
    RDMSR
    MOV [RCX + 9Ch], RAX
    MOV [RCX + 0A4h], RAX

    ; Save CR3
    MOV RAX, CR3
    MOV [RCX + 0ACh], RAX

    RET
save_context ENDP

; ============================================================
; restore_context(ctx: *const CpuContext) -> !
; Restores CPU context from the provided CpuContext struct and jumps to RIP
; ============================================================
restore_context PROC
    ; RCX = ctx pointer
    
    ; Restore CR3 first (address space switch)
    MOV RAX, [RCX + 0ACh]
    MOV CR3, RAX

    ; Restore FS/GS base (using WRMSR)
    MOV RCX, IA32_FS_BASE
    MOV RAX, [RCX + 9Ch]
    WRMSR
    MOV RCX, IA32_GS_BASE
    MOV RAX, [RCX + 0A4h]
    WRMSR

    ; Restore segment registers (data segments)
    MOV DS, [RCX + 94h]
    MOV ES, [RCX + 96h]
    MOV FS, [RCX + 98h]
    MOV GS, [RCX + 9Ah]

    ; Restore RFLAGS
    PUSH QWORD PTR [RCX + 88h]
    POPFQ

    ; Restore RSP
    MOV RSP, [RCX + 80h]

    ; Restore caller-saved registers
    MOV R11, [RCX + 78h]
    MOV R10, [RCX + 70h]
    MOV R9, [RCX + 68h]
    MOV R8, [RCX + 60h]
    MOV RAX, [RCX + 58h]
    MOV RCX, [RCX + 50h]
    MOV RDX, [RCX + 48h]
    MOV RSI, [RCX + 40h]
    MOV RDI, [RCX + 38h]

    ; Restore RIP and callee-saved via IRETQ
    ; Stack layout for IRETQ: RIP, CS, RFLAGS, RSP, SS
    PUSH QWORD PTR [RCX + 20h]  ; SS
    PUSH QWORD PTR [RCX + 80h]  ; RSP
    PUSH QWORD PTR [RCX + 88h]  ; RFLAGS
    PUSH QWORD PTR [RCX + 08h]  ; CS
    PUSH QWORD PTR [RCX + 30h]  ; RIP

    ; Restore callee-saved
    MOV RBP, [RCX + 28h]
    MOV RBX, [RCX + 20h]
    MOV R12, [RCX + 18h]
    MOV R13, [RCX + 10h]
    MOV R14, [RCX + 08h]
    MOV R15, [RCX + 00h]

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