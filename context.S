; context.S — Assembly Context Switch for Axiom-X x86_64
;
; Provides save_context / restore_context matching the CpuContext layout
; defined in axiom-x-arch/src/process.rs (repr(C, packed)):
;
;   r15=0x00 r14=0x08 r13=0x10 r12=0x18 rbx=0x20 rbp=0x28
;   rip=0x30 rdi=0x38 rsi=0x40 rdx=0x48 rcx=0x50 rax=0x58
;   r8=0x60  r9=0x68  r10=0x70 r11=0x78
;   rsp=0x80 rflags=0x88 cs=0x90 ss=0x92 ds=0x94 es=0x96 fs=0x98 gs=0x9a
;   fs_base=0x9c gs_base=0xa4 cr3=0xac
;
; System V ABI: first argument (ctx pointer) in RDI.

section .text
global save_context
global restore_context

; ============================================================
; save_context(ctx: *mut CpuContext)
; ============================================================
save_context:
    ; RDI = ctx pointer

    ; ---- Callee-saved registers ----
    mov [rdi + 0x00], r15
    mov [rdi + 0x08], r14
    mov [rdi + 0x10], r13
    mov [rdi + 0x18], r12
    mov [rdi + 0x20], rbx
    mov [rdi + 0x28], rbp

    ; ---- RIP: return address is on the stack at [rsp] ----
    mov rax, [rsp]
    mov [rdi + 0x30], rax

    ; ---- Caller-saved registers ----
    mov [rdi + 0x38], rdi        ; ctx pointer itself (will be restored later)
    mov [rdi + 0x40], rsi
    mov [rdi + 0x48], rdx
    mov [rdi + 0x50], rcx
    mov [rdi + 0x58], rax
    mov [rdi + 0x60], r8
    mov [rdi + 0x68], r9
    mov [rdi + 0x70], r10
    mov [rdi + 0x78], r11

    ; ---- RSP (points past the return address) ----
    lea rax, [rsp + 8]
    mov [rdi + 0x80], rax

    ; ---- RFLAGS ----
    pushfq
    pop rax
    mov [rdi + 0x88], rax

    ; ---- Segment registers ----
    mov [rdi + 0x90], cs
    mov [rdi + 0x92], ss
    mov [rdi + 0x94], ds
    mov [rdi + 0x96], es
    mov [rdi + 0x98], fs
    mov [rdi + 0x9a], gs

    ; ---- FS base (IA32_FS_BASE = 0xC0000100) ----
    mov ecx, 0xC0000100
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rdi + 0x9c], rax

    ; ---- GS base (IA32_GS_BASE = 0xC0000101) ----
    mov ecx, 0xC0000101
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rdi + 0xa4], rax

    ; ---- CR3 ----
    mov rax, cr3
    mov [rdi + 0xac], rax

    ret

; ============================================================
; restore_context(ctx: *const CpuContext) -> !
; ============================================================
restore_context:
    ; RDI = ctx pointer (must preserve until rdi is restored)

    ; ---- CR3 first: switch address space ----
    mov rax, [rdi + 0xac]
    mov cr3, rax

    ; ---- FS base ----
    mov ecx, 0xC0000100
    mov rax, [rdi + 0x9c]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    ; ---- GS base ----
    mov ecx, 0xC0000101
    mov rax, [rdi + 0xa4]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    ; ---- Segment registers (data segments) ----
    mov ds, word [rdi + 0x94]
    mov es, word [rdi + 0x96]
    mov fs, word [rdi + 0x98]
    mov gs, word [rdi + 0x9a]

    ; ---- RFLAGS ----
    push qword [rdi + 0x88]
    popfq

    ; ---- Restore caller-saved registers except RDI (our ctx pointer) ----
    mov r11, [rdi + 0x78]
    mov r10, [rdi + 0x70]
    mov r9,  [rdi + 0x68]
    mov r8,  [rdi + 0x60]
    mov rax, [rdi + 0x58]
    mov rcx, [rdi + 0x50]
    mov rdx, [rdi + 0x48]
    mov rsi, [rdi + 0x40]

    ; ---- Switch to target stack ----
    mov rsp, [rdi + 0x80]

    ; ---- Build IRETQ frame: pops RIP, CS, RFLAGS, RSP, SS ----
    ; Push in reverse order: SS, RSP, RFLAGS, CS, RIP
    movzx rax, word [rdi + 0x92]   ; SS
    push rax
    mov rax, [rdi + 0x80]          ; RSP
    push rax
    mov rax, [rdi + 0x88]          ; RFLAGS
    push rax
    movzx rax, word [rdi + 0x90]   ; CS
    push rax
    mov rax, [rdi + 0x30]          ; RIP
    push rax

    ; ---- Restore callee-saved registers (RDI last) ----
    mov r15, [rdi + 0x00]
    mov r14, [rdi + 0x08]
    mov r13, [rdi + 0x10]
    mov r12, [rdi + 0x18]
    mov rbx, [rdi + 0x20]
    mov rbp, [rdi + 0x28]
    mov rdi, [rdi + 0x38]          ; RDI loaded from context (old RDI still valid for the address)

    iretq
