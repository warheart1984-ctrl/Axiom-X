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
;
; Ordering follows the mechanism semantics reverse-engineered from Linux
; 7.0.0-39-generic (evidence/RE-LINUX-MECHANISMS-EVIDENCE-2026-10-28.md):
; the switch is the rsp swap into a per-task slot; FS/GS base, segment and
; rflags state ride in the saved context; RFLAGS is applied once, atomically,
; by iretq — never early via popfq.

section .text
global save_context
global restore_context

; ============================================================
; save_context(ctx: *mut CpuContext)
; ============================================================
; Called from context_switch() while the outgoing process is Running.
; [rsp] holds our return address -> ctx.rip; rsp+8 is the resume rsp.
save_context:
    ; RDI = ctx pointer

    ; ---- Caller-saved FIRST: rax must be stored before it is used as
    ;      scratch for the return address (bug: storing rax after loading
    ;      the rip value saved RIP into ctx.rax and lost the real rax). ----
    mov [rdi + 0x58], rax        ; real rax
    mov [rdi + 0x38], rdi        ; ctx pointer itself (restored last)
    mov [rdi + 0x40], rsi
    mov [rdi + 0x48], rdx
    mov [rdi + 0x50], rcx
    mov [rdi + 0x60], r8
    mov [rdi + 0x68], r9
    mov [rdi + 0x70], r10
    mov [rdi + 0x78], r11

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

    ; ---- RSP (points past the return address) ----
    lea rax, [rsp + 8]
    mov [rdi + 0x80], rax

    ; ---- RFLAGS (saved only; iretq applies it on restore) ----
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

    ; ---- FS base (IA32_FS_BASE = 0xC0000100): real TLS base, unswapped ----
    mov ecx, 0xC0000100
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov [rdi + 0x9c], rax

    ; ---- GS base: we are in kernel mode, so IA32_GS_BASE (0xC0000101)
    ;      holds the KERNEL base. The user GS base lives in the inactive
    ;      slot IA32_KERNEL_GS_BASE (0xC0000102) — Linux's
    ;      __rdgsbase_inactive equivalent. ctx.gs_base is documented as
    ;      per-process TLS state -> save the inactive (user) base. ----
    mov ecx, 0xC0000102
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
; Switches address space, restores TLS/segment state, moves to the target
; stack, builds the iretq frame there, and jumps. RFLAGS is applied exactly
; once — by iretq — so no interrupt can observe a half-restored context.
; Linux's __switch_to zeroes caller-saved regs before return for speculation
; hygiene; here every register is loaded from ctx, so any leftover value is
; process-intended state, and fresh contexts start zeroed by Default.
restore_context:
    ; RDI = ctx pointer (kernel-mapped in every address space — the physmap
    ; covers it after the CR3 switch below)

    ; ---- CR3 first: switch address space ----
    mov rax, [rdi + 0xac]
    mov cr3, rax

    ; ---- FS base (IA32_FS_BASE) ----
    mov ecx, 0xC0000100
    mov rax, [rdi + 0x9c]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    ; ---- GS base: write the INACTIVE slot (IA32_KERNEL_GS_BASE = 0xC0000102)
    ;      so the next swapgs on kernel exit hands this base to ring 3.
    ;      Writing active GS_BASE here would corrupt the kernel's own GS. ----
    mov ecx, 0xC0000102
    mov rax, [rdi + 0xa4]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    ; ---- Segment registers (data segments) ----
    mov ds, word [rdi + 0x94]
    mov es, word [rdi + 0x96]
    mov fs, word [rdi + 0x98]
    mov gs, word [rdi + 0x9a]

    ; (No early popfq: iretq restores RFLAGS atomically with CS/RIP/RSP/SS.)

    ; ---- Restore caller-saved registers except RDI (our ctx pointer) ----
    mov r11, [rdi + 0x78]
    mov r10, [rdi + 0x70]
    mov r9,  [rdi + 0x68]
    mov r8,  [rdi + 0x60]
    mov rax, [rdi + 0x58]
    mov rcx, [rdi + 0x50]
    mov rdx, [rdi + 0x48]
    mov rsi, [rdi + 0x40]

    ; ---- Callee-saved registers ----
    mov r15, [rdi + 0x00]
    mov r14, [rdi + 0x08]
    mov r13, [rdi + 0x10]
    mov r12, [rdi + 0x18]
    mov rbx, [rdi + 0x20]
    mov rbp, [rdi + 0x28]

    ; ---- Switch to the target stack and build the IRETQ frame on it.
    ;      iretq pops RIP, CS, RFLAGS, RSP, SS — push in reverse order. ----
    mov rsp, [rdi + 0x80]
    movzx rax, word [rdi + 0x92]   ; SS
    push rax
    mov rax, [rdi + 0x80]          ; RSP (the post-iretq value)
    push rax
    mov rax, [rdi + 0x88]          ; RFLAGS — applied once, here
    push rax
    movzx rax, word [rdi + 0x90]   ; CS
    push rax
    mov rax, [rdi + 0x30]          ; RIP
    push rax

    ; ---- RDI last: it was the ctx pointer until now ----
    mov rdi, [rdi + 0x38]

    iretq
