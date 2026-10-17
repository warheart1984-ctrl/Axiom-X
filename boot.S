; boot.S — Multiboot2 -> long mode entry point for Axiom-X x86_64
;
; Boot sequence:
;   1. Bootloader loads this at 1 MiB (physical), CPU in 32-bit protected mode
;   2. EAX = multiboot magic, EBX = multiboot info structure address
;   3. Build identity + higher-half page tables, switch to long mode
;   4. Far jump to 64-bit trampoline (identity-mapped low), call ax_kernel_entry
;
; GRUB multiboot1 magic: 0x2BADB002 (eax on entry)
; GRUB multiboot2 magic: 0x36D76289 (eax on entry)
; QEMU -kernel uses multiboot1 (0x2BADB002)

section .multiboot
align 8

; ============================================================
; Multiboot2 Header (must be within first 8 KiB of image)
; ============================================================
header_start:
    dd 0xE85250D6              ; magic number (multiboot2)
    dd 0                       ; architecture: 0 = i386 (protected mode entry)
    dd header_end - header_start ; header length
    dd 0x100000000 - (0xE85250D6 + 0 + (header_end - header_start)) ; checksum

; Information request tag (memory map, cmdline, modules, framebuffer, ELF sections)
align 8
    dw 1, 0                      ; type = 1, flags = 0
    dd 24                        ; size = 24 bytes
    dd 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ; requested tags

; Framebuffer tag
align 8
    dw 5, 0                      ; type = 5 (framebuffer), flags = 0
    dd 20                        ; size = 20 bytes
    dd 1024, 768, 32             ; preferred width, height, depth
    dd 0, 0                      ; flags, reserved

; End tag
align 8
    dw 0, 0                      ; type = 0 (end), flags = 0
    dd 8                         ; size = 8 bytes

header_end:

; ============================================================
; Entry Point (_start) — 32-bit protected mode, low physical
; ============================================================
section .boot
align 16
.code32
global _start
extern ax_kernel_entry
extern ax_kernel_entry_mb1

_start:
    cli
    cld

    ; Stash multiboot magic in EBP (survives mode switch)
    mov ebp, eax

    ; ------------------------------------------------------------------
    ; Build bootstrap page tables
    ; PML4[0] -> PDPT_ID -> PD_ID : identity map [0, 1GiB)
    ; PML4[256] -> PDPT_HH -> PD_HH : higher-half [VIRT_BASE, VIRT_BASE+1GiB)
    ; ------------------------------------------------------------------
    lea eax, [boot_pdpt]
    or eax, 3                  ; present + writable
    mov [boot_pml4], eax
    lea eax, [boot_pd]
    or eax, 3
    mov [boot_pdpt], eax

    lea eax, [boot_pdpt_hh]
    or eax, 3
    mov [boot_pml4 + 2048], eax
    lea eax, [boot_pd_hh]
    or eax, 3
    mov [boot_pdpt_hh], eax

    ; PD entries: entry[i] = (i << 21) | 0xE3 (P|W|A|D|HUGE), i in 0..512
    lea edi, [boot_pd]
    lea esi, [boot_pd_hh]
    xor ecx, ecx
.fill_pd:
    mov eax, ecx
    shl eax, 21
    or eax, 0xE3
    mov [edi + ecx*4], eax
    mov [esi + ecx*4], eax
    inc ecx
    cmp ecx, 512
    jb .fill_pd

    ; ------------------------------------------------------------------
    ; Install GDT (null | 64-bit code @0x08 | data @0x10)
    ; ------------------------------------------------------------------
    lgdt [boot_gdt_desc]

    ; ------------------------------------------------------------------
    ; PAE
    ; ------------------------------------------------------------------
    mov eax, cr4
    or eax, 0x20               ; CR4.PAE
    mov cr4, eax

    ; CR3 = physical address of boot_pml4
    lea eax, [boot_pml4]
    mov cr3, eax

    ; EFER.LME = 1
    mov ecx, 0xC0000080        ; IA32_EFER
    rdmsr
    or eax, 0x100              ; LME
    wrmsr

    ; CR0.PG = 1 -> long mode active
    mov eax, cr0
    or eax, 0x80000003         ; PG | PE | MP
    mov cr0, eax

    ; Serialize after enabling paging
    jmp 1f
1:

    ; Debug: write 'Y' to serial COM1 after paging enabled
    mov al, 'Y'
    mov dx, 0x3F8
    out dx, al

    ; Far jump: CS = 0x08 (64-bit code), RIP = trampoline64 (identity-mapped low)
    db 0xEA                    ; jmp ptr16:32
    dd trampoline64
    dw 0x08

; ============================================================
; 64-bit trampoline — identity-mapped low physical
; ============================================================
.code64
align 16
trampoline64:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; RDI = multiboot info address (EBX still holds mbi physical address)
    mov rdi, rbx               ; mbi_addr
    mov rsi, rbp               ; magic (stashed in EBP)

    ; Set up a temporary stack for the trampoline
    lea rsp, [boot_stack_top]

    ; Call the higher-half Rust entry point
    ; ax_kernel_entry(uint64_t mbi_addr) -> !
    call ax_kernel_entry

    ; Should never return
.halt:
    cli
    hlt
    jmp .halt

; ============================================================
; Boot-time data (low physical, zeroed by bootloader)
; ============================================================
section .boot_bss
align 4096
boot_pml4:   resb 4096
align 4096
boot_pdpt:   resb 4096
align 4096
boot_pd:     resb 4096
align 4096
boot_pdpt_hh: resb 4096
align 4096
boot_pd_hh:  resb 4096
align 16
boot_stack:  resb 16384
boot_stack_top:

; ============================================================
; GDT (must be low physical for lgdt before paging)
; ============================================================
section .boot
align 16
boot_gdt:
    dq 0                              ; null descriptor
    dq 0x00AF9A000000FFFF             ; 64-bit code, base=0, limit=0xFFFFF, G=1, L=1
    dq 0x00CF92000000FFFF             ; data, base=0, limit=0xFFFFF, G=1, W=1
boot_gdt_end:
align 8
boot_gdt_desc:
    dw boot_gdt_end - boot_gdt - 1
    dq boot_gdt
