/* trampoline.S — 32-bit to 64-bit entry trampoline for Axiom-X x86_64 */
/* Built with GNU as (gas), not Rust inline asm, to ensure correct 32-bit codegen. */

.section .multiboot, "a"
.align 8

/* Multiboot2 Header */
mb2_start:
    .long 0xE85250D6              /* magic number (multiboot2) */
    .long 0                       /* architecture: 0 = i386 (protected mode entry) */
    .long mb2_hdr_end - mb2_start /* header length */
    .long 0x100000000 - (0xE85250D6 + 0 + (mb2_hdr_end - mb2_start)) /* checksum */

 /* Required Tags */

 /* Information request tag */
 .align 8
    .word 1, 0                      /* type = 1 (information request), flags = 0 */
    .long 24                        /* size = 24 bytes */
    .long 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 /* requested tags */

 /* Framebuffer tag */
 .align 8
    .word 5, 0                      /* type = 5 (framebuffer), flags = 0 */
    .long 20                        /* size = 20 bytes */
    .long 1024, 768, 32             /* preferred width, height, depth */
    .long 0, 0                      /* flags, reserved */

 /* End tag */
 .align 8
    .word 0, 0                      /* type = 0 (end), flags = 0 */
    .long 8                         /* size = 8 bytes */

mb2_hdr_end:

/* Multiboot1 Header (spec §2) */
.align 4
    .long 0x1BADB002               /* magic */
    .long 0x00000003               /* flags = page_align | memory_info */
    .long 0xE4524FFB               /* checksum */

/* Entry trampoline. The bootloader enters here in 32-bit protected */
/* mode with EAX = magic and EBX = mbi (physical address). */
.section .boot, "ax"
.code32
.global _start
_start:
    cli
    cld
    movl %eax, %ebp                /* stash magic (ebp survives switch) */

    /* PML4[0] -> PDPT_ID[0] -> PD_ID : identity map first 1 GiB */
    leal boot_pdpt, %eax
    orl $3, %eax
    movl %eax, boot_pml4
    leal boot_pd, %eax
    orl $3, %eax
    movl %eax, boot_pdpt

    /* PML4[256] -> PDPT_HH[0] -> PD_HH : VIRT_BASE mapping */
    leal boot_pdpt_hh, %eax
    orl $3, %eax
    movl %eax, boot_pml4 + 2048
    leal boot_pd_hh, %eax
    orl $3, %eax
    movl %eax, boot_pdpt_hh

    /* PD entry[i] = (i << 21) | PRESENT|WRITABLE|ACCESSED|DIRTY|HUGE (0xE3), i in 0..512 */
    leal boot_pd, %edi
    leal boot_pd_hh, %esi
    xorl %ecx, %ecx
1:
    movl %ecx, %eax
    shll $21, %eax
    orl $0xE3, %eax
    movl %eax, (%edi, %ecx, 8)    /* entries are 8 bytes; high dword stays 0 */
    movl %eax, (%esi, %ecx, 8)
    incl %ecx
    cmpl $512, %ecx
    jb 1b

    /* Install our GDT (null / 64-bit code @0x08 / data @0x10) */
    lgdt boot_gdt_desc

    /* PAE */
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    /* CR3 = &boot_pml4 */
    leal boot_pml4, %eax
    movl %eax, %cr3

    /* EFER.LME = 1 */
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr

    /* CR0.PG = 1 (PE already set by the bootloader) -> long mode */
    movl %cr0, %eax
    orl $0x80000003, %eax        /* PG | PE | MP (no ET) */
    movl %eax, %cr0

    /* Serialize after enabling paging - multiple mechanisms */
    lfence
    mfence
    jmp 1f
1:

    /* Debug: write 'Y' after enabling paging */
    movb $'Y', %al
    movw $0x3F8, %dx
    outb %al, %dx

    /* Far jump: CS = 0x08, EIP = trampoline64 (low, identity-mapped) */
    .byte 0xEA
    .long trampoline64
    .word 0x08

.code64
trampoline64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    movq %rbx, %rdi               /* mbi */
    movq %rbp, %rsi               /* magic */
    xorl %ebp, %ebp               /* clean frame pointer */
    leaq boot_stack_top(%rip), %rsp  /* trampoline stack */
    jmp *boot_entry_ptr(%rip)

/* ==================================================================== */
/* Boot-time data (still in .boot, low physical)                       */
/* ==================================================================== */
.align 16
boot_gdt:
    .quad 0                          /* null */
    .quad 0x00AF9A000000FFFF         /* 64-bit code, selector 0x08 */
    .quad 0x00CF92000000FFFF         /* data, selector 0x10 */
boot_gdt_end:
.align 8
boot_gdt_desc:
    .word boot_gdt_end - boot_gdt - 1
    .quad boot_gdt
.align 8
boot_entry_ptr:
    .quad kernel_rust_entry          /* higher-half absolute address */

/* ==================================================================== */
/* Bootstrap page tables + trampoline stack (low physical, zeroed by  */
/* the bootloader). Entries beyond those filled above must be zero.   */
/* ==================================================================== */
.section .boot_bss, "aw"
.align 4096
boot_pml4: .zero 4096
.align 4096
boot_pdpt: .zero 4096
.align 4096
boot_pd: .zero 4096
.align 4096
boot_pdpt_hh: .zero 4096
.align 4096
boot_pd_hh: .zero 4096
.align 16
boot_stack: .zero 262144              /* 256 KiB: debug builds put large structs on the stack */
boot_stack_top: