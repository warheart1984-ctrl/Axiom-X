/* kernel.ld — Axiom-X x86_64 higher-half linker script
 *
 * The image has two physical regions:
 *
 *   1. A low trampoline (.multiboot + .boot + .boot_bss) linked at 1 MiB
 *      (VMA == LMA). The bootloader jumps to `_start` here in 32-bit
 *      protected mode; the trampoline builds identity + higher-half page
 *      tables, switches to long mode, and jumps to the higher-half kernel.
 *
 *   2. The kernel itself (.text/.rodata/.data/.bss) linked at
 *      `VIRT_BASE + phys` (VMA). AT() keeps the load address (LMA) at the
 *      physical offset right after the trampoline, so the ELF stays small
 *      and every higher-half section satisfies VMA == VIRT_BASE + LMA,
 *      which is exactly the relation `init_early_page_tables` assumes for
 *      its 1 GiB identity + `VIRT_PHYS_OFFSET` higher-half mapping.
 *
 * Both the multiboot1 and multiboot2 headers live in `.multiboot`, the
 * first section in the file, keeping each within its spec limit
 * (first 8192 / 32768 bytes of the image).
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Physical load address (where GRUB/QEMU loads the kernel) */
PHYS_LOAD = 0x100000;

/* Higher-half virtual base (must match VIRT_PHYS_OFFSET in axiom-x-boot) */
VIRT_BASE = 0xFFFF800000000000;

SECTIONS
{
    /* ----------------------------------------------------------------
     * Low physical trampoline (VMA == LMA == PHYS_LOAD)
     * ---------------------------------------------------------------- */
    . = PHYS_LOAD;

    .multiboot ALIGN(8) :
    {
        KEEP(*(.multiboot))
    }

    /* 32-bit entry stub, bootstrap GDT, higher-half entry pointer. */
    .boot ALIGN(16) :
    {
        *(.boot .boot.*)
    }

    /* Bootstrap page tables + trampoline stack (zeroed by the loader). */
    .boot_bss ALIGN(4096) :
    {
        *(.boot_bss .boot_bss.*)
    }

    /* ----------------------------------------------------------------
     * Higher-half kernel. Move the location counter to VIRT_BASE and pin
     * each section's load address back to its physical offset.
     * ---------------------------------------------------------------- */
    . = ALIGN(4096);
    . += VIRT_BASE;

    .text ALIGN(4096) : AT(ADDR(.text) - VIRT_BASE)
    {
        *(.text .text.*)
        *(.ltext .ltext.*)
        *(.gnu.linkonce.t.*)
    }

    .rodata ALIGN(4096) : AT(ADDR(.rodata) - VIRT_BASE)
    {
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
        *(.gnu.linkonce.r.*)
    }

    .data ALIGN(4096) : AT(ADDR(.data) - VIRT_BASE)
    {
        *(.data .data.*)
        *(.ldata .ldata.*)
        *(.gnu.linkonce.d.*)
    }

    /* Orphan sections: without explicit placement lld puts .got / .data.rel.ro
     * far outside the 2 GiB reach of R_X86_64_GOTPCREL relocations. */
    .got ALIGN(4096) : AT(ADDR(.got) - VIRT_BASE)
    {
        *(.got .got.*)
    }

    .got.plt ALIGN(4096) : AT(ADDR(.got.plt) - VIRT_BASE)
    {
        *(.got.plt .got.plt.*)
    }

    .data.rel.ro ALIGN(4096) : AT(ADDR(.data.rel.ro) - VIRT_BASE)
    {
        *(.data.rel.ro .data.rel.ro.*)
    }

    .bss ALIGN(4096) : AT(ADDR(.bss) - VIRT_BASE)
    {
        *(.bss .bss.*)
        *(.lbss .lbss.*)
        *(COMMON)
        *(.gnu.linkonce.b.*)
    }

    kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}

PROVIDE(__kernel_phys_start = ADDR(.multiboot));
PROVIDE(__kernel_virt_start = ADDR(.text));
PROVIDE(__kernel_virt_end = kernel_end);
