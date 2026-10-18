/* Axiom-X user program layout.
 *
 * Linked at the start of the per-process user slot (PML4 index 1). Each
 * output section gets its own page-aligned PT_LOAD with explicit W^X
 * permissions, which the kernel's ELF loader maps as given:
 *   text   R-X   rodata R--   data/bss RW-
 * The loader rejects segments outside the user image window, segments that
 * are both writable and executable, and unaligned segments.
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R + X */
    rodata PT_LOAD FLAGS(4);   /* R     */
    data   PT_LOAD FLAGS(6);   /* R + W */
}

SECTIONS
{
    . = 0x8000000000;

    /* code-model=large (from .cargo/config.toml) emits .ltext/.lrodata/
       .ldata/.lbss: name them explicitly, or the linker places them as
       orphans after .rodata, putting code and writable data in the R-- segment. */
    .text ALIGN(4096) : { *(.text._start) *(.text .text.*) *(.ltext .ltext.*) } :text
    .rodata ALIGN(4096) : { *(.rodata .rodata.*) *(.lrodata .lrodata.*) } :rodata
    .data ALIGN(4096) : { *(.data .data.*) *(.ldata .ldata.*) *(.got .got.*) } :data
    .bss : { *(.bss .bss.*) *(.lbss .lbss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
