/* LINKED ANALYSIS CANDIDATE, NOT A DEPLOYMENT APPROVAL.
 * Addresses derive from the RV native module header and page mappings.
 * A candidate image needs a loader/header/file-length integration review. */
ENTRY(rv_cp_cold_zero_hook)
SECTIONS {
 .rv_veneer 0xBEF220 : { KEEP(*(.rv_veneer)) }
 .text 0x1A3A000 : { *(.text*) *(.rodata*) }
 .data 0x1A39450 : { *(.data*) }
 .bss 0x1A39450 (NOLOAD) : { __rv_cp_bss_start = .; *(.bss*) *(COMMON) __rv_cp_bss_end = .; }
 ASSERT(SIZEOF(.data) == 0, "New initialized RW data needs an explicit loading contract")
 ASSERT(SIZEOF(.rv_veneer) <= 0x100, "Veneers exceed proven native text-page padding")
 ASSERT(SIZEOF(.text) <= 0x2000, "CP port exceeds two candidate RX pages")
 ASSERT(__rv_cp_bss_end <= 0x1A3A000, "CP private RW collides with RX page")
 /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.attributes*) }
}
