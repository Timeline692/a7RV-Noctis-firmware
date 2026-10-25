/* Deployment script. The build driver must supply verified addresses and proof.
 * No default camera address or presumed code cave is provided. */
ENTRY(rv_cp_module_cold_init)
RV_CODE_ORIGIN = DEFINED(RV_CODE_ORIGIN) ? RV_CODE_ORIGIN : 0;
RV_RW_ORIGIN = DEFINED(RV_RW_ORIGIN) ? RV_RW_ORIGIN : 0;
RV_PLACEMENT_PROVED = DEFINED(RV_PLACEMENT_PROVED) ? RV_PLACEMENT_PROVED : 0;
ASSERT(RV_PLACEMENT_PROVED == 1, "RV CP RX/RW placement and cold-init binding are not proved")
ASSERT(RV_CODE_ORIGIN != 0 && RV_RW_ORIGIN != 0, "No camera VA may be guessed")
SECTIONS {
 .text RV_CODE_ORIGIN : { *(.text*) *(.rodata*) }
 .data RV_RW_ORIGIN : { *(.data*) }
 .bss (NOLOAD) : { __rv_cp_bss_start = .; *(.bss*) *(COMMON) __rv_cp_bss_end = .; }
 /DISCARD/ : { *(.comment*) *(.ARM.exidx*) *(.ARM.attributes*) }
}
