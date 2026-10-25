/* Standalone inspection ELF. Final injector places these sections itself. */
ENTRY(rv_ap_exposure_entry)
rv_ap_exposure_resume = 0x0355619c;
SECTIONS {
  . = 0x09100000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss (NOLOAD) : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.comment*) *(.eh_frame*) *(.note*) }
}
