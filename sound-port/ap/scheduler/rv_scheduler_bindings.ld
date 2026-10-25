/* Native RV 4.00 entry points; include into the final appFw extension script.
 * PC-relative calls remain correct under the original appFw image slide. */
PROVIDE(csnd_native_manager_get = 0x031a9d04);
PROVIDE(csnd_native_register = 0x0326d098);
PROVIDE(csnd_native_base_construct = 0x030c01dc);
PROVIDE(csnd_native_base_destroy = 0x030bed38);
PROVIDE(csnd_native_sized_delete = 0x016db160);
PROVIDE(csnd_native_sequence_rtti = 0x058f6cc0);
PROVIDE(csnd_native_empty_cancel = 0x030bea30);
PROVIDE(csnd_native_empty_finish = 0x030bea34);
PROVIDE(csnd_rv_model_scope_enter = 0x02e7d208);
PROVIDE(csnd_rv_model_scope_leave = 0x02e7cee4);
PROVIDE(csnd_rv_media_leaf = 0x028a3b60);
PROVIDE(csnd_find_first = 0x036911c8);
PROVIDE(csnd_find_next = 0x036911f8);
PROVIDE(csnd_fsys_open = 0x03691104);
PROVIDE(csnd_fsys_read = 0x03691138);
PROVIDE(csnd_fsys_close = 0x03691124);
PROVIDE(csnd_native_dlsym = 0x016dac90);
PROVIDE(rv_ap_postexecute_resume = 0x03255fa4);
