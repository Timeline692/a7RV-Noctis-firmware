#ifndef RV_CONFIRM_UI_H
#define RV_CONFIRM_UI_H
#include <stdint.h>
#define RV_CONFIRM_LAYOUT_WORDS (0x240u/4u)
extern const uint32_t rv_confirm_layouts[2][3][RV_CONFIRM_LAYOUT_WORDS];
/* 0 native;1 electronic import;2 focus import;3 default focus restore. */
uint32_t csnd_controller_confirmation_variant(uint32_t layer,uint32_t scene);
const void *rv_confirm_select_layout(const void *native,uint32_t layer,uint32_t scene,uint32_t orientation);
void rv_ui_confirm_entry(void);
#endif
