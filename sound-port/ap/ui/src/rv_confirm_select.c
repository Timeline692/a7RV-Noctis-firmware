#include "rv_confirm_ui.h"
extern const uint32_t csnd_native_confirm_layout_orientation0[];
extern const uint32_t csnd_native_confirm_layout_orientation_other[];
const void *rv_confirm_select_layout(const void *native,uint32_t layer,uint32_t scene,uint32_t orientation){
 uint32_t index=orientation?1u:0u,variant;
 const void *expected=orientation?(const void *)csnd_native_confirm_layout_orientation_other:
                                    (const void *)csnd_native_confirm_layout_orientation0;
 if(native!=expected || layer>=6 || scene!=0x174)return native;
 variant=csnd_controller_confirmation_variant(layer,scene);
 if(!variant || variant>3)return native;
 return rv_confirm_layouts[index][variant-1];
}
