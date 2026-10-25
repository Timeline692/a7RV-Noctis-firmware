#include <assert.h>
#include "rv_confirm_ui.h"
const uint32_t csnd_native_confirm_layout_orientation0[]={1};
const uint32_t csnd_native_confirm_layout_orientation_other[]={2};
static uint32_t variant;
uint32_t csnd_controller_confirmation_variant(uint32_t layer,uint32_t scene){assert(layer<6&&scene==0x174);return variant;}
int main(void){
 const void *native[2]={csnd_native_confirm_layout_orientation0,csnd_native_confirm_layout_orientation_other};
 for(uint32_t orientation=0;orientation<2;orientation++) {
  variant=0;assert(rv_confirm_select_layout(native[orientation],2,0x174,orientation)==native[orientation]);
  for(variant=1;variant<=3;variant++) {
   const uint32_t *layout=rv_confirm_select_layout(native[orientation],2,0x174,orientation);
   assert(layout==rv_confirm_layouts[orientation][variant-1]);assert(layout[0x6c/4]==0x200ab60+variant);
   assert(layout[0x68/4]==2&&layout[0x1a4/4]==0x200a00c&&layout[0x1d4/4]==0x200a713);
  }
  variant=1;
  assert(rv_confirm_select_layout(native[orientation],6,0x174,orientation)==native[orientation]);
  assert(rv_confirm_select_layout(native[orientation],2,0x16b,orientation)==native[orientation]);
  assert(rv_confirm_select_layout(native[orientation],2,0x174,!orientation)==native[orientation]);
 }
 return 0;
}
