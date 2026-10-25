#include <assert.h>
#include "rv_sound_path_policy.h"
int main(void){
 /* Native AP328 states: Silent ON4, Silent OFF/Audio OFF5, signals ON7. */
 assert(!rv_sound_path_mask_allowed(17,4)&&!rv_sound_path_mask_allowed(4,4));
 assert(rv_sound_path_mask_allowed(17,5)&&!rv_sound_path_mask_allowed(4,5));
 assert(rv_sound_path_mask_allowed(17,7)&&rv_sound_path_mask_allowed(4,7));
 /* APP-only is sufficient: unrelated PIN/CLIP state is never a prerequisite. */
 assert(rv_sound_path_mask_allowed(17,1)&&rv_sound_path_mask_allowed(17,3));
 assert(!rv_sound_path_mask_allowed(17,6)&&!rv_sound_path_mask_allowed(4,2));
 for(uint32_t mask=0;mask<8;mask++)assert(!rv_sound_path_mask_allowed(16,mask));
 return 0;
}
