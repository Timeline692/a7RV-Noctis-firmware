#ifndef RV_SOUND_PATH_POLICY_H
#define RV_SOUND_PATH_POLICY_H
#include <stdint.h>
/* RV native validators: bit0 APP, bit1 PIN, bit2 CLIP. Silent ON clears APP
 * and PIN. A private APP shutter sound is independent of the PIN switch. */
static inline int rv_sound_path_mask_allowed(uint32_t kind,uint32_t mask){
 uint32_t required=kind==17?1u:kind==4?3u:0u;
 return required && (mask&required)==required;
}
#endif
