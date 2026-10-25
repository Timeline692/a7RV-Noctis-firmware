#include "rv_playback_native.h"
/* This call is guarded again by the resource manager's generation/policy
 * ticket immediately before submission. Native AP329 copies its request. */
uint32_t csnd_sysnd_async_once(uint32_t actual_kind){
 int s=rv_ap_start_async(rv_playback_image_slide(),actual_kind);
 return s==SS_OK?1u:(uint32_t)(-s);
}
