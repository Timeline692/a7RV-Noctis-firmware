#ifndef RV_PLAYBACK_NATIVE_H
#define RV_PLAYBACK_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#include "ap_runtime.h"
#include "rv_sound_native.h"
extern void *csnd_malloc(size_t);
extern void csnd_free(void*);
uint32_t csnd_stop_pending(uint64_t image_slide);
int csnd_stop_async_request(uint64_t image_slide,uint32_t actual_kind);
/* Called once by the startup/maintenance bridge after private BSS is zero.
 * It creates one dedicated native OSAL thread. PCM, RPC and conversion never
 * run in the native exposure receive callback or a camera control queue. */
int rv_playback_startup(uintptr_t image_slide);
uint32_t csnd_sysnd_async_once(uint32_t actual_kind);
uintptr_t rv_playback_image_slide(void);
#endif
