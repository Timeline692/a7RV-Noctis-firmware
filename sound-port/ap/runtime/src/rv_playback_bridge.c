#include <stdint.h>
#include "rv_sound_native.h"
extern __attribute__((visibility("hidden"))) uint32_t csnd_native_silent_get(void);
extern int rv_playback_startup(uintptr_t);
extern void csnd_event_config_changed(void);
void csnd_sound_startup(void){
    uintptr_t slide=(uintptr_t)&csnd_native_silent_get-RV_AP_SILENT_GET;
    (void)rv_playback_startup(slide);
}
void csnd_sound_config_changed(void){csnd_event_config_changed();}
