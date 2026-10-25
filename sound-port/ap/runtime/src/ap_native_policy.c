/* RV 4.00 policy uses one native model scope for a consistent snapshot. */
#include "ap_native_policy.h"
#include "rv_sound_native.h"
extern __attribute__((visibility("hidden"))) uint32_t csnd_native_silent_get(void);
static int pending_override(int status,ss_native *out) {
    if(status==SS_OK && csnd_ap_mechanical_pending())out->shutter=SS_SHUTTER_MECHANICAL;
    return status;
}
int csnd_ap_normalize_native(const csnd_native_inputs *in,ss_native *out) {
    rv_ap_raw_policy raw={0};
    if(!out)return SS_INVALID;
    *out=(ss_native){1,0,SS_SHUTTER_MECHANICAL,SS_MF};
    /* The ordinary still model is established. The getter below selects the
       interval model when interval shooting is active. */
    if(!in || in->shutter_parameter!=0x60a)return SS_INVALID;
    raw.silent=in->silent_raw;raw.audio=in->audio_raw;
    raw.focus=in->focus_raw;raw.still_shutter=in->shutter_raw;
    return pending_override(rv_ap_normalize_policy(&raw,out),out);
}
int csnd_ap_read_native(uint32_t parameter,uint32_t known,uint32_t effective,ss_native *out) {
    uintptr_t slide=(uintptr_t)&csnd_native_silent_get-RV_AP_SILENT_GET;
    (void)parameter;(void)known;(void)effective;
    if(!out)return SS_INVALID;
    return pending_override(rv_ap_read_policy(slide,out),out);
}
