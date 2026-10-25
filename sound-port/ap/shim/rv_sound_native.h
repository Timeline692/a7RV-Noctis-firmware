#ifndef RV_SOUND_NATIVE_H
#define RV_SOUND_NATIVE_H
#include <stddef.h>
#include <stdint.h>
#include "sound_core.h"

/* ELF-relative RV 4.00 appFw.so addresses. base is the loaded image slide. */
#define RV_AP_SCOPE_CTOR 0x02e7d208u
#define RV_AP_SCOPE_DTOR 0x02e7cee4u
#define RV_AP_SILENT_GET 0x01c3413cu
#define RV_AP_AUDIO_GET 0x01c0dcbcu
#define RV_AP_FOCUS_GET 0x01c23624u
#define RV_AP_STILL_SHUTTER_GET 0x01bfadc0u
#define RV_AP_INTERVAL_GET 0x01c34eccu
#define RV_AP_INTERVAL_SHUTTER_GET 0x01c34b4cu
#define RV_AP_AUDIO_VOLUME_GET 0x01c0da8cu
#define RV_AP_START329 0x0350360cu
#define RV_AP_EXPOSURE_SITE 0x03556198u
#define RV_AP_EXPOSURE_RESUME 0x0355619cu

typedef struct {
    uint32_t silent, audio, focus, still_shutter;
    uint32_t interval, interval_shutter, volume;
} rv_ap_raw_policy;

/* Worker context only. The original model read scope surrounds all fields. */
int rv_ap_native_snapshot(uintptr_t base, rv_ap_raw_policy *out);
int rv_ap_normalize_policy(const rv_ap_raw_policy *raw, ss_native *out);
int rv_ap_read_policy(uintptr_t base, ss_native *out);

/* Uses the native wrapper and its owned-copy asynchronous queue.
 * Returns SS_OK for native submission return, not playback completion.
 * kind must be the actual registered descriptor kind, never its table index. */
int rv_ap_start_async(uintptr_t base, uint32_t registered_kind);

/* SPSC: sole producer is native receive thread at RV_AP_EXPOSURE_SITE;
 * sole consumer is the sound worker. No packet or native callback is owned.
 * Every native accepted notification creates a local occurrence token.
 * CP retransmissions are not deduplicated using an unverified wire layout. */
#define RV_AP_EVENT_CAPACITY 32u
void rv_ap_exposure_observed(void);
int rv_ap_event_pop(uint32_t *occurrence);
typedef struct { uint32_t observed, queued, dropped, pending; } rv_ap_event_stats;
void rv_ap_event_snapshot(rv_ap_event_stats *out);

/* Entry replaces only mov x0,#1 at site; linker must define the direct
 * branch target rv_ap_exposure_resume at RV_AP_EXPOSURE_RESUME + image slide.
 * All GPRs and NZCV are preserved before the replaced instruction is replayed.
 * Helper objects must retain -mgeneral-regs-only and -mno-outline-atomics. */
void rv_ap_exposure_entry(void);
#endif
