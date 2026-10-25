#include "rv_sound_native.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>

int main(void) {
    rv_ap_raw_policy raw = {1, 0, 0, 1, 0, 0, 3};
    ss_native native;
    uint32_t token = 0, expected = 0;
    rv_ap_event_stats stats;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK);
    assert(!native.silent && native.audio_signals && native.focus == SS_AFS);
    assert(native.shutter == SS_SHUTTER_ELECTRONIC);
    /* Interval source must override ordinary selected electronic. */
    raw.interval = 1;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK);
    assert(native.shutter == SS_SHUTTER_MECHANICAL);
    raw.interval_shutter = 1;
    raw.still_shutter = 2; /* irrelevant invalid ordinary model while interval ON */
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK);
    assert(native.shutter == SS_SHUTTER_ELECTRONIC);
    raw.silent = 0;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK && native.silent);
    raw.audio = 2;
    raw.focus = 1;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK);
    assert(native.audio_signals && native.focus == SS_AFA);
    raw.audio = 3; /* RV OFF: M4 raw3 was an admitting value. */
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK && !native.audio_signals);
    raw.audio = 1;
    raw.focus = 7; /* RV MF differs from reference raw6. */
    assert(rv_ap_normalize_policy(&raw, &native) == SS_OK);
    assert(!native.audio_signals && native.focus == SS_MF);
    raw.audio = 5;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_INVALID);
    assert(native.silent && native.shutter == SS_SHUTTER_MECHANICAL);
    raw.audio = 0;
    raw.interval = 0;
    assert(rv_ap_normalize_policy(&raw, &native) == SS_INVALID);
    assert(!rv_ap_event_pop(&token));
    for (uint32_t round = 0; round != 1000; ++round) {
        for (uint32_t i = 0; i != 40; ++i) rv_ap_exposure_observed();
        for (uint32_t i = 0; i != 32; ++i) {
            assert(rv_ap_event_pop(&token));
            assert(token == expected + i + 1);
        }
        expected += 40;
        assert(!rv_ap_event_pop(&token));
    }
    rv_ap_event_snapshot(&stats);
    assert(stats.observed == 40000 && stats.queued == 32000);
    assert(stats.dropped == 8000 && stats.pending == 0);
    assert(!rv_ap_event_pop(0));
    puts("RV policy and bounded occurrence queue: PASS");
    return 0;
}
