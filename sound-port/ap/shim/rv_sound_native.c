#include "rv_sound_native.h"

typedef void (*scope_fn)(void *);
typedef const volatile uint32_t *(*leaf_fn)(void);
typedef void (*start_fn)(const uint32_t *, uint32_t *);

/* Leaves are bound by the original typed sequence constructors 318ba10,
 * 3192b90 and 3188e58, independently of M4 numeric property assumptions. */
static uint32_t read_leaf(uintptr_t base, uintptr_t address) {
    return *((leaf_fn)(base + address))();
}

int rv_ap_native_snapshot(uintptr_t base, rv_ap_raw_policy *out) {
    uint64_t guard = 0;
    rv_ap_raw_policy value;
    if (!out) return SS_INVALID;
    ((scope_fn)(base + RV_AP_SCOPE_CTOR))(&guard);
    value.silent = read_leaf(base, 0x028aced0u);
    value.audio = read_leaf(base, 0x028b1d8cu);
    value.focus = read_leaf(base, 0x028ae5c8u);
    value.still_shutter = read_leaf(base, 0x028acfc0u);
    value.interval = read_leaf(base, 0x028acca0u);
    value.interval_shutter = read_leaf(base, 0x028acd18u);
    value.volume = read_leaf(base, 0x028b1ddcu);
    ((scope_fn)(base + RV_AP_SCOPE_DTOR))(&guard);
    *out = value;
    return SS_OK;
}

int rv_ap_normalize_policy(const rv_ap_raw_policy *raw, ss_native *out) {
    uint32_t selected;
    if (!out) return SS_INVALID;
    *out = (ss_native){1, 0, SS_SHUTTER_MECHANICAL, SS_MF};
    if (!raw || raw->silent > 1 || raw->audio > 3 || raw->interval > 1)
        return SS_INVALID;
    /* Exact selection in native typed converter 35522e0. AUTO/60b is not
     * part of this product's verified normal shutter setter. */
    selected = raw->interval ? raw->interval_shutter : raw->still_shutter;
    if (selected > 1) return SS_INVALID;
    out->silent = raw->silent == 0;
    out->audio_signals = raw->audio == 0 || raw->audio == 2;
    out->shutter = selected ? SS_SHUTTER_ELECTRONIC : SS_SHUTTER_MECHANICAL;
    /* Only AFS/AFA can admit custom focus. All other RV focus values are
     * intentionally represented as a non-admitting mode. */
    out->focus = raw->focus == 0 ? SS_AFS : raw->focus == 1 ? SS_AFA : SS_MF;
    return SS_OK;
}

int rv_ap_read_policy(uintptr_t base, ss_native *out) {
    rv_ap_raw_policy raw;
    int status;
    if (!out) return SS_INVALID;
    status = rv_ap_native_snapshot(base, &raw);
    if (status != SS_OK) return status;
    return rv_ap_normalize_policy(&raw, out);
}

int rv_ap_start_async(uintptr_t base, uint32_t registered_kind) {
    uint32_t input[3] = {registered_kind, 0, 0};
    uint32_t result = UINT32_MAX;
    if (!registered_kind || registered_kind > 255u) return SS_INVALID;
    ((start_fn)(base + RV_AP_START329))(input, &result);
    return result == 0 ? SS_OK : SS_INCOMPATIBLE;
}
