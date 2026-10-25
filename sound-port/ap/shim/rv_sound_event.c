#include "rv_sound_native.h"

typedef struct {
    uint32_t head, tail, observed, dropped;
    uint32_t occurrence[RV_AP_EVENT_CAPACITY];
} event_queue;
static event_queue events;

/* No allocation, model lock, native calls, borrowed packet, or retry loop. */
__attribute__((visibility("hidden"), noinline))
void rv_ap_exposure_observed(void) {
    uint32_t head = __atomic_load_n(&events.head, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&events.tail, __ATOMIC_ACQUIRE);
    uint32_t occurrence = __atomic_load_n(&events.observed, __ATOMIC_RELAXED) + 1u;
    __atomic_store_n(&events.observed, occurrence, __ATOMIC_RELAXED);
    if (head - tail >= RV_AP_EVENT_CAPACITY) {
        uint32_t dropped = __atomic_load_n(&events.dropped, __ATOMIC_RELAXED);
        __atomic_store_n(&events.dropped, dropped + 1u, __ATOMIC_RELAXED);
        return;
    }
    events.occurrence[head & (RV_AP_EVENT_CAPACITY - 1u)] = occurrence;
    __atomic_store_n(&events.head, head + 1u, __ATOMIC_RELEASE);
}

int rv_ap_event_pop(uint32_t *occurrence) {
    uint32_t tail, head;
    if (!occurrence) return 0;
    tail = __atomic_load_n(&events.tail, __ATOMIC_RELAXED);
    head = __atomic_load_n(&events.head, __ATOMIC_ACQUIRE);
    if (tail == head) return 0;
    *occurrence = events.occurrence[tail & (RV_AP_EVENT_CAPACITY - 1u)];
    __atomic_store_n(&events.tail, tail + 1u, __ATOMIC_RELEASE);
    return 1;
}

void rv_ap_event_snapshot(rv_ap_event_stats *out) {
    uint32_t head, tail;
    if (!out) return;
    tail = __atomic_load_n(&events.tail, __ATOMIC_ACQUIRE);
    head = __atomic_load_n(&events.head, __ATOMIC_ACQUIRE);
    out->observed = __atomic_load_n(&events.observed, __ATOMIC_RELAXED);
    out->dropped = __atomic_load_n(&events.dropped, __ATOMIC_RELAXED);
    out->queued = head;
    out->pending = head - tail;
}
