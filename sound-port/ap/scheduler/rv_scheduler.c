#include "rv_scheduler.h"
typedef void *(*manager_get_fn)(void);
typedef void (*register_fn)(void *, void *, uint32_t, uint32_t, uint32_t);
extern void csnd_rv_model_scope_enter(void *);
extern void csnd_rv_model_scope_leave(void *);
extern const volatile uint8_t *csnd_rv_media_leaf(void);

void *rv_ap_manager_get(uintptr_t image_slide) {
    return ((manager_get_fn)(image_slide + RV_SEQUENCE_MANAGER_GET))();
}

void rv_ap_register(uintptr_t image_slide, void *manager, void *job,
                    uint32_t index, uint32_t request_flag, uint32_t dependency_flag) {
    ((register_fn)(image_slide + RV_SEQUENCE_REGISTER))(
        manager, job, index, request_flag, dependency_flag);
}

int csnd_rv_media_copy(uint8_t output[RV_MEDIA_BYTES]) {
    uint64_t guard = 0;
    const volatile uint8_t *source;
    if (!output) return 1;
    csnd_rv_model_scope_enter(&guard);
    source = csnd_rv_media_leaf();
    for (size_t i = 0; i < RV_MEDIA_BYTES; ++i) output[i] = source[i];
    csnd_rv_model_scope_leave(&guard);
    return 0;
}
