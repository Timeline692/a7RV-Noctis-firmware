#ifndef RV_SCHEDULER_H
#define RV_SCHEDULER_H
#include <stddef.h>
#include <stdint.h>
#define RV_SEQUENCE_MANAGER_GET 0x031a9d04u
#define RV_SEQUENCE_REGISTER 0x0326d098u
#define RV_SEQUENCE_POST_SITE 0x03255fa0u
#define RV_SEQUENCE_POST_RESUME 0x03255fa4u
#define RV_MEDIA_BYTES 0x150u
void *rv_ap_manager_get(uintptr_t image_slide);
void rv_ap_register(uintptr_t image_slide, void *manager, void *job,
                    uint32_t index, uint32_t request_flag, uint32_t dependency_flag);
/* Called on GUI/worker contexts, not from the raw exposure hook. Model scope
 * protects the complete copied two-card object; no borrowed model pointer. */
int csnd_rv_media_copy(uint8_t output[RV_MEDIA_BYTES]);
/* Branch target at post-execute site. The runtime supplies the real
 * csnd_maintenance_after_execute(manager,job); final linker supplies resume. */
void rv_ap_postexecute_entry(void);
#endif
