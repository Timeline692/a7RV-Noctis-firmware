#ifndef RV_CP_ABI_H
#define RV_CP_ABI_H
#include <stdint.h>
struct sound_owner;
extern struct sound_owner csnd_cp_owner;
enum { RV_PROOF_QUIESCENCE=1, RV_PROOF_CODEC=2, RV_PROOF_MEMORY=4,
 RV_PROOF_BOOT_ZERO=8, RV_PROOF_TRANSPORT=16, RV_PROOF_HOOKS=32,
 RV_PROOFS_REQUIRED=63 };
/* Legacy field/bit names are retained for the private ABI. In the explicit
 * experimental profile codec flag0x02 admits an inference, not a device test. */
enum { RV_ALLOW_REFERENCE_CODEC=RV_PROOF_CODEC, RV_ADMISSION_REQUIRED=RV_PROOFS_REQUIRED };
struct rv_cp_binding {
 uint32_t proof_flags,lookup_excluded_caller; /* proof_flags is an admission mask */
 uint32_t busy_address[11];
 uint8_t busy_width[11];
};
extern const volatile struct rv_cp_binding rv_cp_abi;
int rv_cp_runtime_ready(void);
uint32_t rv_cp_busy_mask(void);
uint32_t rv_cp_native_extent(const void*,void*,void*);
uint32_t rv_cp_exists_address(uint32_t,uint32_t);
uint32_t rv_cp_tick_raw(void);
int rv_cp_stop_lookup_allowed(uint32_t,uint32_t);
void rv_cp_module_cold_init(void);
void rv_cp_dmm_dispatch(uint32_t,uint8_t*,uint32_t);
uint32_t csnd_cp_exists_original(void*,uint32_t);
#endif
