#include "rv_cp_abi.h"
#include "cp_owner.h"
/* Default offline builds keep admission0. The explicit experimental profile
 * accepts reference format0 compatibility inference; hardware is NOT_TESTED. */
#ifndef RV_CP_REFERENCE_CODEC_EXPERIMENTAL
#define RV_CP_REFERENCE_CODEC_EXPERIMENTAL 0
#endif
#if RV_CP_REFERENCE_CODEC_EXPERIMENTAL
const char rv_cp_build_profile[]="reference-codec-experimental";
const char rv_cp_codec_admission[]="REFERENCE_FORMAT0_COMPATIBILITY_INFERENCE;HARDWARE_NOT_TESTED";
#else
const char rv_cp_build_profile[]="offline";
const char rv_cp_codec_admission[]="DISABLED;HARDWARE_NOT_TESTED";
#endif
const volatile struct rv_cp_binding rv_cp_abi={
#if RV_CP_REFERENCE_CODEC_EXPERIMENTAL
 .proof_flags=RV_PROOF_QUIESCENCE|RV_ALLOW_REFERENCE_CODEC|RV_PROOF_MEMORY|
              RV_PROOF_BOOT_ZERO|RV_PROOF_TRANSPORT|RV_PROOF_HOOKS,
 .lookup_excluded_caller=0x652fcf,
#else
 .proof_flags=0,.lookup_excluded_caller=0x652fcf,
#endif
 /* Native caches: PIN pre-request@10a6740 and current request@10a66e0.
  * Both are byte0 validity/operation tags of copied32-byte requests.
  * PIN mode@198ad8a is stored alongside the pre-request, passed to Start,
  * then cleared; the reference busy mask conservatively tests this mode.
  * Native and official M4 stock producer/consumer pairs are recorded in
  * analysis/sound-port-cp-busy.json. */
 .busy_address={0x111782c,0x1117830,0x1117860,0x1117878,
                0x10a6740,0x198ad8a,0x16a5ab0,0x16a5ac8,0x10a66e0,0x16a5b2c,0x16a5acc},
 .busy_width={4,4,4,4,1,1,4,4,1,1,1}
};
static volatile uint32_t initialized,diagnostic_sequence;
extern unsigned char __rv_cp_bss_start[],__rv_cp_bss_end[];
/* The loader must call this once on a cold boot before installing any hook.
 * A verified zero-range/entry hook is still a deployment requirement. */
void rv_cp_module_cold_init(void){
 for(unsigned char*p=__rv_cp_bss_start;p<__rv_cp_bss_end;p++)*p=0;
 __atomic_store_n(&initialized,1,__ATOMIC_RELEASE);
}
int rv_cp_runtime_ready(void){
 return rv_cp_abi.proof_flags==RV_ADMISSION_REQUIRED&&
  __atomic_load_n(&initialized,__ATOMIC_ACQUIRE)==1;
}
uint32_t rv_cp_busy_mask(void){
 if(!rv_cp_runtime_ready())return 0x80000000u;
 uint32_t m=0,state=*(volatile uint32_t*)0x16a5ab0,
  active=*(volatile uint32_t*)0x16a5ac8;
 __atomic_thread_fence(__ATOMIC_SEQ_CST);
 for(uint32_t i=0;i<11;i++){
  uint32_t a=rv_cp_abi.busy_address[i],n=rv_cp_abi.busy_width[i];
  if(!a||(n!=1&&n!=4)){m|=0x80000000u;continue;}
  uint32_t v=n==1?*(volatile uint8_t*)a:*(volatile uint32_t*)a;
  if(v)m|=1u<<i;
 }
 __atomic_thread_fence(__ATOMIC_SEQ_CST);
 if(state!=*(volatile uint32_t*)0x16a5ab0||active!=*(volatile uint32_t*)0x16a5ac8)m|=0x80000000u;
 return m;
}
uint32_t rv_cp_native_extent(const void*q,void*r,void*extent){
 /* Thumb target comes from RV DMM dispatch table E6B9BC[2A]. */
 return ((uint32_t(*)(const void*,void*,void*))0xbdb2f1)(q,r,extent);
}
void csnd_cp_clean_buffer(void*p,uint32_t n){
 /* A32 wrapper: ptr/bytes -> cache object -> clean-MVA plus L2/DSB. */
 ((void(*)(void*,uint32_t))0x5e8c18)(p,n);
}
uint32_t rv_cp_exists_address(uint32_t reg,uint32_t kind){
 return csnd_cp_exists_original((void*)reg,kind);
}
uint32_t rv_cp_tick_raw(void){
 /* A local monotonic diagnostic sequence; not an RV clock measurement. */
 return __atomic_add_fetch(&diagnostic_sequence,1,__ATOMIC_RELAXED);
}
int rv_cp_stop_lookup_allowed(uint32_t c,uint32_t retiring){
 if(c==0x655177||c==0x6557ff||c==0x656319)return 1;
 return retiring&&(c==0x19875b||c==0x198775);
}
