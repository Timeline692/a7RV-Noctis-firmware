#include "rv_cp_abi.h"
#include "cp_owner.h"
extern void rv_cp_dmm_dispatch_original(uint32_t,uint8_t*,uint32_t);
extern uint32_t csnd_bind_diag_reply(const uint32_t*,uint32_t*);
static uint32_t r16(const uint8_t*p){return p[0]|(uint32_t)p[1]<<8;}
static uint32_t r32(const uint8_t*p){return r16(p)|(r16(p+2)<<16);}
/* RV BDB982 boundary has native source/raw/length in r0/r1/r2.
 * Request COPY can be 40+n bytes. Its reply remains in that native allocation;
 * AP must require this exact allocation length and validate the first40 bytes.
 * Do not reuse the M4 assumption that every COPY ACK allocation is40 bytes. */
void rv_cp_dmm_dispatch(uint32_t source,uint8_t*raw,uint32_t bytes){
 if(!rv_cp_runtime_ready()||!raw||bytes<40||bytes>1000||
    r16(raw)!=0x7e||r32(raw+12)!=0x4e535343u){
  rv_cp_dmm_dispatch_original(source,raw,bytes);return;
 }
 uint32_t request[10],reply[10];
 for(uint32_t i=0;i<40;i++)((uint8_t*)request)[i]=raw[i];
 csnd_cp_receive_capture(source,raw,bytes);
 csnd_bind_diag_reply(request,reply);
 for(uint32_t i=0;i<40;i++)raw[i]=((const uint8_t*)reply)[i];
 for(uint32_t i=40;i<bytes;i++)raw[i]=0;
}
