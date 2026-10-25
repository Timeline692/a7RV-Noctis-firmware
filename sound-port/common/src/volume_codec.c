/* Pure codec extracted from the MIT reference sidecar_baseline50.c contract. */
#include "volume_codec.h"
static void put(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static uint32_t get(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int valid(const sp_volume *v){return v && v->steps[0]>=1 && v->steps[0]<=10 && v->steps[1]>=1 && v->steps[1]<=10;}
void sp_volume_init(sp_volume *v){if(v){v->steps[0]=5;v->steps[1]=5;}}
int sp_volume_encode(const sp_volume *v,uint8_t output[SP_VOLUME_BYTES]){
    if(!valid(v)||!output)return SS_INVALID;
    /* Build locally so output may alias the input struct without corrupting it. */
    uint8_t b[SP_VOLUME_BYTES];put(b,0x4c4f5643);put(b+4,1);put(b+8,v->steps[0]);put(b+12,v->steps[1]);put(b+16,0);put(b+20,ss_crc32(b,20));
    for(unsigned i=0;i<SP_VOLUME_BYTES;i++)output[i]=b[i];return SS_OK;
}
int sp_volume_decode(sp_volume *v,const uint8_t *b,size_t n){
    if(!v||!b)return SS_INVALID;
    if(n!=SP_VOLUME_BYTES||get(b)!=0x4c4f5643||get(b+4)!=1||get(b+16)!=0||get(b+20)!=ss_crc32(b,20))return SS_CORRUPT;
    sp_volume next={{get(b+8),get(b+12)}};
    if(!valid(&next))return SS_CORRUPT;
    *v=next;return SS_OK;
}
int sp_volume_set(sp_volume *v,uint32_t slot,uint32_t step,sp_volume_commit_fn commit,void *context){
    if(!valid(v)||slot>=SS_SLOT_COUNT||step<1||step>10||!commit)return SS_INVALID;
    if(v->steps[slot]==step)return SS_OK;
    sp_volume next=*v;next.steps[slot]=step;uint8_t b[SP_VOLUME_BYTES];
    if(sp_volume_encode(&next,b)!=SS_OK)return SS_INVALID;
    if(commit(context,b,sizeof(b)))return SS_STORAGE;
    *v=next;return SS_OK;
}
