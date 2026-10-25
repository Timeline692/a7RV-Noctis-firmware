#ifndef SOUND_PORT_VOLUME_CODEC_H
#define SOUND_PORT_VOLUME_CODEC_H
#include "sound_core.h"
enum { SP_VOLUME_BYTES=24, SP_VOLUME_DEFAULT=5 };
typedef struct { uint32_t steps[SS_SLOT_COUNT]; } sp_volume;
typedef int (*sp_volume_commit_fn)(void *,const uint8_t *,size_t);
void sp_volume_init(sp_volume *);
int sp_volume_encode(const sp_volume *,uint8_t output[SP_VOLUME_BYTES]);
int sp_volume_decode(sp_volume *,const uint8_t *,size_t);
/* Persist the exact CVOL bytes before publishing a RAM change. No IO here. */
int sp_volume_set(sp_volume *,uint32_t slot,uint32_t step,sp_volume_commit_fn,void *);
#endif
