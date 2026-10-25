/* The reference implementation remains verbatim, including its F0 entry
 * points. Sharing this translation unit reuses its exact FIR and gain math. */
#define memset sp_reference_memset
#define memcmp sp_reference_memcmp
#include "reference_convert.c"
#undef memset
#undef memcmp
#include "audio_convert.h"

int sp_pcm_to_pcm24k(const uint8_t *input, uint32_t bytes, const ss_format *format,
                    uint8_t *output, uint32_t capacity, sp_pcm_info *info,
                    uint32_t volume_step) {
    uintptr_t a=(uintptr_t)input,b=(uintptr_t)output,c=(uintptr_t)info,d=(uintptr_t)format;
    if(volume_step<1 || volume_step>10 || !span(a,bytes) || !span(b,capacity) ||
       !span(c,sizeof(*info)) || !span(d,sizeof(*format)))return CSND_CONVERT_INVALID;
    if(overlap(a,bytes,b,capacity) || overlap(a,bytes,c,sizeof(*info)) ||
       overlap(b,capacity,c,sizeof(*info)) || overlap(d,sizeof(*format),a,bytes) ||
       overlap(d,sizeof(*format),b,capacity) || overlap(d,sizeof(*format),c,sizeof(*info)))
        return CSND_CONVERT_OVERLAP;
    fir_state s;s.f=*format;
    if(bytes>SS_MAX_WAV_BYTES)return CSND_CONVERT_LIMIT;
    if((s.f.channels!=1 && s.f.channels!=2) || s.f.sample_rate<8000 || s.f.sample_rate>192000 ||
       (s.f.bits_per_sample!=8 && s.f.bits_per_sample!=16 && s.f.bits_per_sample!=24 && s.f.bits_per_sample!=32) ||
       s.f.block_align!=s.f.channels*(s.f.bits_per_sample/8) || s.f.data_offset ||
       s.f.data_bytes!=bytes || bytes%s.f.block_align || s.f.frames!=bytes/s.f.block_align)
        return CSND_CONVERT_WAV;
    if(!s.f.frames || s.f.frames>s.f.sample_rate*SS_MAX_SECONDS)return CSND_CONVERT_LIMIT;
    uint32_t frames=(uint32_t)(((uint64_t)s.f.frames*24000+s.f.sample_rate-1)/s.f.sample_rate);
    if(!frames || frames>CSND_MAX_PCM_FRAMES)return CSND_CONVERT_LIMIT;
    if(capacity<frames*2)return CSND_CONVERT_CAPACITY;
    s.data=input;
    s.scale=s.f.sample_rate>24000?(uint32_t)(((uint64_t)24000*Q24)/s.f.sample_rate):Q24;
    s.half=s.f.sample_rate>24000?(KERNEL_RADIUS*s.f.sample_rate+23999)/24000:KERNEL_RADIUS;
    s.last_phase=0xffffffffu;
    uint32_t center=0,phase=0,peak=0;
    for(uint32_t i=0;i<frames;i++) {
        int32_t v=sample(&s,center,phase);uint32_t p=(uint32_t)(v<0?-v:v);
        if(p>peak)peak=p;
        advance(&s.f,&center,&phase);
    }
    uint32_t denominator=peak>32768?peak:32768;
    center=0;phase=0;
    for(uint32_t i=0;i<frames;i++) {
        int32_t v=sample(&s,center,phase);
        int32_t pcm=(int32_t)((((int64_t)v*7864)/denominator)*(int64_t)volume_step/5);
        uint16_t le=(uint16_t)pcm;
        output[i*2]=(uint8_t)le;output[i*2+1]=(uint8_t)(le>>8);
        advance(&s.f,&center,&phase);
    }
    sp_pcm_info r={1,s.f.sample_rate,s.f.frames,frames,frames*2,peak,denominator,volume_step};
    *info=r;return CSND_CONVERT_OK;
}

int sp_wav_to_pcm24k(const uint8_t *wav,uint32_t bytes,uint8_t *output,uint32_t capacity,
                    sp_pcm_info *info,uint32_t volume_step) {
    uintptr_t a=(uintptr_t)wav,b=(uintptr_t)output,c=(uintptr_t)info;
    if(!span(a,bytes) || !span(b,capacity) || !span(c,sizeof(*info)))return CSND_CONVERT_INVALID;
    if(overlap(a,bytes,b,capacity) || overlap(a,bytes,c,sizeof(*info)) ||
       overlap(b,capacity,c,sizeof(*info)))return CSND_CONVERT_OVERLAP;
    ss_format f;int status=ss_parse_wav(wav,bytes,&f);
    if(status!=SS_OK)return status==SS_LIMIT?CSND_CONVERT_LIMIT:CSND_CONVERT_WAV;
    const uint8_t *pcm=wav+f.data_offset;f.data_offset=0;
    return sp_pcm_to_pcm24k(pcm,f.data_bytes,&f,output,capacity,info,volume_step);
}
