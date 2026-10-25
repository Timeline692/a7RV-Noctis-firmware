#ifndef SOUND_PORT_AUDIO_CONVERT_H
#define SOUND_PORT_AUDIO_CONVERT_H
#include "convert.h"

enum { SP_MAX_PCM_BYTES = CSND_MAX_PCM_FRAMES * 2 };
typedef struct {
    uint32_t schema, source_rate, source_frames, pcm_frames;
    uint32_t pcm_bytes, source_peak, gain_denominator, volume_step;
} sp_pcm_info;

/* Same integer WAV/FIR/gain contract as the reference converter. Output is
 * little-endian signed PCM16, mono, 24000 Hz; no header or trailing guard.
 * Input, destination capacity, format and info must be pairwise disjoint.
 * Failure leaves destination/info untouched. Caller serializes all calls.
 * This is an audio payload; registration in the RV driver is adapter work. */
int sp_wav_to_pcm24k(const uint8_t *, uint32_t, uint8_t *, uint32_t,
                    sp_pcm_info *, uint32_t volume_step);
int sp_pcm_to_pcm24k(const uint8_t *, uint32_t, const ss_format *,
                    uint8_t *, uint32_t, sp_pcm_info *, uint32_t volume_step);
#endif
