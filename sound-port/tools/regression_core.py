"""One bounded integration regression of the compiled C core and host adapters."""
from __future__ import annotations
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import zlib
from sound_assets import ROOT, U8, State, PcmInfo, Volume, Commit, VolumeCommit, Store, buffer, load_core, pcm24k, snapshot
from uxc_resources import parse, repack, update


def wav_pcm(bits=16, channels=1, rate=24000, frames=120, value=12000):
    if bits == 8:
        unit, expected = bytes([128 + value // 256]), (value // 256) * 256
    else:
        unit, expected = (value << (bits - 16)).to_bytes(bits // 8, 'little', signed=True), value
    raw = unit * channels * frames
    align = channels * bits // 8
    fmt = struct.pack('<HHIIHH', 1, channels, rate, rate * align, align, bits)
    body = b'WAVEfmt ' + struct.pack('<I', 16) + fmt + b'data' + struct.pack('<I', len(raw)) + raw
    if len(raw) & 1:
        body += b'\0'
    return b'RIFF' + struct.pack('<I', len(body)) + body, expected


def samples(pcm):
    return struct.unpack('<' + 'h' * (len(pcm) // 2), pcm)


def main():
    core = load_core()
    accepted = []
    # DC gain is an independent numeric oracle for all accepted integer formats
    # and the down/up-sampling boundaries; stereo uses equal channels.
    for bits in (8, 16, 24, 32):
        for channels in (1, 2):
            for rate in (8000, 24000, 44100, 192000):
                wav, source = wav_pcm(bits, channels, rate, max(2, rate // 200))
                pcm, info = pcm24k(core, wav)
                frames = ((max(2, rate // 200)) * 24000 + rate - 1) // rate
                expected = source * 7864 // 32768
                assert info['pcm_frames'] == frames and len(pcm) == frames * 2
                assert set(samples(pcm)) == {expected}, (bits, channels, rate, expected, set(samples(pcm)))
                accepted.append({'bits': bits, 'channels': channels, 'rate': rate, 'frames': frames})
    good, _ = wav_pcm()
    malformed = {'truncated': good[:-1], 'float': good[:20] + b'\x03\x00' + good[22:],
                 'wave_extensible': good[:20] + b'\xfe\xff' + good[22:],
                 'byte_rate': good[:28] + struct.pack('<I', 1) + good[32:],
                 'block_align': good[:32] + b'\x01\x00' + good[34:],
                 'riff_length': good[:4] + struct.pack('<I', len(good)) + good[8:],
                 'over_five_seconds': wav_pcm(8, 1, 8000, 40001)[0],
                 'over_one_mib': good + bytes(1048577 - len(good))}
    duplicated = good + good[12:36]
    malformed['duplicate_fmt'] = duplicated[:4] + struct.pack('<I', len(duplicated) - 8) + duplicated[8:]
    duplicated = good + good[36:]
    malformed['duplicate_data'] = duplicated[:4] + struct.pack('<I', len(duplicated) - 8) + duplicated[8:]
    rejected = {}
    for name, bad in malformed.items():
        dst, info = (U8 * 240000)(*([0xA5] * 240000)), PcmInfo()
        C.memset(C.byref(info), 0x5A, C.sizeof(info))
        before = bytes(info)
        code = core.sp_wav_to_pcm24k(buffer(bad), len(bad), dst, len(dst), C.byref(info), 5)
        assert code != 0 and bytes(dst) == bytes([0xA5]) * 240000 and bytes(info) == before
        rejected[name] = code
    # Insufficient output, overlap and invalid volume must not partially publish.
    source = buffer(good); info = PcmInfo(); small = (U8 * 1)(0xA5)
    assert core.sp_wav_to_pcm24k(source, len(good), small, 1, C.byref(info), 5) == -2
    assert small[0] == 0xA5
    assert core.sp_wav_to_pcm24k(source, len(good), source, len(good), C.byref(info), 5) == -3
    dst = (U8 * 240000)()
    assert core.sp_wav_to_pcm24k(source, len(good), dst, len(dst), C.byref(info), 11) == -1
    gain = {}
    for step in (1, 5, 10):
        pcm, _ = pcm24k(core, good, step)
        expected = (12000 * 7864 // 32768) * step // 5
        assert set(samples(pcm)) == {expected}
        gain[step] = expected
    # Original F0 and new LPCM share the pre-quantization audio path. Compare a
    # nonconstant clip once; this is not a claim that F0 is the RV ADPCM codec.
    clip = (ROOT / 'sound-prototype/click.wav').read_bytes()
    pcm, ci = pcm24k(core, clip)
    f0, fi = (U8 * 153600)(), PcmInfo()
    core.csnd_wav_to_f0.argtypes = [C.POINTER(U8), C.c_uint32, C.POINTER(U8), C.c_uint32, C.POINTER(PcmInfo)]
    assert core.csnd_wav_to_f0(buffer(clip), len(clip), f0, len(f0), C.byref(fi)) == 0
    # Fifth field in reference csnd_convert_info is encoded_bytes.
    decoded = []
    for at in range(0, fi.pcm_bytes, 32):
        shift = f0[at]
        assert shift <= 7
        decoded.extend((v if v < 128 else v - 256) << shift for v in f0[at + 1:at + 32])
    errors = [abs(a - b) for a, b in zip(samples(pcm), decoded[:ci['pcm_frames']])]
    assert max(errors) <= 64
    assert bytes(f0[fi.pcm_bytes:]) == bytes(len(f0) - fi.pcm_bytes)
    with tempfile.TemporaryDirectory(prefix='sound-port-regression-') as temporary:
        directory = Path(temporary)
        clipfile = directory / '快门.wav'; clipfile.write_bytes(clip)
        store = Store(core, directory / 'settings')
        store.enabled(0, 1); store.import_wav(clipfile)
        store.enabled(1, 1); store.import_wav(clipfile, 1)
        store.set_volume(0, 8); store.set_volume(0, 10)
        reboot = Store(core, store.directory)
        assert reboot.state.generation == 4
        assert [s.custom for s in reboot.state.slots] == [1, 1]
        assert reboot.volume.steps[0] == 10
        assert C.string_at(reboot.state.slots[0].wav, len(clip)) == clip
        wire = snapshot(core, C.byref(reboot.state))
        assert wire[:8] == b'SSND001\0' and len(wire) == 640 + 2 * len(clip)
        before = bytes(reboot.state)
        corrupt = bytearray(wire); corrupt[-1] ^= 1
        assert core.ss_snapshot_restore(C.byref(reboot.state), buffer(corrupt), len(corrupt)) == 7
        assert bytes(reboot.state) == before
        corrupt[20:24] = bytes(4)
        corrupt[20:24] = struct.pack('<I', zlib.crc32(corrupt))
        assert core.ss_snapshot_restore(C.byref(reboot.state), buffer(corrupt), len(corrupt)) == 7
        assert bytes(reboot.state) == before  # waveform SHA catches repaired-CRC corruption
        failed = Commit(lambda context, state: -1)
        assert core.ss_set_enabled(C.byref(reboot.state), 0, 0, 0, failed, None) == 4
        assert bytes(reboot.state) == before
        vbefore = bytes(reboot.volume)
        failed_v = VolumeCommit(lambda context, payload, n: -1)
        assert core.sp_volume_set(C.byref(reboot.volume), 0, 2, failed_v, None) == 4
        assert bytes(reboot.volume) == vbefore
        vwire = (U8 * 24)()
        assert core.sp_volume_encode(C.byref(reboot.volume), vwire) == 0
        assert bytes(vwire[:4]) == b'CVOL' and len(vwire) == 24
        vwire[8] ^= 1
        assert core.sp_volume_decode(C.byref(reboot.volume), vwire, 24) == 7
        assert bytes(reboot.volume) == vbefore
        (store.directory / 'volume.bin').write_bytes(b'corrupt')
        (store.directory / 'settings.bin').write_bytes(b'corrupt')
        fallback = Store(core, store.directory)
        assert fallback.state.generation == 3 and fallback.state.slots[0].custom == 1
        assert fallback.volume.steps[0] == 8
        assert fallback.restored_from == {'settings.bin': 'settings.bak', 'volume.bin': 'volume.bak'}
        backup_v = (store.directory / 'volume.bak').read_bytes()
        fallback.set_volume(0, 6)
        assert (store.directory / 'volume.bak').read_bytes() == backup_v
        assert Store(core, store.directory).volume.steps[0] == 6
        persistence = {'restart_generation': 4, 'waveform_sha256': hashlib.sha256(clip).hexdigest(),
                       'recovered_generation': fallback.state.generation,
                       'backup_volume_step': 8, 'recovery_publish_volume_step': 6,
                       'failed_commits_leave_state_unchanged': True,
                       'repaired_crc_waveform_corruption_rejected_by_sha256': True}
    # A synthetic bank verifies the generic RV resource tool independently of
    # reference private-ID availability; original code/text are not mutated.
    bank = bytearray(b'uxc\x07' + bytes(12))
    struct.pack_into('<H', bank, 10, 5)
    struct.pack_into('<I', bank, 12, 4096 * 0x1001)
    bank += b'\xff\xff' * 4096
    records = {0x0200AB00: '保留的菜单', 0x0200AB5C: ''}
    original = repack(bytes(bank), records)
    spec = {'schema': 1, 'source_sha256': hashlib.sha256(original).hexdigest(),
            'changes': [{'id': '0x0200AB5C', 'old': '', 'text': '自定义电子快门声'},
                        {'id': '0x0200AB65', 'old': None, 'text': '音量'}]}
    patched = update(original, spec)
    assert parse(patched)[1] == {**records, 0x0200AB5C: '自定义电子快门声', 0x0200AB65: '音量'}
    try:
        update(patched, spec)
    except ValueError:
        pass
    else:
        raise AssertionError('Wrong source accepted')
    report = {'schema': 1, 'status': 'PASS', 'accepted_format_cases': accepted,
              'malformed_wavs_rejected_without_output_mutation': rejected,
              'capacity_overlap_volume_validation': 'PASS', 'volume_gain_dc': gain,
              'reference_f0_vs_lpcm_max_error': max(errors), 'reference_f0_is_rv_adpcm': False,
              'persistence': persistence, 'uxc_synthetic_roundtrip': 'PASS',
              'camera_io': False, 'camera_power_loss_durability_tested': False}
    (ROOT / 'analysis/sound-port-core-regression.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'status': 'PASS', 'accepted_cases': len(accepted), 'rejected_cases': len(rejected),
                      'persistence': 'PASS', 'uxc': 'PASS', 'f0_pcm_max_error': max(errors)}, indent=2))


if __name__ == '__main__':
    main()
