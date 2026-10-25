"""Host binding for the actual C core, audio conversion and restartable settings."""
from __future__ import annotations
import argparse
import ctypes as C
import json
import os
from pathlib import Path
import wave

ROOT = Path(__file__).resolve().parents[2]
U8 = C.c_ubyte
U32 = C.c_uint32


class Format(C.Structure):
    _fields_ = [(k, U32) for k in ('channels', 'sample_rate', 'bits_per_sample', 'block_align',
                                 'data_offset', 'data_bytes', 'frames')]


class Slot(C.Structure):
    _fields_ = [(k, U32) for k in ('enabled', 'custom', 'wav_bytes', 'name_bytes')] + [
        ('sha256', U8 * 32), ('name', C.c_char * 256), ('wav', C.POINTER(U8)), ('format', Format)]


class State(C.Structure):
    _fields_ = [('generation', U32), ('slots', Slot * 2)]


class PcmInfo(C.Structure):
    _fields_ = [(k, U32) for k in ('schema', 'source_rate', 'source_frames', 'pcm_frames',
                                  'pcm_bytes', 'source_peak', 'gain_denominator', 'volume_step')]


class Volume(C.Structure):
    _fields_ = [('steps', U32 * 2)]


Commit = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(State))
VolumeCommit = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(U8), C.c_size_t)


def buffer(data: bytes):
    return (U8 * len(data)).from_buffer_copy(data)


def check(status: int):
    if status:
        raise ValueError(f'C core status {status}')


def load_core(path: Path | None = None):
    # MinGW's CRT uses libmcfgthread-2.dll; retain the search handle as long as
    # the loaded DLL, rather than modifying the user's global PATH.
    dependency_dir = os.add_dll_directory(r'D:\Apps\mingw64\bin') if os.name == 'nt' else None
    lib = C.CDLL(str(path or ROOT / 'sound-port/build/common/sound_core.dll'))
    lib._dependency_dir = dependency_dir
    sigs = {
        'ss_init': ([C.POINTER(State)], None),
        'ss_parse_wav': ([C.POINTER(U8), C.c_size_t, C.POINTER(Format)], C.c_int),
        'ss_set_enabled': ([C.POINTER(State), U32, U32, U32, Commit, C.c_void_p], C.c_int),
        'ss_import': ([C.POINTER(State), U32, C.c_char_p, C.c_size_t, C.POINTER(U8), C.c_size_t, Commit, C.c_void_p], C.c_int),
        'ss_snapshot_size': ([C.POINTER(State)], C.c_size_t),
        'ss_snapshot_write': ([C.POINTER(State), C.POINTER(U8), C.c_size_t, C.POINTER(C.c_size_t)], C.c_int),
        'ss_snapshot_restore': ([C.POINTER(State), C.POINTER(U8), C.c_size_t], C.c_int),
        'sp_wav_to_pcm24k': ([C.POINTER(U8), U32, C.POINTER(U8), U32, C.POINTER(PcmInfo), U32], C.c_int),
        'sp_volume_init': ([C.POINTER(Volume)], None),
        'sp_volume_encode': ([C.POINTER(Volume), C.POINTER(U8)], C.c_int),
        'sp_volume_decode': ([C.POINTER(Volume), C.POINTER(U8), C.c_size_t], C.c_int),
        'sp_volume_set': ([C.POINTER(Volume), U32, U32, VolumeCommit, C.c_void_p], C.c_int),
    }
    for name, (args, ret) in sigs.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, ret
    return lib


def pcm24k(core, wav: bytes, step: int = 5) -> tuple[bytes, dict]:
    src, dst, info = buffer(wav), (U8 * 240000)(), PcmInfo()
    check(core.sp_wav_to_pcm24k(src, len(wav), dst, len(dst), C.byref(info), step))
    return bytes(dst[:info.pcm_bytes]), {k: getattr(info, k) for k, _ in info._fields_}


def snapshot(core, state) -> bytes:
    n = core.ss_snapshot_size(state)
    if not n:
        raise ValueError('Invalid core state')
    dst, written = (U8 * n)(), C.c_size_t()
    check(core.ss_snapshot_write(state, dst, n, C.byref(written)))
    return bytes(dst[:written.value])


def publish(path: Path, data: bytes, valid) -> None:
    """Atomic host publication; only a valid primary replaces the previous backup."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary, backup = path.with_suffix('.tmp'), path.with_suffix('.bak')
    with temporary.open('wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # Corrupt primary after a backup restore must never overwrite that backup.
    if path.exists() and valid(path.read_bytes()):
        os.replace(path, backup)
    try:
        os.replace(temporary, path)
    except OSError:
        if not path.exists() and backup.exists():
            os.replace(backup, path)
        raise
    # POSIX directory fsync; Windows os.replace provides atomic name publication,
    # but this host test does not assert camera power-loss durability.
    if os.name != 'nt':
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Store:
    """WAV buffers are pinned for this process; no camera playback is performed."""
    def __init__(self, core, directory: Path):
        self.core, self.directory, self.buffers = core, directory, []
        self.state, self.volume = State(), Volume()
        core.ss_init(C.byref(self.state))
        core.sp_volume_init(C.byref(self.volume))
        self.restored_from = {}
        self.last_error = None
        for name, dst, validate in [('settings.bin', self.state, self.valid_snapshot),
                                    ('volume.bin', self.volume, self.valid_volume)]:
            path = directory / name
            for candidate in (path, path.with_suffix('.bak')):
                if not candidate.exists():
                    continue
                data = candidate.read_bytes()
                if not validate(data):
                    continue
                src = buffer(data)
                fn = core.ss_snapshot_restore if name == 'settings.bin' else core.sp_volume_decode
                check(fn(C.byref(dst), src, len(data)))
                self.buffers.append(src)
                self.restored_from[name] = candidate.name
                break
        self.commit = Commit(self._commit)
        self.volume_commit = VolumeCommit(self._volume_commit)

    def valid_snapshot(self, data):
        return self.core.ss_snapshot_restore(C.byref(State()), buffer(data), len(data)) == 0

    def valid_volume(self, data):
        return self.core.sp_volume_decode(C.byref(Volume()), buffer(data), len(data)) == 0

    def _commit(self, context, state):
        try:
            publish(self.directory / 'settings.bin', snapshot(self.core, state), self.valid_snapshot)
            return 0
        except Exception as error:
            self.last_error = str(error)
            return -1

    def _volume_commit(self, context, data, n):
        try:
            publish(self.directory / 'volume.bin', bytes(data[:n]), self.valid_volume)
            return 0
        except Exception as error:
            self.last_error = str(error)
            return -1

    def enabled(self, slot: int, enabled: int):
        check(self.core.ss_set_enabled(C.byref(self.state), slot, enabled, 0, self.commit, None))

    def import_wav(self, path: Path, slot: int = 0):
        data, name = path.read_bytes(), path.name.encode('utf8')
        src = buffer(data)
        check(self.core.ss_import(C.byref(self.state), slot, name, len(name), src, len(data), self.commit, None))
        self.buffers.append(src)

    def set_volume(self, slot: int, step: int):
        check(self.core.sp_volume_set(C.byref(self.volume), slot, step, self.volume_commit, None))

    def describe(self):
        return {'generation': self.state.generation, 'restored_from': self.restored_from,
                'slots': [{'slot': i, 'enabled': s.enabled, 'custom': s.custom,
                           'name': bytes(s.name).decode('utf8'), 'wav_bytes': s.wav_bytes,
                           'volume_step': self.volume.steps[i]} for i, s in enumerate(self.state.slots)]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('convert')
    c.add_argument('wav', type=Path); c.add_argument('output', type=Path)
    c.add_argument('--step', type=int, default=5)
    for command in ('show', 'enable', 'import', 'volume'):
        q = sub.add_parser(command); q.add_argument('directory', type=Path)
        if command != 'show':
            q.add_argument('--slot', type=int, choices=(0, 1), default=0)
        if command == 'enable': q.add_argument('enabled', type=int, choices=(0, 1))
        if command == 'import': q.add_argument('wav', type=Path)
        if command == 'volume': q.add_argument('step', type=int, choices=range(1, 11))
    a, core = p.parse_args(), load_core()
    if a.command == 'convert':
        pcm, info = pcm24k(core, a.wav.read_bytes(), a.step)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_bytes(pcm)
        preview = a.output.with_suffix('.wav')
        with wave.open(str(preview), 'wb') as w:
            w.setparams((1, 2, 24000, 0, 'NONE', 'not compressed')); w.writeframes(pcm)
        info.update(input=str(a.wav), output=str(a.output), preview=str(preview), format='LPCM16_LE_24k_mono')
        a.output.with_suffix('.json').write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding='utf8')
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    store = Store(core, a.directory)
    if a.command == 'enable': store.enabled(a.slot, a.enabled)
    if a.command == 'import': store.import_wav(a.wav, a.slot)
    if a.command == 'volume': store.set_volume(a.slot, a.step)
    print(json.dumps(store.describe(), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
