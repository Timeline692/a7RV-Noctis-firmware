"""Build the real portable C core; Python stdlib only, no camera operations."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / 'sound-port/common'
OUT = ROOT / 'sound-port/build/common'
SOURCES = [COMMON / ('src/' + name) for name in
           ('sound_core.c', 'audio_convert.c', 'volume_codec.c', 'memory.c')]


def elf_info(path: Path) -> dict:
    b = path.read_bytes()
    if b[:4] != b'\x7fELF' or b[5] != 1:
        raise ValueError('Expected little-endian ELF')
    bits = b[4] * 32
    machine = struct.unpack_from('<H', b, 18)[0]
    if bits == 64:
        shoff = struct.unpack_from('<Q', b, 40)[0]
        size, count = struct.unpack_from('<HH', b, 58)
        fmt = '<IIQQQQIIQQ'
        symfmt = '<IBBHQQ'
    else:
        shoff = struct.unpack_from('<I', b, 32)[0]
        size, count = struct.unpack_from('<HH', b, 46)
        fmt = '<IIIIIIIIII'
        symfmt = '<IIIBBH'
    sections = [struct.unpack_from(fmt, b, shoff + size * i) for i in range(count)]
    unresolved = []
    symbols = []
    for s in sections:
        if s[1] != 2:
            continue
        strings = sections[s[6]]
        st = b[strings[4]:strings[4] + strings[5]]
        for at in range(s[4], s[4] + s[5], s[9]):
            symbol = struct.unpack_from(symfmt, b, at)
            name_at = symbol[0]
            name = st[name_at:st.find(b'\0', name_at)].decode('utf8')
            info, ndx = (symbol[1], symbol[3]) if bits == 64 else (symbol[3], symbol[5])
            if name and info >> 4 in (1, 2):
                symbols.append(name)
                if ndx == 0:
                    unresolved.append(name)
    return {'bits': bits, 'machine': machine, 'bytes': len(b),
            'undefined_symbols': sorted(set(unresolved)), 'global_symbols': sorted(set(symbols))}


def run(command: list[str], log: Path) -> dict:
    p = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True, text=True,
                       encoding='utf8', errors='replace')
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(p.stdout + p.stderr, encoding='utf8')
    return {'command': [str(x) for x in command], 'exit_code': p.returncode,
            'log': str(log.relative_to(ROOT))}


def build(host: bool, cross: bool) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    gcc = shutil.which('gcc') or r'D:\Apps\mingw64\bin\gcc.exe'
    zig = ROOT / 'toolchains/zig-x86_64-windows-0.15.2/zig.exe'
    result = {'schema': 1, 'gcc': str(gcc), 'zig': str(zig), 'artifacts': {}, 'camera_io': False}
    base = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Wno-misleading-indentation',
            '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
            '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-I' + str(COMMON / 'include')]
    if host:
        dll = OUT / 'sound_core.dll'
        r = run([gcc, *base, '-shared', *map(str, SOURCES), '-o', str(dll)], OUT / 'host.log')
        r.update(path=str(dll.relative_to(ROOT)), status='PASS' if r['exit_code'] == 0 else 'BUILD_FAILED')
        result['artifacts']['host'] = r
    if cross:
        for key, target, flags in [
                ('aarch64', 'aarch64-freestanding-none', ['-mgeneral-regs-only', '-mno-outline-atomics']),
                ('armv7_thumb', 'thumb-freestanding-eabi', ['-mcpu=cortex_a8', '-mfloat-abi=soft'])]:
            folder = OUT / key
            folder.mkdir(exist_ok=True)
            objects, commands = [], []
            for source in SOURCES:
                obj = folder / (source.stem + '.o')
                r = run([str(zig), 'cc', '-target', target, *flags, *base, '-c', str(source), '-o', str(obj)],
                        folder / (source.stem + '.log'))
                commands.append(r)
                if r['exit_code']:
                    break
                objects.append(obj)
            r = {'target': target, 'commands': commands, 'status': 'BUILD_FAILED'}
            if len(objects) == len(SOURCES):
                archive = folder / 'libsound_port.a'
                ar = run([str(zig), 'ar', 'rcs', str(archive), *map(str, objects)], folder / 'archive.log')
                commands.append(ar)
                r['archive'] = str(archive.relative_to(ROOT))
                r['object_dependencies'] = {o.name: elf_info(o)['undefined_symbols'] for o in objects}
                # Link every routine; no GC hiding missing ARM division/memory helpers.
                linked = folder / 'sound_port_linkcheck.elf'
                link = run([str(zig), 'cc', '-target', target, *flags, '-nostdlib',
                            '-Wl,-e,sp_wav_to_pcm24k', '-Wl,--no-gc-sections',
                            *map(str, objects), '-o', str(linked)], folder / 'link.log')
                commands.append(link)
                if not ar['exit_code'] and not link['exit_code']:
                    r['linked'] = str(linked.relative_to(ROOT))
                    r['elf'] = elf_info(linked)
                    r['status'] = 'PASS' if not r['elf']['undefined_symbols'] else 'UNRESOLVED_SYMBOLS'
                elif not ar['exit_code']:
                    r['status'] = 'ARCHIVE_ONLY_LINK_FAILED'
            result['artifacts'][key] = r
    (ROOT / 'analysis/sound-port-common-build.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host-only', action='store_true')
    p.add_argument('--cross-only', action='store_true')
    a = p.parse_args()
    r = build(not a.cross_only, not a.host_only)
    print(json.dumps({k: v['status'] for k, v in r['artifacts'].items()}, indent=2))
    raise SystemExit(any(v['status'] != 'PASS' for v in r['artifacts'].values()))
