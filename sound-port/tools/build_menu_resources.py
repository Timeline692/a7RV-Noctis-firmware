"""Transfer only the public reference ADD strings into the 68 extracted RV banks."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import struct
from uxc_resources import REFERENCE_IDS, PUBLIC_DELTA, parse, repack

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'analysis/targets/menu'
OUT = ROOT / 'sound-port/menu/resources'
PROFILE = ROOT / 'references/sony-a7m4-custom-firmware/a7m4/profiles/custom-sounds-reference.json'


def public_strings(row: dict) -> dict[int, str]:
    chunks = [base64.b64decode(op['data'], validate=True) for op in row['ops'] if 'data' in op]
    result = {}
    for rid in REFERENCE_IDS:
        needle, found = struct.pack('<I', rid + PUBLIC_DELTA), set()
        for b in chunks:
            at = 0
            while True:
                pos = b.find(needle, at)
                if pos < 0:
                    break
                end = b.find(b'\0', pos + 4, pos + 4 + 4096)
                if end >= 0:
                    try:
                        text = b[pos + 4:end].decode('utf8')
                        if not any(ord(c) < 32 and c not in '\n\t\r' for c in text):
                            found.add(text)
                    except UnicodeError:
                        pass
                at = pos + 1
        if len(found) != 1:
            raise ValueError(f'Expected exactly one public ADD text for {row["path"]} {rid:#x}: {found}')
        result[rid] = found.pop()
    if result[0x0200AB60] != '' or [result[r] for r in range(0x0200ABD8, 0x0200ABE2)] != [f'{n}%' for n in range(10, 101, 10)]:
        raise ValueError('Reference retired-caption/volume label contract mismatch')
    return result


def main():
    profile = json.loads(PROFILE.read_text(encoding='utf8'))
    rows = [r for r in profile['files'] if r['path'].startswith('share/app/string_')]
    if len(rows) != 68:
        raise ValueError('Reference must describe both orientations for 34 languages')
    prepared, evidence, labels = {}, [], {}
    for row in rows:
        path = SOURCE / row['path']
        source = path.read_bytes()
        before, native = parse(source)
        additions = public_strings(row)
        for rid, text in additions.items():
            if native.get(rid) not in (None, ''):
                raise ValueError(f'RV ID already occupied: {row["path"]} {rid:#x}')
        result = repack(source, native | additions)
        after, final = parse(result)
        if any(final.get(rid) != text for rid, text in native.items() if rid not in additions):
            raise ValueError('An original resource record changed')
        prepared[row['path']] = result
        labels[row['path']] = {hex(k): v for k, v in additions.items()}
        evidence.append({'path': row['path'], 'source_sha256': before['sha256'], 'output_sha256': after['sha256'],
                         'source_bytes': len(source), 'output_bytes': len(result),
                         'source_count': before['count'], 'output_count': after['count'],
                         'original_records_preserved': len(native), 'added_records': len(additions)})
    if OUT.exists():
        raise ValueError('Output already exists; choose/review a new generation before rebuilding')
    for name, result in prepared.items():
        target = OUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as f:
            f.write(result)
    menu = OUT.parent
    (menu / 'public-reference-labels.json').write_text(json.dumps(labels, ensure_ascii=False, indent=2), encoding='utf8')
    manifest = {'schema': 1, 'firmware': 'A7R V 4.00 supplied BODYDATA.DAT',
                'reference_commit': 'caa29145644e1d7d0a41cef1e42f0c53368bd025',
                'reference_source': str(PROFILE.relative_to(ROOT)), 'reference_copy_data_used': False,
                'files': evidence, 'banks': 68, 'languages': 34, 'text_records_added': 1360,
                'camera_io': False, 'glyph_rendering_tested': False,
                'mpr_modification_required_for_uxc_count': 'not established; count is encoded in each UXC header'}
    (menu / 'resource-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'banks': 68, 'languages': 34, 'added_records': 1360,
                      'counts': sorted({(r['source_count'], r['output_count']) for r in evidence}),
                      'output': str(OUT)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
