"""Inspect/repack indexed UXC text banks; writes a new file with explicit old values."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

PUBLIC_DELTA = 0x1C000000
REFERENCE_IDS = [*range(0x0200AB5C, 0x0200AB66), *range(0x0200ABD8, 0x0200ABE2)]


def parse(data: bytes) -> tuple[dict, dict[int, str]]:
    if len(data) < 16 or data[:4] != b'uxc\x07':
        raise ValueError('Not an indexed UXC v7 bank')
    count, rem = divmod(struct.unpack_from('<I', data, 12)[0], 0x1001)
    base = (16 + count * 2 + 3) & ~3
    if rem or not 0 < count <= 8192 or base > len(data):
        raise ValueError('Invalid index count/bounds')
    bank = struct.unpack_from('<H', data, 10)[0]
    first = 0x1E000000 + (bank << 13)
    records = {}
    for index in range(count):
        offset = struct.unpack_from('<H', data, 16 + 2 * index)[0]
        if offset == 0xFFFF:
            continue
        pos, physical = base + 4 * offset, first + index
        if pos + 4 > len(data) or struct.unpack_from('<I', data, pos)[0] != physical:
            raise ValueError(f'Invalid indexed record {index}')
        end = data.find(b'\0', pos + 4)
        if end < 0:
            raise ValueError(f'Unterminated text {index}')
        records[physical - PUBLIC_DELTA] = data[pos + 4:end].decode('utf8')
    return {'schema': 1, 'bytes': len(data), 'bank': bank, 'count': count, 'data_base': base,
            'public_first_id': hex(first - PUBLIC_DELTA), 'records': len(records),
            'unused_indices': count - len(records), 'sha256': hashlib.sha256(data).hexdigest()}, records


def repack(data: bytes, records: dict[int, str]) -> bytes:
    header, _ = parse(data)
    count, base = header['count'], header['data_base']
    first = int(header['public_first_id'], 16)
    needed = max((rid - first + 1 for rid in records), default=count)
    if needed > 8192:
        raise ValueError('ID exceeds indexed bank capacity')
    if needed > count:
        count = needed
        base = (16 + 2 * count + 3) & ~3
        out = bytearray(data[:16]) + bytes(base - 16)
        struct.pack_into('<I', out, 12, count * 0x1001)
    else:
        out = bytearray(data[:base])
    out[16:16 + count * 2] = b'\xff\xff' * count
    # Longest last reduces the maximum start offset stored in the u16 index.
    encoded = []
    for public, text in records.items():
        if not first <= public < first + count or '\0' in text:
            raise ValueError('ID outside this bank or NUL inside text')
        encoded.append((public, text.encode('utf8')))
    for public, text in sorted(encoded, key=lambda item: (len(item[1]), item[0])):
        offset = (len(out) - base) // 4
        if offset >= 0xFFFF:
            raise ValueError('UXC word offset overflow')
        struct.pack_into('<H', out, 16 + 2 * (public - first), offset)
        out += struct.pack('<I', public + PUBLIC_DELTA) + text + b'\0'
        out += bytes((-len(out)) % 4)
    result = bytes(out)
    if parse(result)[1] != records:
        raise ValueError('Repacked bank failed the semantic record check')
    return result


def update(data: bytes, specification: dict) -> bytes:
    info, records = parse(data)
    if specification.get('schema') != 1 or specification.get('source_sha256') != info['sha256']:
        raise ValueError('Schema/source SHA256 mismatch')
    changes = specification.get('changes')
    if not isinstance(changes, list) or not changes:
        raise ValueError('No explicit changes')
    seen = set()
    for change in changes:
        rid = int(change['id'], 0) if isinstance(change['id'], str) else change['id']
        if rid in seen or set(change) != {'id', 'old', 'text'}:
            raise ValueError('Duplicate ID or incomplete change')
        seen.add(rid)
        if records.get(rid) != change['old'] or not isinstance(change['text'], str):
            raise ValueError(f'Old text mismatch for {rid:#x}')
        records[rid] = change['text']
    return repack(data, records)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('inspect'); q.add_argument('input', type=Path)
    q.add_argument('--id', action='append', type=lambda v: int(v, 0))
    q = sub.add_parser('update'); q.add_argument('input', type=Path)
    q.add_argument('changes', type=Path); q.add_argument('output', type=Path)
    a = p.parse_args(); data = a.input.read_bytes(); info, records = parse(data)
    if a.command == 'inspect':
        ids = a.id or REFERENCE_IDS
        info['requested_text'] = {hex(rid): records.get(rid) for rid in ids}
        print(json.dumps(info, ensure_ascii=False, indent=2)); return
    if a.input.resolve() == a.output.resolve() or a.output.exists():
        raise ValueError('Choose a new output path')
    result = update(data, json.loads(a.changes.read_text(encoding='utf8')))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('xb') as f:
        f.write(result)
    print(json.dumps({'source': info, 'output': str(a.output), 'result': parse(result)[0]},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
