"""Targeted extraction of existing decoded RV menu resources, without unpacking again."""
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'references/fwtool-a7iv'))
from fwtool import archive
from fwtool.io import FilePart


def main():
    meta = json.loads((ROOT / 'analysis/firmware-probe.json').read_text(encoding='utf8'))
    members = json.loads((ROOT / 'analysis/update-tar-inventory.json').read_text(encoding='utf8'))
    out = ROOT / 'analysis/targets/menu'
    member, = [r for r in members if r['name'] == '0700_part_image/dev/nflasha15']
    rows = []
    with open(meta['decoded_path'], 'rb') as source:
        image = FilePart(source, meta['firmware_offset'] + member['offset_in_tar'], member['size'])
        for entry in archive.readArchive(image):
            wanted = entry.path == '/lib/libmpr.so' or re.fullmatch(
                r'/share/app/string_[^/]+_(?:horizontal|vertical)\.uxc', entry.path)
            if not wanted or not stat.S_ISREG(entry.mode):
                continue
            target = out / entry.path.lstrip('/')
            if not target.resolve().is_relative_to(out.resolve()):
                raise ValueError('Extraction escapes target directory')
            target.parent.mkdir(parents=True, exist_ok=True)
            data = entry.contents.read()
            with target.open('xb') as f:
                f.write(data)
            rows.append({'partition': 'nflasha15', 'path': entry.path,
                         'local_path': target.relative_to(ROOT).as_posix(),
                         'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    (ROOT / 'analysis/sound-port-menu-targets.json').write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'files': len(rows), 'bytes': sum(r['bytes'] for r in rows)}))


if __name__ == '__main__':
    main()
