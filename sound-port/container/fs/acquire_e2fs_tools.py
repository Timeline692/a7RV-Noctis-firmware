"""Fetch official Cygwin e2fsprogs into this workspace; no installer or scripts."""
import concurrent.futures
import hashlib
import io
import json
import lzma
from pathlib import Path
import tarfile
import requests
import zstandard

HERE = Path(__file__).resolve().parent
BASE = 'https://mirrors.kernel.org/sourceware/cygwin/'
PACKAGES = ['e2fsprogs', 'cygwin', 'libblkid1', 'libcom_err2', 'libe2p2',
            'libext2fs2', 'libintl8', 'libss2', 'libuuid1', 'libiconv2', 'libgcc1']


def get(url):
    response = requests.get(url, timeout=90)
    response.raise_for_status()
    return response.content


def main():
    cache = HERE / 'toolchain/packages'
    binaries = HERE / 'toolchain/bin'
    cache.mkdir(parents=True, exist_ok=True)
    binaries.mkdir(parents=True, exist_ok=True)
    index_path = cache / 'setup.xz'
    if not index_path.exists():
        index_path.write_bytes(get(BASE + 'x86_64/setup.xz'))
    sections = {}
    for section in lzma.decompress(index_path.read_bytes()).decode().split('\n@ ')[1:]:
        lines = section.splitlines()
        # The first install entry is the current stable version, before [prev].
        install = next((x[9:] for x in lines if x.startswith('install: ')), None)
        if install:
            sections[lines[0]] = install.split()

    def fetch(name):
        relative, size, expected = sections[name]
        target = cache / Path(relative).name
        data = target.read_bytes() if target.exists() else get(BASE + relative)
        assert len(data) == int(size) and hashlib.sha512(data).hexdigest() == expected, name
        if not target.exists():
            target.write_bytes(data)
        extracted = []
        tar_data = zstandard.ZstdDecompressor().decompress(data, max_output_size=128 << 20) if relative.endswith('.zst') else data
        with tarfile.open(fileobj=io.BytesIO(tar_data)) as archive:
            for member in archive:
                filename = Path(member.name).name
                if member.isfile() and (filename.endswith('.dll') or filename in {
                        'debugfs.exe', 'e2fsck.exe', 'resize2fs.exe', 'dumpe2fs.exe', 'tune2fs.exe'}):
                    payload = archive.extractfile(member).read()
                    (binaries / filename).write_bytes(payload)
                    extracted.append({'name': filename, 'sha256': hashlib.sha256(payload).hexdigest()})
        return {'package': name, 'url': BASE + relative, 'sha512_verified': expected, 'files': extracted}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(fetch, PACKAGES))
    report = {'source': 'official Cygwin distribution mirror', 'installer_executed': False,
              'package_scripts_executed': False, 'global_configuration_changed': False, 'packages': records}
    (HERE / 'toolchain/manifest.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({'packages': len(records), 'files': sum(len(r['files']) for r in records),
                      'bin': str(binaries)}, indent=2))


if __name__ == '__main__':
    main()
