"""Rebuild RV AP EXT2 and CP FAT12 images without touching the input DAT."""
import hashlib
import json
import math
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

from ext2_image import Ext2Image

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'references/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat

BIN = HERE / 'toolchain/bin'
AP = ROOT / 'sound-port/build/components/appFw.offline.so'
CP = ROOT / 'sound-port/build/components/reference-codec-experimental/cpapp-b.offline.bin'
RESOURCES = ROOT / 'sound-port/menu/resources'
ANALYSIS = ROOT / 'analysis'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(path):
    return Path(path).relative_to(ROOT).as_posix()


def tool(name, arguments, logname, allowed=(0,)):
    result = subprocess.run([str(BIN / (name + '.exe')), *map(str, arguments)], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW, timeout=180)
    (HERE / logname).write_bytes(result.stdout)
    assert result.returncode in allowed, result.stdout.decode('utf8', 'replace')[-5000:]
    return result.returncode


def rebuild_ap():
    source = HERE / 'nflasha15.original.img'
    output = HERE / 'nflasha15.sound.ext2.img'
    assert not output.exists(), 'Choose a new output; original is never overwritten'
    fs = Ext2Image(source)
    before = fs.inventory()
    replacements = {'/lib/appFw.so': AP}
    resource_manifest = json.loads((ROOT / 'sound-port/menu/resource-manifest.json').read_text('utf8'))
    for row in resource_manifest['files']:
        path = '/' + row['path']
        replacement = RESOURCES / row['path']
        assert before[path]['sha256'] == row['source_sha256']
        assert sha(replacement) == row['output_sha256']
        replacements[path] = replacement
    assert len(replacements) == 69
    originals = {path: fs.inode(before[path]['inode']) for path in replacements}
    expected = {path: sha(value) for path, value in replacements.items()}
    for inode in originals.values():
        assert struct.unpack_from('<H', inode, 26)[0] == 1, 'Replacement has hard links'
    root_inode = fs.inode(2)
    fs.close()
    shutil.copyfile(source, output)
    # Source filesystem is clean; a read-only forced check precedes the bounded resize.
    tool('e2fsck', ['-f', '-n', relative(output)], 'ext2-source-check.log')
    new_size = source.stat().st_size + (16 << 20)
    assert new_size <= 749731840
    tool('resize2fs', ['-f', relative(output), str(new_size // 1024)], 'ext2-resize.log')
    assert output.stat().st_size == new_size
    directory = '/.__csnd_transfer'
    # This Cygwin debugfs write command uses a basename in its current EXT directory.
    commands = [f'mkdir {directory}', f'cd {directory}']
    for index, (path, replacement) in enumerate(replacements.items()):
        commands += [f'punch {path} 0 4294967295', f'write {relative(replacement)} f{index:03d}']
    script = HERE / 'ext2-allocate.commands'
    script.write_text('\n'.join(commands) + '\n', encoding='ascii')
    tool('debugfs', ['-w', '-f', relative(script), relative(output)], 'ext2-allocate.log')
    fs = Ext2Image(output)
    paths = fs.paths()
    transfers = []
    for index, path in enumerate(replacements):
        destination = before[path]['inode']
        temporary = paths[f'{directory}/f{index:03d}']
        new_inode = fs.inode(temporary)
        original = bytearray(originals[path])
        # Move only size and allocation pointers into the original inode.
        for start, end in ((4, 8), (28, 32), (40, 100), (108, 112)):
            original[start:end] = new_inode[start:end]
        empty = bytearray(new_inode)
        for start, end in ((4, 8), (28, 32), (40, 100), (108, 112)):
            empty[start:end] = bytes(end - start)
        transfers += [(fs.inode_offset(destination), original), (fs.inode_offset(temporary), empty)]
    # A single temporary root entry must not cause a root block allocation.
    assert fs.inode(2)[4:8] == root_inode[4:8] and fs.inode(2)[28:100] == root_inode[28:100]
    root_offset = fs.inode_offset(2)
    fs.close()
    with output.open('r+b') as stream:
        for offset, inode in transfers:
            stream.seek(offset)
            stream.write(inode)
    commands = [f'cd {directory}'] + [f'rm f{n:03d}' for n in range(len(replacements))] + ['cd /', f'rmdir {directory}']
    script = HERE / 'ext2-cleanup.commands'
    script.write_text('\n'.join(commands) + '\n', encoding='ascii')
    tool('debugfs', ['-w', '-f', relative(script), relative(output)], 'ext2-cleanup.log')
    with output.open('r+b') as stream:
        stream.seek(root_offset)
        stream.write(root_inode)
    tool('e2fsck', ['-f', '-n', relative(output)], 'ext2-final-check.log')
    fs = Ext2Image(output)
    after = fs.inventory()
    fs.close()
    assert before.keys() == after.keys(), 'Filesystem paths changed'
    changed = []
    for path, old in before.items():
        new = after[path]
        assert all(old[field] == new[field] for field in ('inode', 'mode', 'uid', 'gid', 'inode_metadata_hex', 'acl_sha256')), path
        if path in replacements:
            assert new['sha256'] == expected[path] and new['size'] == replacements[path].stat().st_size, path
            changed.append({'path': path, 'source_bytes': old['size'], 'output_bytes': new['size'],
                            'source_sha256': old['sha256'], 'output_sha256': new['sha256'], 'inode': old['inode']})
        else:
            assert old == new, 'Unexpected content or metadata change: ' + path
    report = {'filesystem': 'EXT2', 'source_image': relative(source), 'output_image': relative(output),
              'source_bytes': source.stat().st_size, 'output_bytes': output.stat().st_size,
              'source_sha256': sha(source), 'output_sha256': sha(output), 'partition_capacity': 749731840,
              'paths': len(before), 'replaced_files': len(changed), 'changes': changed,
              'all_original_inodes_and_metadata_preserved': True, 'all_other_file_contents_preserved': True,
              'e2fsck_source_readonly': 'PASS', 'e2fsck_final_readonly': 'PASS'}
    (ANALYSIS / 'dat-fs-ext2-inventory-before.json').write_text(json.dumps(before, indent=2), encoding='utf8')
    (ANALYSIS / 'dat-fs-ext2-inventory-after.json').write_text(json.dumps(after, indent=2), encoding='utf8')
    (ANALYSIS / 'dat-fs-ext2.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    return report


def fat_inventory(fs):
    result = {}
    def walk(first, prefix):
        for name, (entry, cluster, size, attr) in fs.entries(first).items():
            if name in ('.', '..'):
                continue
            path = prefix + '/' + name
            raw = bytes(fs.data[entry:entry + 32])
            result[path] = {'size': size, 'attr': attr, 'directory_entry_hex': raw.hex(),
                            'sha256': hashlib.sha256(fs.read(path)).hexdigest() if not attr & 16 else None}
            if attr & 16:
                walk(cluster, path)
    walk(None, '')
    return result


def rebuild_cp():
    source = HERE / 'nflasha8.original.img'
    output = HERE / 'nflasha8.sound.fat.img'
    assert not output.exists()
    original = source.read_bytes()
    old = Fat(original)
    assert old.bits == 12
    before = fat_inventory(old)
    data = bytearray(original)
    new_size = 40 << 20
    assert new_size < 67108864
    data.extend(bytes(new_size - len(data)))
    struct.pack_into('<H', data, 19, 0)
    struct.pack_into('<I', data, 32, new_size // old.bps)
    fs = Fat(data)
    assert fs.bits == 12 and fs.cluster_count < 4085
    entry, first, _, _ = fs.locate('CPAPP-B.BIN')
    chain = fs.chain(first)
    payload = CP.read_bytes()
    needed = math.ceil(len(payload) / fs.cluster_size)
    def get(cluster):
        word = struct.unpack_from('<H', fs.data, fs.fat_start + cluster * 3 // 2)[0]
        return (word >> 4 if cluster & 1 else word) & 0xfff
    def put(cluster, value):
        for copy in range(fs.nfat):
            offset = fs.fat_start + copy * fs.fat_size + cluster * 3 // 2
            word, = struct.unpack_from('<H', fs.data, offset)
            word = (word & 0x000f) | (value << 4) if cluster & 1 else (word & 0xf000) | value
            struct.pack_into('<H', fs.data, offset, word)
    additional = [c for c in range(2, fs.cluster_count + 2) if get(c) == 0][:max(0, needed - len(chain))]
    assert len(chain) + len(additional) >= needed, 'FAT12 capacity exceeded'
    if additional:
        put(chain[-1], additional[0])
        for n, cluster in enumerate(additional):
            put(cluster, additional[n + 1] if n + 1 < len(additional) else 0xfff)
        chain += additional
    for n, cluster in enumerate(chain):
        chunk = payload[n * fs.cluster_size:(n + 1) * fs.cluster_size]
        if chunk:
            at = fs.offset(cluster)
            fs.data[at:at + len(chunk)] = chunk
    struct.pack_into('<I', fs.data, entry + 28, len(payload))
    with output.open('xb') as stream:
        stream.write(fs.bytes())
    reopened = Fat(output.read_bytes())
    after = fat_inventory(reopened)
    assert before.keys() == after.keys()
    for path, original_row in before.items():
        if path == '/CPAPP-B.BIN':
            assert bytes.fromhex(original_row['directory_entry_hex'])[:28] == bytes.fromhex(after[path]['directory_entry_hex'])[:28]
            assert after[path]['sha256'] == hashlib.sha256(payload).hexdigest()
        else:
            assert original_row == after[path], 'Unexpected FAT file/metadata change: ' + path
    report = {'filesystem': 'FAT12', 'source_image': relative(source), 'output_image': relative(output),
              'source_bytes': len(original), 'output_bytes': new_size, 'source_sha256': sha(source),
              'output_sha256': sha(output), 'partition_capacity': 67108864, 'cluster_size': fs.cluster_size,
              'cluster_count': fs.cluster_count, 'fat_copies': fs.nfat, 'files_and_directories': len(before),
              'existing_layout_preserved': True, 'fat_copies_and_ownership_verified': True,
              'all_other_files_and_directory_metadata_preserved': True, 'cp': {'component': relative(CP),
              'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
              'allocated_clusters': len(chain), 'appended_clusters': len(additional)}, 'before': before, 'after': after}
    (ANALYSIS / 'dat-fs-fat.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    return report


def main():
    start = time.monotonic()
    cp_report = ANALYSIS / 'dat-fs-fat.json'
    cp = json.loads(cp_report.read_text('utf8')) if cp_report.exists() else rebuild_cp()
    assert cp['cp']['sha256'] == sha(CP), 'Existing CP image uses a different component'
    ap = rebuild_ap()
    report = {'status': 'OFFLINE_FILESYSTEM_IMAGES_REBUILT', 'camera_io': False, 'hardware_tested': False,
              'source_plaintext_reused': 'analysis/firmware-decrypted.fdat', 'originals_overwritten': False,
              'ap_report': 'analysis/dat-fs-ext2.json', 'cp_report': 'analysis/dat-fs-fat.json',
              'images': [{key: row[key] for key in ('filesystem', 'output_image', 'output_bytes', 'output_sha256')}
                         for row in (ap, cp)], 'seconds': round(time.monotonic() - start, 3)}
    (ANALYSIS / 'dat-fs-build.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
