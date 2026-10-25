"""Bounded read-only EXT2 view for the supplied RV image and its resized copy."""
import hashlib
import mmap
from pathlib import Path
import stat
import struct


class Ext2Image:
    def __init__(self, path):
        self.file = Path(path).open('rb')
        self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        s = self.data[1024:2048]
        assert s[56:58] == b'\x53\xef'
        self.block_size = 1024 << struct.unpack_from('<I', s, 24)[0]
        self.blocks = struct.unpack_from('<I', s, 4)[0]
        self.inodes_per_group = struct.unpack_from('<I', s, 40)[0]
        self.inode_size = struct.unpack_from('<H', s, 88)[0]
        assert self.block_size == 1024 and self.inode_size == 128
        assert struct.unpack_from('<I', s, 96)[0] == 2, 'Only original EXT2 filetype feature supported'
        assert self.blocks * self.block_size == len(self.data)
        groups = (self.blocks - 1) // struct.unpack_from('<I', s, 32)[0] + 1
        self.inode_tables = [struct.unpack_from('<I', self.data, 2048 + n * 32 + 8)[0] for n in range(groups)]
        self.pointer_cache = {}

    def close(self):
        self.data.close()
        self.file.close()

    def inode_offset(self, number):
        assert number > 0
        group, index = divmod(number - 1, self.inodes_per_group)
        return self.inode_tables[group] * self.block_size + index * self.inode_size

    def inode(self, number):
        at = self.inode_offset(number)
        return self.data[at:at + self.inode_size]

    def pointers(self, block):
        if block not in self.pointer_cache:
            assert 0 < block < self.blocks
            self.pointer_cache[block] = struct.unpack_from('<256I', self.data, block * self.block_size)
        return self.pointer_cache[block]

    def chunks(self, inode):
        mode, = struct.unpack_from('<H', inode)
        size, = struct.unpack_from('<I', inode, 4)
        if stat.S_ISLNK(mode) and size <= 60:
            yield inode[40:40 + size]
            return
        pointers = struct.unpack_from('<15I', inode, 40)
        def descend(block, level):
            if not level:
                yield block
            elif not block:
                yield from (0 for _ in range(256 ** level))
            else:
                for child in self.pointers(block):
                    yield from descend(child, level - 1)
        remaining = size
        for n, pointer in enumerate(pointers):
            for block in descend(pointer, max(0, n - 11)):
                if not remaining:
                    return
                amount = min(remaining, self.block_size)
                assert block < self.blocks
                yield self.data[block * self.block_size:block * self.block_size + amount] if block else bytes(amount)
                remaining -= amount
        assert remaining == 0, 'Truncated EXT2 block tree'

    def entries(self, number):
        inode = self.inode(number)
        content = b''.join(self.chunks(inode))
        at = 0
        result = []
        while at < len(content):
            child, length, namesize, kind = struct.unpack_from('<IHBB', content, at)
            assert length >= 8 and length % 4 == 0 and at + length <= len(content)
            assert namesize <= length - 8
            name = content[at + 8:at + 8 + namesize].decode('utf8')
            if child and name not in ('.', '..'):
                result.append((name, child))
            at += length
        return result

    def paths(self):
        result = {}
        def walk(number, path):
            assert path not in result
            inode = self.inode(number)
            result[path] = number
            if stat.S_ISDIR(struct.unpack_from('<H', inode)[0]):
                for name, child in self.entries(number):
                    assert '/' not in name
                    walk(child, path + '/' + name)
        walk(2, '')
        return result

    def inventory(self):
        result = {}
        for path, number in self.paths().items():
            inode = self.inode(number)
            mode, = struct.unpack_from('<H', inode)
            meta = bytearray(inode)
            regular = stat.S_ISREG(mode)
            if regular:
                # These describe content size/allocation; every other inode byte is metadata.
                for start, end in ((4, 8), (28, 32), (40, 100), (108, 112)):
                    meta[start:end] = bytes(end - start)
            digest = None
            if regular or stat.S_ISLNK(mode):
                h = hashlib.sha256()
                for chunk in self.chunks(inode):
                    h.update(chunk)
                digest = h.hexdigest()
            acl, = struct.unpack_from('<I', inode, 104)
            result[path] = {'inode': number, 'mode': mode, 'uid': struct.unpack_from('<H', inode, 2)[0],
                            'gid': struct.unpack_from('<H', inode, 24)[0],
                            'size': struct.unpack_from('<I', inode, 4)[0], 'sha256': digest,
                            'inode_metadata_hex': meta.hex(),
                            'acl_sha256': hashlib.sha256(self.data[acl * 1024:(acl + 1) * 1024]).hexdigest() if acl else None}
        return result
