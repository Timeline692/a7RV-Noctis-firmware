"""Read Sony update metadata; use the reviewed upstream decoder for its header."""
import json
import io
import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'references/fwtool-a7iv'))
from fwtool.sony import dat, fdat

source = Path(sys.argv[1])
report = {'source': str(source), 'size': source.stat().st_size, 'chunks': []}
with source.open('rb') as stream:
    assert stream.read(8) == dat.datHeaderMagic
    offset = 8
    while offset < report['size']:
        stream.seek(offset)
        size, kind = struct.unpack('>I4s', stream.read(8))
        assert offset + 8 + size <= report['size'], 'chunk exceeds file'
        report['chunks'].append({'type': kind.decode('ascii'), 'header_offset': offset,
                                 'data_offset': offset + 8, 'size': size})
        offset += 8 + size
        if kind == b'DEND':
            break
    assert offset == report['size'], 'unparsed trailer'
    container = dat.readDat(stream)
    report['outer_crc'] = 'PASS'
    report['usb_normal'] = [[hex(v), hex(p)] for v, p in container.normalUsbDescriptors]
    report['usb_updater'] = [[hex(v), hex(p)] for v, p in container.updaterUsbDescriptors]
    try:
        decoder, plain = fdat.decryptFdat(container.firmwareData)
        report['decoder'] = decoder
        header_bytes = plain.read(512)
        header_stream = io.BytesIO(header_bytes)
        header = fdat.FdatHeader.unpack(header_stream)
        contents = fdat.readFdat(header_stream)
        report['decoder'] = decoder
        report['header_crc'] = 'PASS'
        report['model'] = hex(contents.model)
        report['region'] = hex(contents.region)
        report['version'] = contents.version
        report['firmware_offset'] = header.firmwareOffset
        report['firmware_size'] = header.firmwareSize
        report['filesystems'] = []
        for i in range(header.numFileSystems):
            fs = fdat.FdatFileSystemHeader.unpack(header.fileSystemHeaders, i * 16)
            report['filesystems'].append({'mode': fs.modeType.decode('ascii'),
                                         'offset': fs.offset, 'size': fs.size})
        (ROOT / 'analysis/fdat-header.bin').write_bytes(header_bytes)
        if '--decode' in sys.argv[2:]:
            target = ROOT / 'analysis/firmware-decrypted.fdat'
            with target.open('xb') as dst:
                dst.write(header_bytes)
                shutil.copyfileobj(plain, dst)
            report['decoded_path'] = str(target)
            report['decoded_size'] = target.stat().st_size
    except Exception as exc:
        report['decoder_error'] = f'{type(exc).__name__}: {exc}'
out = ROOT / 'analysis/firmware-probe.json'
out.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
