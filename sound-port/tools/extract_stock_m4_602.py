"""Decode the downloaded donor and extract only CP and stock sound resources."""
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
import time
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'references/stock-a7m4-602'
sys.path.insert(0,str(ROOT/'references/fwtool-a7iv'))
from fwtool.sony import dat,fdat
from fwtool import archive
from fwtool.io import FilePart

REFERENCE_CP='1c34764fe413d4c0d720d629e323996498305fc29e5c53d2c52d0cca0c0d1504'


def decode_cbc(encrypted,decoder,header,out):
    """Same upstream CBC/block contract, batched without per-byte Python sums."""
    crypter=fdat._crypters[decoder]()
    if not isinstance(crypter,fdat.AesCbcCrypter):raise ValueError('Expected existing CBC firmware crypter')
    size=encrypted.size-0x110
    if size<=0 or size%1024:raise ValueError('CBC block extent mismatch')
    encrypted.seek(size);iv=encrypted.read(16)
    cipher=fdat.AES.new(crypter._key,fdat.AES.MODE_CBC,iv)
    blocks=size//1024;at=0;written=0
    def publish(raw,index):
        nonlocal written
        count=len(raw)//1024
        words=np.frombuffer(raw,dtype='<u2').reshape(count,512)
        checks=(words[:,1:].sum(axis=1,dtype=np.uint64)&0xffff)==words[:,0]
        sizes=words[:,1]&0x7fff;ends=(words[:,1]&0x8000)!=0
        expected=np.arange(index,index+count)==blocks-1
        if not checks.all() or not (sizes<=1020).all() or not np.array_equal(ends,expected):
            raise ValueError('Upstream CBC packed-block checksum/size/end flag contract failed')
        payload=np.frombuffer(raw,dtype='u1').reshape(count,1024)[:,4:]
        if (sizes==1020).all():
            b=payload.tobytes();out.write(b);written+=len(b)
        else:
            for row,n in zip(payload,sizes):
                b=row[:int(n)].tobytes();out.write(b);written+=len(b)
    encrypted.seek(0);first=encrypted.read(1024)
    first=crypter._cipher.decrypt(first[:512])+cipher.decrypt(first[512:])
    if first[4:516]!=header:raise ValueError('Batch decrypt does not match upstream header decryption')
    publish(first,0);at=1
    while at<blocks:
        count=min(8192,blocks-at)
        raw=encrypted.read(count*1024)
        if len(raw)!=count*1024:raise ValueError('Short encrypted FDAT')
        publish(cipher.decrypt(raw),at);at+=count
    return {'packed_blocks_checked':blocks,'decrypted_bytes':written,'implementation':'upstream AES/key contract with NumPy block-checksum batching'}


def main():
    started=time.monotonic();source=OUT/'BODYDATA.DAT';decoded=OUT/'firmware-decrypted.fdat'
    report={'schema':1,'source':str(source.relative_to(ROOT)),
            'source_page':'https://service.sony.com.cn/download/firm/00003010.html',
            'camera_io':False,'ap_extracted':False,'entire_filesystem_extracted':False}
    rows=[];inventory=[]
    try:
        with source.open('rb')as stream:
            container=dat.readDat(stream);report['outer_dat_crc']='PASS'
            decoder,plain=fdat.decryptFdat(container.firmwareData);headerbytes=plain.read(512)
            head=fdat.FdatHeader.unpack(io.BytesIO(headerbytes));info=fdat.readFdat(io.BytesIO(headerbytes))
            report.update(decoder=decoder,header_crc='PASS',version=info.version,model=hex(info.model),
                          region=hex(info.region),firmware_offset=head.firmwareOffset,firmware_size=head.firmwareSize)
            if info.version!='6.02':raise ValueError('Official donor is not version6.02')
            with decoded.open('xb')as output:report['decode']=decode_cbc(container.firmwareData,decoder,headerbytes,output)
        print(json.dumps({'decode':'complete','version':report['version'],**report['decode']}),flush=True)
        destination=OUT/'extracted'
        with decoded.open('rb')as stream:
            firmware=FilePart(stream,head.firmwareOffset,head.firmwareSize)
            for member in archive.readArchive(firmware):
                path=member.path.lstrip('/');partition=Path(path).name
                inventory.append({'path':path,'bytes':member.size})
                if path!=f'0700_part_image/dev/{partition}' or partition not in('nflasha8','nflasha15'):continue
                for entry in archive.readArchive(member.contents):
                    wanted=(partition=='nflasha8' and entry.path in('/cpapp-b.bin','/SysSound.bin')) or (
                        partition=='nflasha15' and entry.path.startswith('/share/avsystemsound/'))
                    if not wanted or not stat.S_ISREG(entry.mode):continue
                    target=destination/partition/entry.path.lstrip('/')
                    if not target.resolve().is_relative_to(destination.resolve()):raise ValueError('Output escapes donor directory')
                    data=entry.contents.read();target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb')as output:output.write(data)
                    rows.append({'partition':partition,'path':entry.path,'local_path':str(target.relative_to(ROOT)),
                                 'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                                 'head_hex':data[:32].hex(' ')})
        cp,=[r for r in rows if r['path']=='/cpapp-b.bin']
        report['cp']={**cp,'reference_input_sha256':REFERENCE_CP,'matches_reference_input':cp['sha256']==REFERENCE_CP,
                      'mapping':'raw file offset +0x108000 = CP VA'}
        rv=json.loads((ROOT/'analysis/sound-targets.json').read_text(encoding='utf8'))
        rv={(r['partition'],r['path']):r for r in rv}
        for row in rows:
            reference=rv.get((row['partition'],row['path']))
            if reference:row['rv_stock_comparison']={'sha256':reference['sha256'],'equal':row['sha256']==reference['sha256']}
        soundfolder=destination/'nflasha15/share/avsystemsound'
        pack=(soundfolder/'SysSound.bin').read_bytes();cppack=(destination/'nflasha8/SysSound.bin').read_bytes()
        sounds=[]
        for line in (soundfolder/'beeplist.txt').read_text(encoding='utf8').splitlines():
            if not line.startswith('BEEP_ID_'):continue
            fields=[s.strip()for s in line.split(',')]
            row={'name':fields[0],'beep_id':int(fields[1],16),'filename':fields[3],
                 'kind_id':int(fields[8],16),'memory_type':fields[2]}
            if fields[4]!='N/A' and fields[5]!='N/A':
                size,offset=int(fields[4],16),int(fields[5],16)
                data=(soundfolder/fields[3]).read_bytes()
                if len(data)!=size or pack[offset:offset+size]!=data:raise ValueError('M4 stock sound pack/beeplist boundary mismatch')
                row.update(bytes=size,pack_offset=offset,first_control=data[0],
                           control_values=sorted(set(data[::32])),pack_slice_equals_file=True)
            sounds.append(row)
        report.update(status='EXTRACTED',files=rows,update_members=inventory,
                      sound_catalog={'usr_cp_packs_equal':pack==cppack,'pack_bytes':len(pack),'resources':sounds},
                      equal_rv_sound_files=sum(r.get('rv_stock_comparison',{}).get('equal',False)for r in rows),
                      compared_rv_sound_files=sum('rv_stock_comparison'in r for r in rows),
                      seconds=round(time.monotonic()-started,2))
    except Exception as error:
        report.update(status='FAILED',error=f'{type(error).__name__}: {error}',files=rows,
                      seconds=round(time.monotonic()-started,2))
    (OUT/'extraction-manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items()if k not in('files','update_members','sound_catalog')},ensure_ascii=False),flush=True)
    if report['status']!='EXTRACTED':raise SystemExit(1)


if __name__=='__main__':main()
