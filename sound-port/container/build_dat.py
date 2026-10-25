"""Assemble and self-sign a complete RV 4.00-based custom update container.

This is a file builder. The stock receiver does not trust this signing key.
No device, USB, driver or receiver modification is performed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import struct
import tarfile
import zlib
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT=Path(__file__).resolve().parents[2]
SOURCE_SHA='51e1176a255a9a4b4782dfbcfa6c5f332b71173bdfe9ed2bcf4fca6bcbc6c2e2'
MODEL=0x11030080
KEY_HEADER=bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb924')
KEY_K8=bytes.fromhex('434589432d319010f1132727353286ce4d7ede8b9c4f7217a0e0226e0f0edc69')
BLOCK=4<<20

def require(value,message):
    if not value:raise ValueError(message)

def exact(stream,count):
    value=stream.read(count)
    require(len(value)==count,'Truncated input')
    return value

def sha_file(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(BLOCK),b''):h.update(b)
    return h.hexdigest()

def transfer(src,dst,count,*,digest=False,prefix=None):
    crc=0;h=hashlib.sha256();left=count
    if prefix is not None:
        require(len(prefix)<=left,'Replacement prefix exceeds member')
        src.seek(len(prefix),1);dst.write(prefix);crc=zlib.crc32(prefix,crc);h.update(prefix);left-=len(prefix)
    while left:
        b=exact(src,min(BLOCK,left));dst.write(b);crc=zlib.crc32(b,crc);h.update(b);left-=len(b)
    return {'bytes':count,'crc32':f'{crc&0xffffffff:08x}','sha256':h.hexdigest()} if digest else None

def ufutemplate(path):
    total=Path(path).stat().st_size;chunks=[]
    with Path(path).open('rb') as f:
        require(exact(f,8)==b'\x89UFU\r\n\x1a\n','Expected Sony UFU')
        pos=8
        while pos<total:
            f.seek(pos);size,kind=struct.unpack('>I4s',exact(f,8))
            require(pos+8+size<=total,'UFU chunk exceeds input')
            chunks.append((kind,pos+8,size));pos+=8+size
        require(pos==total and chunks[-1][0]==b'DEND' and chunks[-1][2]==4,'UFU final layout')
        require(chunks[-2][0]==b'FDAT' and sum(x[0]==b'FDAT' for x in chunks)==1,'Ambiguous FDAT')
        _,start,size=chunks[-2]
        require((size-272)%1024==0,'Original FDAT framing')
        f.seek(0);prefix=exact(f,start)
        f.seek(start+size-272);iv=exact(f,16)
    return prefix,iv,chunks

def sum_edit(data,changes):
    result=[];seen=set()
    for line in data.decode('ascii').splitlines(keepends=True):
        fields=line.split(',')
        if len(fields)>10 and fields[0]=='0' and fields[10] in changes:
            name=fields[10];item=changes[name]
            require(name not in seen and int(fields[2],16)==item['old_bytes'],'Checksum member identity differs')
            require(len(fields[1])==len(fields[2])==8,'Unexpected checksum widths')
            fields[1]=item['crc32'];fields[2]=f"{item['bytes']:08x}"
            line=','.join(fields);seen.add(name)
        result.append(line)
    require(seen==set(changes),'Missing partition checksum records')
    return ''.join(result).encode('ascii')

def tar_header(header,size):
    value=bytearray(header)
    require(len(value)==512 and int(value[148:156].strip(b'\0 ') or b'0',8)==sum(value[:148])+8*32+sum(value[156:]),'Original TAR header checksum')
    require(0<=size<8**11,'TAR member is too large')
    value[124:136]=f'{size:011o}\0'.encode('ascii');value[148:156]=b' '*8
    value[148:156]=f'{sum(value):06o}\0 '.encode('ascii')
    return value

def assemble_plain(source,images,target,version,*,cold_header_bytes):
    source=Path(source);require(not target.exists(),'Plaintext output exists')
    changes={};seen=set();member_report=[]
    with source.open('rb') as f:
        header=bytearray(exact(f,512))
        require(header[:8]==b'UDTRFIRM' and zlib.crc32(header[12:])==struct.unpack_from('<I',header,8)[0],'Original FDAT header')
        require(struct.unpack_from('<I',header,0x24)[0]==MODEL,'Wrong camera model')
        offset,length=struct.unpack_from('<II',header,48)
        require(offset+length==source.stat().st_size,'Unexpected plaintext tail')
        f.seek(offset)
        with tarfile.open(fileobj=f,mode='r:') as archive:members=list(archive)
        require(len({m.name for m in members})==len(members),'Duplicate TAR member')
        require(set(images)<=set(m.name for m in members),'Replacement image is absent')
        with target.open('xb+') as out:
            f.seek(0);transfer(f,out,offset)
            cursor=offset
            for m in members:
                require(not m.name.startswith('/') and '..' not in Path(m.name).parts,'Unsafe member path')
                base=m.offset_data-512;require(base>=cursor,'Overlapping TAR records')
                f.seek(cursor);transfer(f,out,base-cursor)
                h=exact(f,512);new_size=m.size;payload=None;prefix=None;image=images.get(m.name)
                if image:
                    require(m.isfile() and 'size' not in m.pax_headers,'Unsupported image member metadata')
                    new_size=image['path'].stat().st_size
                elif m.name=='0700_part_image/dev/nflasha5':
                    require(m.isfile() and m.size>=cold_header_bytes,'Invalid WBI member')
                    f.seek(m.offset_data);require(exact(f,4)==b'WBI2','Unexpected original WBI marker')
                    prefix=bytes(cold_header_bytes)
                elif m.name=='0701_part_image_sum/part_image.sum':
                    f.seek(m.offset_data);payload=sum_edit(exact(f,m.size),changes);new_size=len(payload)
                changed=image is not None or prefix is not None or payload is not None
                out.write(tar_header(h,new_size) if changed else h)
                start=out.tell()
                if image:
                    with image['path'].open('rb') as replacement:info=transfer(replacement,out,new_size,digest=True)
                    require(info['sha256']==image['sha256'],'Replacement image differs from its build manifest')
                    seen.add(m.name)
                elif payload is not None:
                    out.write(payload);info={'bytes':new_size,'crc32':f'{zlib.crc32(payload):08x}','sha256':hashlib.sha256(payload).hexdigest()}
                else:
                    f.seek(m.offset_data);info=transfer(f,out,m.size,digest=changed,prefix=prefix)
                if changed:
                    if m.name.startswith('0700_part_image/'):
                        changes[m.name.removeprefix('0700_part_image/')]=dict(info,old_bytes=m.size)
                    out.write(bytes((-new_size)%512))
                    member_report.append({'name':m.name,'old_bytes':m.size,'new_bytes':new_size,'new_plain_offset':start,**info})
                else:
                    f.seek(m.offset_data+m.size);transfer(f,out,(-m.size)%512)
                cursor=m.offset_data+((m.size+511)//512)*512
            f.seek(cursor);transfer(f,out,offset+length-cursor)
            require(seen==set(images),'Not every replacement was written')
            end=out.tell();major,minor=map(int,version.split('.'))
            require(major<=9 and 0<=minor<=99,'Version must be X.YY')
            header[0x20:0x22]=bytes([((minor//10)<<4)|(minor%10),major])
            struct.pack_into('<I',header,52,end-offset)
            struct.pack_into('<I',header,8,zlib.crc32(header[12:]))
            out.seek(0);out.write(header)
    return {'bytes':end,'firmware_offset':offset,'firmware_bytes':end-offset,'changed_members':member_report,
            'version':version,'model':hex(MODEL),'updater_body_unchanged':True,'p1_updated':False,
            'cold_boot_invalidation':{'member':'0700_part_image/dev/nflasha5','zero_prefix_bytes':cold_header_bytes,'remainder_preserved':True}}

def encode_signed(prefix,iv,plain,plain_size,key,out):
    count=(plain_size+1019)//1020;encrypted_size=count*1024
    prefix=bytearray(prefix);struct.pack_into('>I',prefix,len(prefix)-8,encrypted_size+272)
    out.write(prefix);crc=zlib.crc32(prefix);signed=hashlib.sha256();plain_hash=hashlib.sha256()
    ecb=Cipher(algorithms.AES(KEY_HEADER),modes.ECB()).encryptor()
    cbc=Cipher(algorithms.AES(KEY_K8),modes.CBC(iv)).encryptor()
    for base in range(0,count,4096):
        n=min(4096,count-base);payload=exact(plain,min(n*1020,plain_size-base*1020));plain_hash.update(payload)
        a=np.full((n,1024),255,dtype=np.uint8);words=a.view('<u2').reshape(n,512)
        words[:,1]=1020;complete=len(payload)//1020;partial=len(payload)%1020
        if complete:a[:complete,4:]=np.frombuffer(payload[:complete*1020],dtype=np.uint8).reshape(complete,1020)
        if partial:a[-1,4:4+partial]=np.frombuffer(payload[-partial:],dtype=np.uint8);words[-1,1]=partial
        if base+n==count:words[-1,1]|=0x8000
        words[:,0]=words[:,1:].sum(axis=1,dtype=np.uint64)&0xffff
        raw=a.tobytes();cipher=ecb.update(raw[:512])+cbc.update(raw[512:]) if base==0 else cbc.update(raw)
        out.write(cipher);crc=zlib.crc32(cipher,crc);signed.update(cipher)
    require(not plain.read(1) and not ecb.finalize() and not cbc.finalize(),'Cipher/plaintext tail')
    out.write(iv);crc=zlib.crc32(iv,crc);signed.update(iv)
    signature=key.sign(signed.digest(),padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
    require(len(signature)==256,'Expected RSA2048 signature')
    key.public_key().verify(signature,signed.digest(),padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
    out.write(signature);crc=zlib.crc32(signature,crc);out.write(struct.pack('>I4sI',4,b'DEND',crc))
    return {'plaintext_sha256':plain_hash.hexdigest(),'plaintext_bytes':plain_size,'blocks':count,
            'encrypted_bytes':encrypted_size,'signed_range':[len(prefix),len(prefix)+encrypted_size+16],
            'rsa_bits':2048,'rsa_pkcs1_sha256_self_verified':True,'dend_crc32':f'{crc:08x}'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original',type=Path,default=Path('inputs/BODYDATA.DAT'))
    p.add_argument('--plain',type=Path,default=ROOT/'analysis/firmware-decrypted.fdat')
    p.add_argument('--images',type=Path,default=ROOT/'analysis/dat-fs-build.json')
    p.add_argument('--private-key',type=Path,default=ROOT/'sound-port/container/keys/RV-SoundMenu-private.pem')
    p.add_argument('--public-key',type=Path,default=ROOT/'sound-port/container/keys/RV-SoundMenu-public.pem')
    p.add_argument('--version',default='4.01')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();require(not args.output.exists(),'Choose a new output directory')
    require(sha_file(args.original)==SOURCE_SHA,'Exact original RV4.00 DAT required')
    key=serialization.load_pem_private_key(args.private_key.read_bytes(),None)
    public=serialization.load_pem_public_key(args.public_key.read_bytes())
    require(key.key_size==2048 and key.public_key().public_numbers()==public.public_numbers(),'Signing identity mismatch')
    manifest=json.loads(args.images.read_text(encoding='utf8'));images={}
    for item in manifest['images']:
        part='nflasha15' if item['filesystem']=='EXT2' else 'nflasha8'
        images['0700_part_image/dev/'+part]={'path':ROOT/item['output_image'],'sha256':item['output_sha256']}
    require(set(images)=={'0700_part_image/dev/nflasha15','0700_part_image/dev/nflasha8'},'Expected exactly two replacement partitions')
    args.output.mkdir(parents=True);work=args.output/'work';work.mkdir()
    plain=work/'firmware.custom.fdat'
    assembly=assemble_plain(args.plain,images,plain,args.version,cold_header_bytes=512)
    prefix,iv,chunks=ufutemplate(args.original)
    output=args.output/'BODYDATA.DAT'
    with plain.open('rb') as src,output.open('xb') as dst:encoding=encode_signed(prefix,iv,src,plain.stat().st_size,key,dst)
    shutil.copyfile(args.public_key,args.output/'RV-SoundMenu-public.pem')
    der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    report={'schema':1,'status':'COMPLETE_CUSTOM_SIGNED_DAT_PENDING_INDEPENDENT_VERIFY',
            'source_sha256':SOURCE_SHA,'output_sha256':sha_file(output),'output_bytes':output.stat().st_size,
            'custom_version':args.version,'official_version_claimed':False,'assembly':assembly,'encoding':encoding,
            'signing_key_fingerprint':hashlib.sha256(der).hexdigest(),'sony_official_signature':False,
            'receiver_requirement':'Existing RV updater must be prepared to trust this public key',
            'stock_4_00_direct_install_supported':False,'camera_io':False,'hardware_tested':False}
    (args.output/'build-manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({'output':str(output),'bytes':report['output_bytes'],'sha256':report['output_sha256'],
                      'status':report['status']},ensure_ascii=False))

if __name__=='__main__':main()
