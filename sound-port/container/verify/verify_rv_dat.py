"""Independent RV DAT readback: no import or call into any package encoder.

Uses struct checksums, standard AES/RSA primitives, stdlib TAR, and separate
read-only FAT/EXT2 parsers. A PASS describes file contracts, not a flashed body.
"""
from __future__ import annotations
import argparse,hashlib,io,json,struct,tarfile,time,zlib
from pathlib import Path,PurePosixPath
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding,utils
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from fs_readers import Region,FatAudit,Ext2Read,need

ROOT=Path(__file__).resolve().parents[3]
KEY_ECB=bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb924')
KEY_CBC=bytes.fromhex('434589432d319010f1132727353286ce4d7ede8b9c4f7217a0e0226e0f0edc69')
U16_BLOCK=struct.Struct('<511H')

def exact(stream,size):
 data=stream.read(size);need(len(data)==size,'Unexpected EOF');return data
def digest(chunks,kind='sha256'):
 h=hashlib.new(kind)
 for chunk in chunks:h.update(chunk)
 return h.hexdigest()
def file_hash(path):
 with Path(path).open('rb')as f:return digest(iter(lambda:f.read(4<<20),b''))
def crc(region):
 value=0
 for chunk in region.chunks():value=zlib.crc32(chunk,value)
 return value&0xffffffff
def ufu(stream):
 stream.seek(0,2);total=stream.tell();stream.seek(0);need(exact(stream,8)==b'\x89UFU\r\n\x1a\n','UFU magic')
 rows=[];tags=set()
 while stream.tell()<total:
  header=stream.tell();size,tag=struct.unpack('>I4s',exact(stream,8));offset=stream.tell()
  need(tag not in tags and offset+size<=total,'Duplicate/out-of-bounds UFU chunk');tags.add(tag);rows.append((tag,offset,size,header));stream.seek(size,1)
 need(stream.tell()==total and [r[0]for r in rows]==[b'DATV',b'PROV',b'UDID',b'FDAT',b'DEND'],'Unexpected RV UFU layout')
 need(rows[-1][2]==4,'DEND size');return rows
def identity(stream,rows):
 by={r[0]:r for r in rows}
 def read(tag):_,offset,size,_=by[tag];stream.seek(offset);return exact(stream,size)
 datv,prov,udid=read(b'DATV'),read(b'PROV'),read(b'UDID')
 need(datv==b'\x01\x00\x00\x00' and prov==b'\x01\x00\x00\x00','RV DATV/PROV identity')
 count=struct.unpack_from('>I',udid)[0];need(len(udid)==4+8*count and 0<count<=128,'UDID count')
 descriptors=[]
 for index in range(count):
  pid,vid,mode,reserved=struct.unpack_from('>HHB3s',udid,4+index*8)
  need(mode in (1,2)and reserved==bytes(3),'UDID mode/reserved');descriptors.append({'vid':hex(vid),'pid':hex(pid),'mode':mode})
 need(len({(d['vid'],d['pid'],d['mode'])for d in descriptors})==count,'Duplicate USB descriptor')
 return {'DATV':datv.hex(),'PROV':prov.hex(),'UDID':udid.hex(),'USB':descriptors}

def decode_compare(dat,plain,public_key,original_dat):
 started=time.monotonic();public=serialization.load_pem_public_key(Path(public_key).read_bytes())
 need(isinstance(public,rsa.RSAPublicKey)and public.key_size==2048 and public.public_numbers().e==65537,'RSA2048 e65537 key')
 with Path(dat).open('rb')as source,Path(plain).open('rb')as target,Path(original_dat).open('rb')as original:
  chunks=ufu(source);ident=identity(source,chunks);original_ident=identity(original,ufu(original));need(ident==original_ident,'UDID/USB identity differs from original RV DAT')
  _,start,size,_=chunks[-2];_,dend_data,_,dend_header=chunks[-1]
  computed=crc(Region(source,0,dend_header));source.seek(dend_data);need(struct.unpack('>I',exact(source,4))[0]==computed,'Outer DEND CRC mismatch')
  encrypted=size-272;need(encrypted>0 and encrypted%1024==0,'FDAT 1024-byte framing')
  signed=bytes.fromhex(digest(Region(source,start,size-256).chunks()));source.seek(start+size-256)
  public.verify(exact(source,256),signed,padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
  source.seek(start+encrypted);iv=exact(source,16)
  ecb=Cipher(algorithms.AES(KEY_ECB),modes.ECB()).decryptor();cbc=Cipher(algorithms.AES(KEY_CBC),modes.CBC(iv)).decryptor()
  source.seek(start);blocks=encrypted//1024;index=0;h=hashlib.sha256();plain_bytes=0;first=bytearray()
  while index<blocks:
   number=min(2048,blocks-index);cipher=exact(source,number*1024)
   raw=ecb.update(cipher[:512])+cbc.update(cipher[512:])if index==0 else cbc.update(cipher)
   payload=bytearray()
   for local in range(number):
    block=raw[local*1024:(local+1)*1024];checksum,flags=struct.unpack_from('<HH',block);length=flags&0x7fff;last=index+local==blocks-1
    need(0<length<=1020 and bool(flags&0x8000)==last and(last or length==1020),f'Packed frame flags at {index+local}')
    need(sum(U16_BLOCK.unpack_from(block,2))&65535==checksum,f'Packed checksum at {index+local}')
    payload.extend(block[4:4+length])
   need(exact(target,len(payload))==payload,f'CBC/ECB decoded plaintext differs near frame {index}')
   if len(first)<512:first.extend(payload[:512-len(first)])
   h.update(payload);plain_bytes+=len(payload);index+=number
   if index%65536==0:print(f'Independent decode {index}/{blocks} frames',flush=True)
  need(not target.read(1),'Reference plaintext has extra data');need(ecb.finalize()==cbc.finalize()==b'','Cipher tail')
  return {'blocks_verified':blocks,'plaintext_bytes':plain_bytes,'plaintext_sha256':h.hexdigest(),'compared_every_plaintext_byte':True,
   'dend_crc_verified':True,'rsa_signature_verified_with_supplied_self_signing_key':True,'signing_public_key_sha256':hashlib.sha256(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
   'UDID_preserved':True,'identity':ident,'seconds':round(time.monotonic()-started,2),'header':bytes(first)}

class Slice(io.RawIOBase):
 def __init__(self,region):self.region,self.position=region,0
 def readable(self):return True
 def seekable(self):return True
 def tell(self):return self.position
 def seek(self,offset,whence=0):
  self.position=offset if whence==0 else self.position+offset if whence==1 else self.region.size+offset
  need(0<=self.position<=self.region.size,'Slice seek outside TAR');return self.position
 def read(self,size=-1):
  size=self.region.size-self.position if size<0 else min(size,self.region.size-self.position)
  result=self.region.read(self.position,size);self.position+=len(result);return result

def firmware_header(stream,size,model,version=None):
 stream.seek(0);h=exact(stream,512);need(h[:8]==b'UDTRFIRM' and h[12:16]==b'0100','FDAT plaintext header identity')
 need(struct.unpack_from('<I',h,8)[0]==zlib.crc32(h[12:]),'FDAT header CRC')
 need(struct.unpack_from('<I',h,0x24)[0]==model,'RV model mismatch')
 def bcd(x):need(x&15<=9 and x>>4<=9,'Invalid BCD version');return (x>>4)*10+(x&15)
 actual=f'{bcd(h[0x21])}.{bcd(h[0x20]):02d}';need(version is None or actual==version,'Unexpected custom version')
 offset,length,count=struct.unpack_from('<III',h,48);need(offset>=512 and offset+length<=size and count<=28,'Header firmware bounds')
 filesystems=[]
 for index in range(count):
  mode,at,n,res=struct.unpack_from('<4sIII',h,64+16*index);need(at+n<=size,'Embedded filesystem bounds')
  filesystems.append({'mode':mode.rstrip(b'\0').decode('ascii'),'offset':at,'bytes':n,'reserved':res})
 return {'model':hex(model),'region':hex(struct.unpack_from('<I',h,0x28)[0]),'version':actual,'header_crc_verified':True,'firmware_offset':offset,'firmware_bytes':length,'filesystems':filesystems}
def clean(name):
 name=name.removeprefix('./').rstrip('/');p=PurePosixPath(name)
 need(name and not p.is_absolute()and'..'not in p.parts and'\\'not in name and'\0'not in name,'Unsafe TAR name');return name
def index_tar(stream,header):
 region=Region(stream,header['firmware_offset'],header['firmware_bytes']);members={}
 with tarfile.open(fileobj=Slice(region),mode='r:')as archive:
  for member in archive:
   name=clean(member.name);need(name not in members,'Duplicate TAR member '+name)
   need(member.offset_data+member.size<=region.size,'TAR member outside declared firmware')
   members[name]={'offset':header['firmware_offset']+member.offset_data,'bytes':member.size,'regular':member.isfile(),'type':member.type.decode('ascii'),'mode':member.mode,'uid':member.uid,'gid':member.gid,'mtime':member.mtime,'link':member.linkname}
 return members

def inspect_plain(args):
 with args.plain.open('rb')as stream,args.original_plain.open('rb')as original:
  header=firmware_header(stream,args.plain.stat().st_size,args.model,args.version)
  old_header=firmware_header(original,args.original_plain.stat().st_size,args.model)
  need(header['region']==old_header['region'],'Region changed')
  files=index_tar(stream,header);old_files=index_tar(original,old_header)
  need(set(files)==set(old_files),'TAR member set differs from the supplied RV original inventory')
  for name,row in files.items():
   old=old_files[name]
   need(all(row[k]==old[k]for k in ('type','mode','uid','gid','mtime','link')),'TAR metadata changed: '+name)
  allowed_changes={'0700_part_image/dev/nflasha8','0700_part_image/dev/nflasha15','0700_part_image/dev/nflasha5','0701_part_image_sum/part_image.sum'}
  unchanged=[]
  for name,row in files.items():
   if not row['regular']or name in allowed_changes:continue
   old=old_files[name];need(row['bytes']==old['bytes'],'Unchanged member resized '+name)
   need(digest(Region(stream,row['offset'],row['bytes']).chunks())==digest(Region(original,old['offset'],old['bytes']).chunks()),'Undeclared TAR content modification '+name);unchanged.append(name)
  updater=[]
  old_u=[r for r in old_header['filesystems']if r['mode']=='U'and r['bytes']]
  new_u=[r for r in header['filesystems']if r['mode']=='U'and r['bytes']]
  need(len(old_u)==len(new_u)==1,'Expected one original RV U-body')
  old,new=old_u[0],new_u[0];old_sha=digest(Region(original,old['offset'],old['bytes']).chunks());new_sha=digest(Region(stream,new['offset'],new['bytes']).chunks())
  need(old_sha==new_sha and old['bytes']==new['bytes'],'Original RV U-body changed');updater={'bytes':new['bytes'],'sha256':new_sha,'original_body_preserved':True}
  sums=[]
  for name,row in sorted(files.items()):
   if not row['regular']or not name.endswith('.sum'):continue
   directory,filename=name.rsplit('/',1);need('_sum'in directory,'Unknown checksum directory '+directory)
   number,section=directory.split('_',1);section=section.removesuffix('_sum');prefix=f'{int(number)-1:04d}_{section}/'
   lines=Region(stream,row['offset'],row['bytes']).read(0,row['bytes']).decode('ascii').splitlines();checked=set();metadata=0
   for line in lines:
    fields=line.split(',');need(len(fields)>=11,'Malformed checksum line in '+name)
    target=prefix+clean(fields[10]);need(target in files,'Checksum target missing '+target)
    if fields[0]!='0':metadata+=1;continue
    need(target not in checked and files[target]['regular'],'Duplicate/non-file CRC target '+target)
    f=files[target];need(f['bytes']==int(fields[2],16),'Checksum size differs '+target)
    need(crc(Region(stream,f['offset'],f['bytes']))==int(fields[1],16),'Checksum CRC differs '+target);checked.add(target)
   covered={n for n,f in files.items()if n.startswith(prefix)and f['regular']}
   need(checked==covered,'Incomplete checksum coverage '+name)
   sums.append({'manifest':name,'files_checked':len(checked),'metadata_rows':metadata,'all_section_regular_files_covered':True})
  need(sums and len(sums)==sum(r['regular']and n.endswith('.sum')for n,r in files.items()),'Not all checksum lists verified')
  images={}
  for name,path in args.expect_image.items():
   key='0700_part_image/dev/'+name;need(key in files,'Expected image missing '+key);row=files[key]
   actual=digest(Region(stream,row['offset'],row['bytes']).chunks());need(row['bytes']==path.stat().st_size and actual==file_hash(path),'Embedded image differs '+name)
   images[name]={'bytes':row['bytes'],'sha256':actual,'matches_expected_file':True}
  need({'nflasha8','nflasha15'}<=set(images),'Both CP FAT and AP EXT2 expected images are required')
  cp=files['0700_part_image/dev/nflasha8'];ap=files['0700_part_image/dev/nflasha15']
  fat=FatAudit(Region(stream,cp['offset'],cp['bytes']));need(fat.total<=64<<20,'CP FAT exceeds64MiB partition capacity')
  cp_sha=digest(fat.chunks('/CPAPP-B.BIN'));need(cp_sha==file_hash(args.cp_component),'CP file differs from linked component')
  ext=Ext2Read(Region(stream,ap['offset'],ap['bytes']));need(ext.blocks*ext.block_bytes<=749731840,'AP EXT2 exceeds declared physical partition')
  ap_sha=digest(ext.chunks('/lib/appFw.so'));need(ap_sha==file_hash(args.ap_component),'AP file differs from linked component')
  resources=json.loads(args.resource_manifest.read_text(encoding='utf-8'));verified_resources=[]
  for record in resources['files']:
   path='/'+record['path'].lstrip('/');actual=digest(ext.chunks(path));need(actual==record['output_sha256'],'UI resource mismatch '+path);verified_resources.append(path)
  need(verified_resources,'No UI resources verified')
  wbi=files['0700_part_image/dev/nflasha5'];old_wbi=old_files['0700_part_image/dev/nflasha5'];need(wbi['bytes']==old_wbi['bytes'],'WBI extent changed')
  prefix_bytes=512 if args.warm_boot_marker=='ZERO512' else 4
  marker=Region(stream,wbi['offset'],prefix_bytes).read(0,prefix_bytes)
  expected=bytes(512)if args.warm_boot_marker=='ZERO512' else args.warm_boot_marker.encode('ascii')
  need(marker==expected,'Expected warm-boot invalidation bytes')
  tail=digest(Region(stream,wbi['offset']+prefix_bytes,wbi['bytes']-prefix_bytes).chunks());old_tail=digest(Region(original,old_wbi['offset']+prefix_bytes,old_wbi['bytes']-prefix_bytes).chunks())
  need(tail==old_tail,'WBI changed outside the declared invalidation prefix')
  return {'firmware':header,'TAR_members':len(files),'TAR_inventory_and_metadata_preserved':True,'unchanged_regular_members_byte_content_verified':unchanged,'declared_mutable_members':sorted(allowed_changes),'all_sum_manifests':sums,'U_body':updater,'embedded_images':images,
   'CP_FAT':fat.summary()|{'cp_component_sha256':cp_sha},'AP_EXT2':ext.summary()|{'ap_component_sha256':ap_sha},'UXC_resources_verified':verified_resources,
   'warm_boot':{'invalidation':args.warm_boot_marker,'declared_prefix_bytes':prefix_bytes,'all_bytes_after_prefix_original':True,'tail_sha256':tail,'native_boot_acceptance':'NOT_TESTED'}}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dat',type=Path,required=True);p.add_argument('--plain',type=Path,required=True);p.add_argument('--public-key',type=Path,required=True)
 p.add_argument('--original-dat',type=Path,default=Path('inputs/BODYDATA.DAT'));p.add_argument('--original-plain',type=Path,default=ROOT/'analysis/firmware-decrypted.fdat')
 p.add_argument('--model',type=lambda x:int(x,0),default=0x11030080);p.add_argument('--version',default='4.01');p.add_argument('--warm-boot-marker',default='ZERO512',choices=['ZERO512','WBI3','WBI4'])
 p.add_argument('--expect-image',action='append',required=True,help='nflasha8=path or nflasha15=path');p.add_argument('--cp-component',type=Path,required=True);p.add_argument('--ap-component',type=Path,required=True)
 p.add_argument('--resource-manifest',type=Path,default=ROOT/'sound-port/menu/resource-manifest.json');p.add_argument('--report',type=Path,default=ROOT/'analysis/dat-verify-final.json');a=p.parse_args()
 a.expect_image={name:Path(path)for name,path in (item.split('=',1)for item in a.expect_image)}
 result={'status':'VERIFYING','DAT_bytes':a.dat.stat().st_size,'DAT_sha256':file_hash(a.dat),'independent_from_encoder':True,'encoder_imported_or_called':False,'camera_io':False,'hardware_flash_or_audio_verified':False}
 try:
  result['container']=decode_compare(a.dat,a.plain,a.public_key,a.original_dat);result['container'].pop('header');print('Container/RSA/decode PASS; verifying all TAR sums and embedded files',flush=True)
  result['contents']=inspect_plain(a);result['status']='INDEPENDENT_RV_DAT_READBACK_PASS'
 except Exception as error:
  result['status']='FAILED';result['error']=str(error);a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');raise
 result['boundaries']={'signature':'cryptographically valid with supplied package signing key; stock camera trust is a separate condition','NOR_physical_capacity_and_boot_branch':'runtime device state not read','WBI_cold_start':'declared invalidation prefix and original tail verified; actual boot not tested'}
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(result['status'],a.report)

if __name__=='__main__':main()
