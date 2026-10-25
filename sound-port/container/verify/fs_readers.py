"""Independent read-only FAT12/16 and classic EXT2 readers for package audits."""
import math,struct

def need(value,message):
 if not value:raise ValueError(message)

class Region:
 def __init__(self,stream,start,size):self.stream,self.start,self.size=stream,start,size
 def read(self,offset,size):
  need(0<=offset<=self.size and 0<=size<=self.size-offset,'Filesystem read outside image')
  self.stream.seek(self.start+offset);data=self.stream.read(size)
  need(len(data)==size,'Truncated filesystem image');return data
 def chunks(self,offset=0,size=None,chunk=4<<20):
  size=self.size-offset if size is None else size
  while size:
   data=self.read(offset,min(size,chunk));yield data;offset+=len(data);size-=len(data)

class FatAudit:
 def __init__(self,region):
  self.region=region;b=region.read(0,512)
  need(b[510:512]==b'\x55\xaa','FAT boot signature')
  self.bps=struct.unpack_from('<H',b,11)[0];self.spc=b[13]
  self.reserved=struct.unpack_from('<H',b,14)[0];self.copies=b[16];self.roots=struct.unpack_from('<H',b,17)[0]
  self.sectors=struct.unpack_from('<H',b,19)[0]or struct.unpack_from('<I',b,32)[0]
  self.spf=struct.unpack_from('<H',b,22)[0]
  need(self.bps in (512,1024,2048,4096) and self.spc in (1,2,4,8,16,32,64,128) and self.reserved and self.copies in (1,2) and self.roots and self.spf,'Unsupported FAT geometry')
  self.cluster_bytes=self.bps*self.spc;self.fat_start=self.reserved*self.bps;self.fat_bytes=self.spf*self.bps
  self.root_start=self.fat_start+self.copies*self.fat_bytes;self.root_bytes=self.roots*32
  self.data_start=self.root_start+math.ceil(self.root_bytes/self.bps)*self.bps;self.total=self.sectors*self.bps
  need(self.data_start<self.total<=region.size,'FAT serialized image shorter than BPB total')
  self.clusters=(self.total-self.data_start)//self.cluster_bytes
  self.bits=12 if self.clusters<4085 else 16
  need(self.clusters<65525,'FAT32 not supported by this audited path')
  need(math.ceil((self.clusters+2)*self.bits/8)<=self.fat_bytes,'FAT table capacity')
  self.table=region.read(self.fat_start,self.fat_bytes)
  for copy in range(1,self.copies):need(self.table==region.read(self.fat_start+copy*self.fat_bytes,self.fat_bytes),'FAT mirrors differ')
  self.files={};self.owners={};self._walk(None,'',0)
 def value(self,cluster):
  offset=cluster*3//2 if self.bits==12 else cluster*2
  value=struct.unpack_from('<H',self.table,offset)[0]
  return ((value>>4 if cluster&1 else value)&4095) if self.bits==12 else value
 def chain(self,start):
  if start==0:return []
  chain=[];seen=set();current=start
  while True:
   need(2<=current<self.clusters+2 and current not in seen,'FAT cyclic/out-of-range chain')
   seen.add(current);chain.append(current);value=self.value(current)
   if value>=(0xff8 if self.bits==12 else 0xfff8):return chain
   need(2<=value<(0xff0 if self.bits==12 else 0xfff0),'FAT chain reaches free/bad/reserved cluster');current=value
 def cluster_offset(self,cluster):return self.data_start+(cluster-2)*self.cluster_bytes
 def _walk(self,first,prefix,depth):
  need(depth<64,'FAT directory depth')
  ranges=[(self.root_start,self.root_bytes)]if first is None else[(self.cluster_offset(c),self.cluster_bytes)for c in self.chain(first)]
  names=set()
  for start,size in ranges:
   data=self.region.read(start,size)
   for offset in range(0,size,32):
    row=data[offset:offset+32]
    if row[0]==0:return
    if row[0]==0xe5 or row[11]==0xf or row[11]&8:continue
    name=row[:8].decode('ascii').rstrip();ext=row[8:11].decode('ascii').rstrip()
    if ext:name+='.'+ext
    if name in ('.','..'):continue
    need(name not in names,'FAT duplicate short filename');names.add(name)
    key=prefix+name;cluster=struct.unpack_from('<H',row,26)[0];length=struct.unpack_from('<I',row,28)[0];chain=self.chain(cluster)
    for c in chain:need(c not in self.owners,'Cross-linked FAT ownership');self.owners[c]=key
    need(length<=len(chain)*self.cluster_bytes,'FAT file exceeds allocated chain')
    if row[11]&16:
     need(cluster>=2,'FAT directory missing cluster');self._walk(cluster,key+'/',depth+1)
    else:self.files[key.upper()]={'bytes':length,'chain':chain}
 def chunks(self,path):
  key=path.strip('/').upper();need(key in self.files,'Missing FAT file '+path);entry=self.files[key];left=entry['bytes']
  for c in entry['chain']:
   if not left:break
   n=min(left,self.cluster_bytes);yield self.region.read(self.cluster_offset(c),n);left-=n
  need(left==0,'Incomplete FAT file read')
 def summary(self):
  free=sum(self.value(c)==0 for c in range(2,self.clusters+2))
  return {'type':f'FAT{self.bits}','image_bytes':self.region.size,'BPB_bytes':self.total,'cluster_bytes':self.cluster_bytes,'clusters':self.clusters,
   'free_cluster_bytes':free*self.cluster_bytes,'files':len(self.files),'owned_clusters':len(self.owners),'mirrors_equal':True,'cross_links':0,
   'CP':self.files.get('CPAPP-B.BIN')and{'bytes':self.files['CPAPP-B.BIN']['bytes'],'allocated_bytes':len(self.files['CPAPP-B.BIN']['chain'])*self.cluster_bytes}}

class Ext2Read:
 def __init__(self,region):
  self.region=region;s=region.read(1024,1024)
  need(s[56:58]==b'\x53\xef','EXT2 superblock magic')
  self.blocks=struct.unpack_from('<I',s,4)[0];self.first_data=struct.unpack_from('<I',s,20)[0]
  self.block_bytes=1024<<struct.unpack_from('<I',s,24)[0];self.blocks_per_group=struct.unpack_from('<I',s,32)[0]
  self.inodes_per_group=struct.unpack_from('<I',s,40)[0];self.inode_bytes=struct.unpack_from('<H',s,88)[0] or 128
  self.incompat=struct.unpack_from('<I',s,96)[0]
  need(self.block_bytes in (1024,2048,4096,8192,16384,32768,65536) and self.blocks*self.block_bytes<=region.size,'EXT2 block geometry')
  need(not(self.incompat&0x40)and not(self.incompat&0x80),'EXT4 extents/64bit need a separate audited reader')
  self.groups=math.ceil((self.blocks-self.first_data)/self.blocks_per_group);self.cache={};self.inode_cache={}
 def block(self,number):
  need(0<number<self.blocks,'EXT2 data block outside filesystem');return self.region.read(number*self.block_bytes,self.block_bytes)
 def pointer(self,number,index):
  if not number:return 0
  if number not in self.cache:self.cache[number]=self.block(number)
  return struct.unpack_from('<I',self.cache[number],index*4)[0]
 def inode(self,number):
  if number in self.inode_cache:return self.inode_cache[number]
  need(number>0,'EXT2 inode0');group,index=divmod(number-1,self.inodes_per_group);need(group<self.groups,'EXT2 inode group')
  gd=(self.first_data+1)*self.block_bytes+group*32;table=struct.unpack('<I',self.region.read(gd+8,4))[0]
  data=self.region.read(table*self.block_bytes+index*self.inode_bytes,self.inode_bytes)
  mode=struct.unpack_from('<H',data)[0];size=struct.unpack_from('<I',data,4)[0]
  if mode&0xf000==0x8000:size|=struct.unpack_from('<I',data,108)[0]<<32
  need(not(struct.unpack_from('<I',data,32)[0]&0x80000),'Unexpected EXT4 extent inode')
  item={'mode':mode,'bytes':size,'pointers':struct.unpack_from('<15I',data,40)};self.inode_cache[number]=item;return item
 def inode_chunks(self,item):
  left=item['bytes'];per=self.block_bytes//4;p=item['pointers'];index=0
  while left:
   if index<12:number=p[index]
   elif index<12+per:number=self.pointer(p[12],index-12)
   elif index<12+per+per*per:
    a,b=divmod(index-12-per,per);number=self.pointer(self.pointer(p[13],a),b)
   else:
    at=index-12-per-per*per;a,rest=divmod(at,per*per);b,c=divmod(rest,per)
    need(a<per,'EXT2 triple indirect bound');number=self.pointer(self.pointer(self.pointer(p[14],a),b),c)
   n=min(left,self.block_bytes);yield self.block(number)[:n]if number else bytes(n);left-=n;index+=1
 def locate(self,path):
  current=self.inode(2)
  for component in path.strip('/').split('/'):
   need(component not in ('','.','..'),'Invalid EXT2 path');need(current['mode']&0xf000==0x4000,'EXT2 path parent is not a directory')
   content=b''.join(self.inode_chunks(current));offset=0;found=[]
   while offset<len(content):
    number,length,namesize,_=struct.unpack_from('<IHBB',content,offset)
    need(length>=8 and length%4==0 and offset+length<=len(content)and namesize<=length-8,'EXT2 directory entry bounds')
    if number and content[offset+8:offset+8+namesize]==component.encode('utf8'):found.append(number)
    offset+=length
   need(len(found)==1,'Missing/duplicate EXT2 path '+path);current=self.inode(found[0])
  need(current['mode']&0xf000==0x8000,'Expected EXT2 regular file');return current
 def chunks(self,path):yield from self.inode_chunks(self.locate(path))
 def summary(self):return {'type':'EXT2','image_bytes':self.region.size,'filesystem_bytes':self.blocks*self.block_bytes,'block_bytes':self.block_bytes,'incompat_flags':hex(self.incompat),'extents':False}
