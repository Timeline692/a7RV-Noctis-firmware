"""Build an exact RV 4.00 offline CP component from the linked ARM extension.

This writes a separate raw CP component and manifest, never an update package.
The manifest retains unresolved codec, runtime readiness and outer-load limits.
"""
from __future__ import annotations
import argparse,hashlib,io,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE_SHA256='3269bf62426339791fcfbe8529698cd4accbe6c3d2ea61cd7c368a90ab7ee7c8'
BASE_BYTES=17617008
FILE_VA=0x108000
HEADER=0x128000
RX_START,RX_END=0x1a3a000,0x1a3c000
RW_START=0x1a39450
OLD_BSS_END=0x1a39448
VENEER_START,VENEER_END=0xbef220,0xbf0000
HOOKS=(
 ('lookup',0x65669c,'00f1140c','rv_veneer_lookup','csnd_cp_lookup_hook'),
 ('exists',0x65660a,'14300022','rv_veneer_exists','csnd_cp_exists'),
 ('start',0x6545c8,'f0b503af','rv_veneer_start','csnd_cp_start'),
 ('validate',0x198cf0,'b0b502af','rv_veneer_validate','csnd_cp_validate'),
 ('gain',0x1998b8,'28798df80400','rv_veneer_gain','csnd_custom_gain_hook'),
 ('driver_entry',0xb35832,'d0b502af','rv_veneer_driver_entry','csnd_driver_entry_hook'),
 ('driver_exit',0xb358d0,'204602b0d0bd','rv_veneer_driver_exit','csnd_driver_exit_hook'),
 ('dmm_dispatch',0xbdb982,'f0b503af','rv_veneer_dmm','rv_cp_dmm_dispatch'),
)
HEADER_WORDS={0:0x5f0a50,0x124:0,0x128:0xac7218,0x12c:0x128000,
 0x130:0xac8000,0x134:0x48e728,0x138:0xbf0000,0x13c:0xf57000,
 0x140:0x116070,0x144:0x107f000,0x148:0x106f000,0x14c:0x8a2448,
 0x150:0x1197000,0x154:0,0x158:0x4000,0x15c:0x1a3c000,
 0x160:0,0x164:0x8000,0x168:0x1a40000,0x16c:0x128000,
 0x170:0x106f000,0x174:0x418,0x178:4}
COLD_ENTRY=bytes.fromhex('000051e3f6ccff0a0100a0e12deaffea')
COLD_ZERO=bytes.fromhex('002007e3483409e3181400e3192140e3a33140e3010082e0022043e0011042e0694600eb000007e30110a0e3190140e3140090e5001080e54ff07ff504f020e3')

def codec_evidence_summary():
 root=Path(__file__).resolve().parents[2]
 path=root/'sound-port/config/reference-codec.json'
 evidence=json.loads(path.read_text(encoding='utf-8'))
 windows=evidence['function_windows']
 if not(evidence['status']=='STATIC_COMPATIBILITY_EVIDENCE' and len(windows)==10 and
        all(w['normalized_equal'] and not w['differences'] for w in windows) and
        not evidence['external_mapping_conflicts'] and evidence['all_40_stock_sound_assets_equal'] and
        evidence['hardware_audio_or_decoder_output_verified'] is False):
  raise ValueError('Static codec compatibility evidence differs from the admitted inference')
 return {'report':'sound-port/config/reference-codec.json',
  'status':'STATIC_COMPATIBILITY_EVIDENCE','normalized_native_windows_equal':10,
  'instructions_per_side':sum(w['rv_instructions']for w in windows),'stock_sound_assets_equal':40,
  'external_call_mapping_conflicts':0,'inference_accepted_only_by_explicit_profile':True,
  'reference_custom_F0_waveform_verified':False,'hardware_audio_or_decoder_output_verified':False}

def u32(data,at):return struct.unpack_from('<I',data,at)[0]
def align(value,n=4096):return (value+n-1)&-n
def require(condition,message):
 if not condition:raise ValueError(message)
def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
def thumb_branch(source,target):
 require(source%2==0 and target&1,'Thumb hook needs halfword source and Thumb symbol')
 delta=(target&~1)-(source+4)
 require(delta%2==0 and -(1<<24)<=delta<(1<<24),'Thumb B.W target out of range')
 x=delta&0x1ffffff;s=x>>24;i1=x>>23&1;i2=x>>22&1
 return struct.pack('<HH',0xf000|s<<10|((x>>12)&0x3ff),
                    0x9000|((1^i1^s)<<13)|((1^i2^s)<<11)|((x>>1)&0x7ff))
def thumb_target(source,data):
 a,b=struct.unpack('<HH',data)
 require(a&0xf800==0xf000 and b&0xd000==0x9000,'Expected unconditional Thumb B.W')
 s=a>>10&1;i1=1^(b>>13&1)^s;i2=1^(b>>11&1)^s
 x=s<<24|i1<<23|i2<<22|(a&0x3ff)<<12|(b&0x7ff)<<1
 return source+4+signed(x,25)
def arm_bl(source,target):
 delta=target-(source+8)
 require(source%4==target%4==0 and -(1<<25)<=delta<(1<<25),'A32 BL target out of range')
 return struct.pack('<I',0xeb000000|((delta>>2)&0xffffff))
def arm_target(source,data):
 ins=u32(data,0);require(ins&0xff000000==0xeb000000,'Expected unconditional A32 BL')
 return source+8+signed(ins&0xffffff,24)*4
def native_l1(header):
 physical=u32(header,0x16c);offset=u32(header,0x148);size=u32(header,0x14c)
 extra=0x4fff if u32(header,0x150)==physical+offset else 0x3fff
 return ((offset+size+extra)&~0x3fff)+physical

def patch(source:bytes,module:bytes):
 require(len(source)==BASE_BYTES and hashlib.sha256(source).hexdigest()==BASE_SHA256,
         'Expected the exact original A7R V 4.00 cpapp-b.bin')
 original_header=source[HEADER-FILE_VA:HEADER-FILE_VA+0x17c]
 for at,value in HEADER_WORDS.items():require(u32(original_header,at)==value,f'Module header differs at +{at:#x}')
 require(source[0x5f0af0-FILE_VA:0x5f0b00-FILE_VA]==COLD_ENTRY,'Primary-only startup guard differs')
 require(source[0x5e3ee4-FILE_VA:0x5e3f24-FILE_VA]==COLD_ZERO,'Cold-zero/secondary-release ordering guard differs')
 require(arm_target(0x5e3f04,source[0x5e3f04-FILE_VA:0x5e3f08-FILE_VA])==0x5f58b0,'Original cold-zero callee differs')
 require(not any(source[0xbef218-FILE_VA:VENEER_END-FILE_VA]),'Native text-page padding is not zero')
 elf=ELFFile(io.BytesIO(module))
 require(elf.elfclass==32 and elf.little_endian and elf['e_machine']=='EM_ARM' and elf['e_type']=='ET_EXEC','Expected linked little-endian ARM32 ET_EXEC')
 require(elf['e_flags']==0x5000200,'Expected ARM EABI5 soft-float extension')
 symtab=elf.get_section_by_name('.symtab');require(symtab is not None,'ELF symbol table is required')
 symbols={s.name:int(s['st_value']) for s in symtab.iter_symbols() if s.name and s['st_shndx']!='SHN_UNDEF'}
 undefined=[s.name for s in symtab.iter_symbols() if s.name and s['st_shndx']=='SHN_UNDEF'];require(not undefined,f'Undefined ELF symbols: {undefined}')
 for s in elf.iter_sections():require(not(s['sh_type'] in ('SHT_REL','SHT_RELA') and s['sh_size']),'Unapplied ELF relocations')
 allocated=[s for s in elf.iter_sections() if s['sh_flags']&2 and s['sh_size']]
 require({s.name for s in allocated}=={'.rv_veneer','.text','.bss'},'Unexpected allocated ELF sections')
 byname={s.name:s for s in allocated};veneer,text,bss=(byname[n] for n in ('.rv_veneer','.text','.bss'))
 require(veneer['sh_addr']==VENEER_START and veneer['sh_size']<=0x100 and veneer['sh_flags']==6 and veneer['sh_type']=='SHT_PROGBITS','Veneer exceeds proven text-page padding')
 require(text['sh_addr']==RX_START and text['sh_size']<=RX_END-RX_START and text['sh_flags']==6 and text['sh_type']=='SHT_PROGBITS','Private RX exceeds proven two-page allocation')
 require(bss['sh_addr']==RW_START and bss['sh_flags']==3 and bss['sh_type']=='SHT_NOBITS','Unexpected private BSS contract')
 bss_end=RW_START+bss['sh_size']
 require(symbols['__rv_cp_bss_start']==RW_START and symbols['__rv_cp_bss_end']==bss_end and bss_end<=RX_START,'Private BSS symbols or RW/RX boundary differ')
 require(elf['e_entry']==symbols['rv_cp_cold_zero_hook'] and not(elf['e_entry']&3),'Entry must be the A32 cold wrapper')

 def module_data(va,size):
  found=[s for s in allocated if s['sh_type']=='SHT_PROGBITS' and s['sh_addr']<=va and va+size<=s['sh_addr']+s['sh_size']]
  require(len(found)==1,f'ELF code at {va:#x}+{size:#x} not uniquely backed')
  s=found[0];at=va-s['sh_addr'];return s.data()[at:at+size]

 # Native zero call, private zero/init, then return before original release.
 cold=symbols['rv_cp_cold_zero_hook'];body=module_data(cold,24)
 require(u32(body,0)==0xe92d4010 and u32(body,8)==u32(body,16)==0xe12fff3c and u32(body,20)==0xe8bd8010,'Cold wrapper call/return sequence differs')
 cold_calls=[]
 for offset,expected in ((4,0x5f58b0),(12,symbols['rv_cp_module_cold_init'])):
  instruction=u32(body,offset);require(instruction&0xfffff000==0xe59fc000,'Cold wrapper requires literal LDR r12')
  address=cold+offset+8+(instruction&0xfff);actual=u32(module_data(address,4),0)
  require(actual==expected,'Cold wrapper literal target differs');cold_calls.append(hex(actual))

 out=bytearray(source);out.extend(bytes(RX_END-FILE_VA-len(out)))
 edits=[];sections=[];changed=[]
 def edit(va,before,after,name):
  at=va-FILE_VA;require(len(before)==len(after) and source[at:at+len(before)]==before,f'Exact original guard failed: {name} at{va:#x}')
  require(not any(at<end and start<at+len(after) for start,end in changed),'Overlapping native edits')
  out[at:at+len(after)]=after;changed.append((at,at+len(after)))
  edits.append({'name':name,'va':hex(va),'file_offset':hex(at),'bytes':len(after),'before_hex':before.hex(),'after_hex':after.hex()})
 for s in allocated:
  va,size=int(s['sh_addr']),int(s['sh_size'])
  payload=bytes(size) if s['sh_type']=='SHT_NOBITS' else s.data()
  if s.name=='.rv_veneer':edit(va,bytes(size),payload,'ELF .rv_veneer')
  else:
   require(va-FILE_VA>=len(source),'Private section overlaps the original file')
   out[va-FILE_VA:va-FILE_VA+size]=payload
  sections.append({'name':s.name,'va':hex(va),'bytes':size,'file_offset':hex(va-FILE_VA),'cold_zero':s['sh_type']=='SHT_NOBITS','sha256':hashlib.sha256(payload).hexdigest()})
 hooks=[]
 for name,va,expected_hex,veneer_name,target_name in HOOKS:
  expected=bytes.fromhex(expected_hex);target=symbols[veneer_name]
  replacement=thumb_branch(va,target)+b'\x00\xbf'*((len(expected)-4)//2)
  require(thumb_target(va,replacement[:4])==target&~1,'Thumb hook target did not round-trip')
  veneer_body=module_data(target&~1,8)
  require(veneer_body[:4]==b'\xdf\xf8\x00\xf0' and u32(veneer_body,4)==symbols[target_name] and symbols[target_name]&1,'Thumb veneer target/interworking differs')
  edit(va,expected,replacement,name)
  hooks.append({'name':name,'va':hex(va),'isa':'Thumb','veneer':hex(target),'target_symbol':target_name,'target':hex(symbols[target_name]),'branch_decode_verified':True})
 va=0x5e3f04;target=symbols['rv_veneer_cold'];replacement=arm_bl(va,target)
 require(arm_target(va,replacement)==target,'A32 hook target did not round-trip')
 require(module_data(target,8)==struct.pack('<II',0xe51ff004,cold),'A32 cold veneer literal differs')
 edit(va,bytes.fromhex('694600eb'),replacement,'cold_bss_zero')
 hooks.append({'name':'cold_bss_zero','va':hex(va),'isa':'A32','veneer':hex(target),'target_symbol':'rv_cp_cold_zero_hook','target':hex(cold),'branch_decode_verified':True})
 for offset,value,label in ((0x128,RX_END-HEADER,'text_size'),(0x14c,bss_end-0x1197000,'bss_size')):
  edit(HEADER+offset,struct.pack('<I',HEADER_WORDS[offset]),struct.pack('<I',value),label)
 header=bytes(out[HEADER-FILE_VA:HEADER-FILE_VA+0x17c])
 require(native_l1(original_header)==native_l1(header)==0x1a3c000,'Native L1 page-table base moved')
 require(header[0x158:]==original_header[0x158:],'Page-table/reserved boot fields moved')
 # Simulate the actual loader overlay order at each installed section.
 regions=[(u32(header,a+8),align(u32(header,a+4)),flags) for a,flags in ((0x124,'RX'),(0x130,'RO'),(0x13c,'RW'),(0x148,'RW'))]
 def final_permission(address):
  result=None
  for start,size,flags in regions:
   if start<=address<start+size:result=flags
  return result
 for s in allocated:
  expected='RW' if s['sh_flags']&1 else 'RX'
  for page in range(s['sh_addr']&~4095,align(s['sh_addr']+s['sh_size']),4096):
   require(final_permission(page)==expected,f'Final native overlay permission differs for {s.name}')
 cursor=0
 for start,end in sorted(changed):
  require(source[cursor:start]==out[cursor:start],'Original bytes changed outside declared edits');cursor=end
 require(source[cursor:]==out[cursor:len(source)],'Original tail changed')
 abi=symbols['rv_cp_abi'];binding=module_data(abi,64);proof_flags=u32(binding,0)
 busy_addresses=struct.unpack_from('<11I',binding,8);busy_widths=list(binding[52:63])
 busy_complete=all(address and width in (1,4) for address,width in zip(busy_addresses,busy_widths))
 def module_string(name):
  if name not in symbols:return None
  result=bytearray()
  for index in range(128):
   value=module_data(symbols[name]+index,1)[0]
   if not value:return result.decode('ascii')
   result.append(value)
  raise ValueError('Unterminated CP build profile metadata')
 profile=module_string('rv_cp_build_profile') or 'offline'
 codec_admission=module_string('rv_cp_codec_admission') or 'DISABLED;HARDWARE_NOT_TESTED'
 require(proof_flags in (0,63),'Unsupported CP admission mask')
 require(profile in ('offline','reference-codec-experimental'),'Unknown CP build profile')
 experimental=profile=='reference-codec-experimental'
 require((experimental and proof_flags==63 and busy_complete)or(not experimental and proof_flags==0),'Profile/admission mask or busy bindings differ')
 if experimental:require(codec_admission=='REFERENCE_FORMAT0_COMPATIBILITY_INFERENCE;HARDWARE_NOT_TESTED','Experimental codec admission is not explicitly labelled')
 codec_evidence=codec_evidence_summary() if experimental else None
 report={'schema':1,'status':'OFFLINE_CP_COMPONENT','base_sha256':BASE_SHA256,
  'source_bytes':len(source),'elf_sha256':hashlib.sha256(module).hexdigest(),'output_sha256':hashlib.sha256(out).hexdigest(),'output_bytes':len(out),
  'sections':sections,'hooks':hooks,'original_edits':edits,'original_bytes_preserved_outside_declared_ranges':True,
  'module_header':{'text_size':hex(u32(header,0x128)),'bss_size':hex(u32(header,0x14c)),'private_bss_end':hex(bss_end),
   'native_l1_before_and_after':'0x1a3c000','native_l2_base_unchanged':'0x1a40000','overlay_order':'text RX, native RO, native initialized RW, BSS RW','installed_page_permissions_verified':True},
  'cold_init':{'primary_only_guard':'0x5f0af0..0x5f0b00','callsite':'0x5e3f04','calls_in_order':cold_calls,'return_va':'0x5e3f08','secondary_release_va':'0x5e3f18','dsb_va':'0x5e3f1c','sev_va':'0x5e3f20','private_bss_cleared_before_release':True},
  'profile':profile,'experimental':experimental,'codec_static_compatibility':codec_evidence,
  'readiness':{'linked_proof_flags':proof_flags,'required_proof_flags':63,'admission_mask':proof_flags,
   'legacy_field_is_admission_mask_not_proof_certificate':True,'private_runtime_enabled_after_cold_init':proof_flags==63,
   'private_runtime_enabled':proof_flags==63,'proof_flags_not_changed_by_patcher':True,
   'codec_bit_admission':codec_admission,'all_11_busy_mapped':busy_complete,
   'busy_bindings':[{'address':hex(address),'width':width}for address,width in zip(busy_addresses,busy_widths)]},
  'boundaries':{'codec':'REFERENCE_FORMAT0_COMPATIBILITY_INFERENCE_ACCEPTED' if experimental else 'REFERENCE_F0_CANDIDATE_NOT_RV_DECODER_PROOF',
   'codec_hardware_audibility':'NOT_TESTED','admission_mask63_is_not_63_verified_hardware_proofs':True,'outer_file_transfer_capacity':'NOT_PROVEN',
   'outer_nor_capacity':'NOT_PROVEN; pformat cpapp size0 is not a capacity result','complete_firmware':False,'device_execution':'NOT_TESTED'},
  'batch_contract':'Use with AP extension/resources from the same source build: private NSCC ops1..6; COPY ACK allocation40+n; kind4 focus/kind17 shutter.',
  'evidence':['analysis/sound-port-cp-loader-native.txt','analysis/sound-port-cp-cold-entry.txt','analysis/sound-port-cp-cold-zero.txt','analysis/sound-port-cp-hook-plan.json','analysis/emulator-cp-handoff.json','analysis/sound-port-cp-busy.json',
   'references/stock-a7m4-602/extraction-manifest.json']+(['sound-port/config/reference-codec.json','references/stock-a7m4-602/codec-summary.md'] if experimental else [])}
 return bytes(out),report

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--base',type=Path,required=True);parser.add_argument('--elf',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 args=parser.parse_args();manifest=args.output.with_suffix(args.output.suffix+'.manifest.json')
 if args.output.exists() or manifest.exists():raise FileExistsError('Output or manifest exists; choose a new path')
 if args.output.resolve() in (args.base.resolve(),args.elf.resolve()):raise ValueError('Output cannot replace an input')
 payload,report=patch(args.base.read_bytes(),args.elf.read_bytes())
 report.update({'base_path':str(args.base.resolve()),'elf_path':str(args.elf.resolve()),'output_path':str(args.output.resolve())})
 args.output.parent.mkdir(parents=True,exist_ok=True)
 with args.output.open('xb') as f:f.write(payload)
 with manifest.open('x',encoding='utf-8') as f:json.dump(report,f,ensure_ascii=False,indent=2)
 print(json.dumps({'status':report['status'],'output_bytes':len(payload),'hooks':len(report['hooks']),'manifest':str(manifest),'boundaries':report['boundaries']},ensure_ascii=False))

if __name__=='__main__':main()
