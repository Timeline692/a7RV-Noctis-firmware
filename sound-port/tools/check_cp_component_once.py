"""One real-file offline contract check of the CP component generator."""
from __future__ import annotations
import argparse,hashlib,io,json,os,struct,subprocess,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB,CS_OP_IMM
from elftools.elf.elffile import ELFFile
from patch_cp import patch,FILE_VA,HEADER,HOOKS,RX_START,RX_END,native_l1
ROOT=Path(__file__).resolve().parents[2]

def rejected(fn):
 try:fn()
 except ValueError:return True
 raise AssertionError('Expected malformed input to be rejected')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--elf',type=Path,default=ROOT/'sound-port/build/cp/cp-port-candidate.elf')
 p.add_argument('--output',type=Path,default=ROOT/'sound-port/build/components/cpapp-b.offline.bin')
 a=p.parse_args();a.output=a.output.resolve();a.elf=a.elf.resolve();base=ROOT/'analysis/targets/nflasha8/cpapp-b.bin'
 original=base.read_bytes();before=base.stat();module=a.elf.read_bytes()
 command=[sys.executable,str(ROOT/'sound-port/tools/patch_cp.py'),'--base',str(base),'--elf',str(a.elf),'--output',str(a.output)]
 environment=dict(os.environ,PYTHONIOENCODING='utf-8')
 if not a.output.exists():
  r=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',env=environment)
  if r.returncode:raise RuntimeError(r.stderr)
 output=a.output.read_bytes();manifest=json.loads(a.output.with_suffix(a.output.suffix+'.manifest.json').read_text(encoding='utf-8'))
 assert manifest['status']=='OFFLINE_CP_COMPONENT' and not manifest['boundaries']['complete_firmware']
 assert manifest['output_sha256']==hashlib.sha256(output).hexdigest()
 assert manifest['elf_sha256']==hashlib.sha256(module).hexdigest()
 assert len(output)==RX_END-FILE_VA
 # Reconstruct the exact original file using the manifest's retained bytes.
 restored=bytearray(output[:len(original)])
 for edit in manifest['original_edits']:
  at=int(edit['file_offset'],0);old=bytes.fromhex(edit['before_hex']);new=bytes.fromhex(edit['after_hex'])
  assert original[at:at+len(old)]==old and output[at:at+len(new)]==new
  restored[at:at+len(old)]=old
 assert restored==original
 elf=ELFFile(io.BytesIO(module));symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name}
 for section in elf.iter_sections():
  if not section['sh_flags']&2 or not section['sh_size']:continue
  at=section['sh_addr']-FILE_VA;size=section['sh_size']
  expected=bytes(size) if section['sh_type']=='SHT_NOBITS' else section.data()
  assert output[at:at+size]==expected
 decoders={'Thumb':Cs(CS_ARCH_ARM,CS_MODE_THUMB),'A32':Cs(CS_ARCH_ARM,CS_MODE_ARM)}
 for dis in decoders.values():dis.detail=True
 decoded=[]
 for hook in manifest['hooks']:
  va=int(hook['va'],0);target=int(hook['veneer'],0)&~1
  instruction=list(decoders[hook['isa']].disasm(output[va-FILE_VA:va-FILE_VA+4],va))
  assert len(instruction)==1 and instruction[0].mnemonic==('b.w' if hook['isa']=='Thumb' else 'bl')
  operand=instruction[0].operands[0];assert operand.type==CS_OP_IMM and operand.imm==target
  decoded.append({'va':hex(va),'instruction':instruction[0].mnemonic+' '+instruction[0].op_str,'target':hex(target)})
  if hook['isa']=='Thumb':assert struct.unpack_from('<I',output,target-FILE_VA+4)[0]==int(hook['target'],0)
  else:assert struct.unpack_from('<II',output,target-FILE_VA)==(0xe51ff004,int(hook['target'],0))
 h=output[HEADER-FILE_VA:HEADER-FILE_VA+0x17c]
 assert native_l1(h)==0x1a3c000 and struct.unpack_from('<I',h,0x168)[0]==0x1a40000
 assert struct.unpack_from('<I',h,0x128)[0]==RX_END-HEADER
 bss_end=struct.unpack_from('<I',h,0x150)[0]+struct.unpack_from('<I',h,0x14c)[0]
 assert bss_end==symbols['__rv_cp_bss_end']<=RX_START
 # Cold wrapper preserves native zero, private init, and the original release.
 cold=symbols['rv_cp_cold_zero_hook'];cold_ins=list(decoders['A32'].disasm(output[cold-FILE_VA:cold-FILE_VA+24],cold))
 assert [i.mnemonic for i in cold_ins]==['push','ldr','blx','ldr','blx','pop']
 assert output[0x5e3f08-FILE_VA:0x5e3f24-FILE_VA]==original[0x5e3f08-FILE_VA:0x5e3f24-FILE_VA]
 # Guard failures are checked in memory; they create no extra files.
 bad=bytearray(original);bad[HOOKS[0][1]-FILE_VA]^=1
 rejected(lambda:patch(bytes(bad),module))
 bad_module=bytearray(module);veneer=elf.get_section_by_name('.rv_veneer');bad_module[veneer['sh_offset']+4]^=2
 rejected(lambda:patch(original,bytes(bad_module)))
 rerun=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',env=environment);assert rerun.returncode and 'exists' in rerun.stderr
 after=base.stat();assert before.st_mtime_ns==after.st_mtime_ns and before.st_size==after.st_size and base.read_bytes()==original
 report={'status':'OFFLINE_CP_FILE_CONTRACT_PASS','output':str(a.output.relative_to(ROOT)),'output_bytes':len(output),
  'manifest':str(a.output.with_suffix(a.output.suffix+'.manifest.json').relative_to(ROOT)),
  'real_original_preserved':True,'all_declared_original_bytes_restorable':True,
  'elf_sections_installed_exactly':True,'capstone_independent_branch_decodes':decoded,
  'veneer_literals_match_symbols':True,'native_l1_unchanged':True,'cold_init_order_static_check':True,
  'bad_original_rejected':True,'bad_veneer_rejected':True,'existing_output_rejected':True,
  'boundaries':manifest['boundaries'],'linked_proof_flags':manifest['readiness']['linked_proof_flags']}
 (ROOT/'analysis/sound-port-cp-patcher-contract.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
 print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':main()
