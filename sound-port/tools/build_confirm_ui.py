"""Copy both exact RV confirmation layouts, replacing only the sound prompt ID."""
from pathlib import Path
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf
e=AppElf(ROOT/'analysis/targets/nflasha15/lib/appFw.so')
sources=[e.ptr(0x5973728),e.ptr(0x594bbd0)]
assert sources==[0x41d8ec8,0x41d8c88]
hook={'va':'0x1e48c44','expected_hex':'620a00f9','symbol':'rv_ui_confirm_entry'}
assert e.data[e.offset(0x1e48c44):e.offset(0x1e48c44)+4].hex()==hook['expected_hex']
assert not [at for at in e.reloc_target_to_addend if any(a<=at<a+0x240 for a in sources)]
rows=[];blocks=[]
for orientation,source in enumerate(sources):
 native=e.data[e.offset(source):e.offset(source)+0x240]
 assert struct.unpack_from('<II',native,0x68)==(2,0x2006219)
 for variant,textid in enumerate((0x200ab61,0x200ab62,0x200ab63),1):
  block=bytearray(native);struct.pack_into('<I',block,0x6c,textid)
  assert block[:0x6c]==native[:0x6c] and block[0x70:]==native[0x70:]
  words=struct.unpack('<144I',block);blocks.append(words)
  rows.append({'orientation_index':orientation,'native_layout':hex(source),'variant':variant,'bytes':len(block),
   'prompt_offset':'0x6c','old_text_id':'0x2006219','text_id':hex(textid),'original_sha256':hashlib.sha256(native).hexdigest(),
   'modified_sha256':hashlib.sha256(block).hexdigest(),'all_other_bytes_identical':True,'internal_pointer_relocations':0})
ui=ROOT/'sound-port/ap/ui';(ui/'src').mkdir(parents=True,exist_ok=True)
out=['/* Generated solely from RV native templates; 6 complete0x240-byte layouts. */','#include "rv_confirm_ui.h"',
 'const uint32_t rv_confirm_layouts[2][3][RV_CONFIRM_LAYOUT_WORDS] __attribute__((aligned(8)))={']
for orientation in range(2):
 out.append(' {')
 for variant in range(3):
  out.append('  {')
  words=blocks[orientation*3+variant]
  out+=['   '+','.join(f'0x{x:08x}u'for x in words[at:at+8])+',' for at in range(0,len(words),8)]
  out.append('  },')
 out.append(' },')
out.append('};')
(ui/'src/rv_confirm_layouts.c').write_text('\n'.join(out)+'\n',encoding='utf-8')
# Same complete native-ABI preservation frame as the installed scheduler hook.
asm=(ROOT/'sound-port/ap/scheduler/rv_scheduler_post.S').read_text(encoding='utf-8')
asm=asm.replace('rv_ap_postexecute_entry','rv_ui_confirm_entry').replace('rv_ap_postexecute_resume','rv_ui_confirm_resume')
asm=asm.replace('    mov x0, x23\n    mov x1, x20\n    bl csnd_maintenance_after_execute',
 '    mov x0, x2\n    mov w1, w22\n    mov w2, w20\n    mov w3, w5\n    bl rv_confirm_select_layout\n    str x0, [sp, #16]')
asm=asm.replace('    mov w0, w22','    str x2, [x19, #16]')
(ui/'src/rv_confirm_entry.S').write_text('/* Constructor interior hook: preserve GPR/SIMD/NZCV/FPCR/FPSR, select, replay STR. */\n'+asm,encoding='utf-8')
report={'status':'RV_PRIVATE_CONFIRM_LAYOUTS_SOURCE_BOUND','template_size':'0x240','reference_m4_size_not_reused':'0x208',
 'native_constructor':'0x1e48be0','select_site':'0x1e48c38','hook':hook,'resume':'0x1e48c48',
 'native_consumers':['0x1b2ae4c','0x1bc3304','view vtable+0x10'],'templates':rows,
 'selection_guard':'exact native pointer + scene174/layer<6 + live GUI-thread private flow + validated selection',
 'preservation':'784B frame: x0..x30,32xQ,NZCV,FPCR,FPSR; only savedx2 substituted before replaying nativeSTR',
 'relative_fixups':[],'bindings_ld':'sound-port/ap/ui/rv_ui_bindings.ld','hooks':[hook],
 'sources':['sound-port/ap/ui/src/rv_confirm_layouts.c','sound-port/ap/ui/src/rv_confirm_select.c','sound-port/ap/ui/src/rv_confirm_entry.S'],
 'data_bytes':6*0x240,'native_lut_layouts_changed':False,'device_ui_execution':'NOT_TESTED'}
(ROOT/'analysis/sound-ui-confirm-bindings.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(report['status'],report['data_bytes'])
