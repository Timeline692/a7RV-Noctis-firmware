"""Plan three expanded native UI caches and their GOT loader relocations."""
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf


def build_cache_install(base=0xB000000):
    if base%0x10000:raise ValueError('Cache LOAD must be page aligned')
    caches=[{'name':'option','got':0x5947A28,'original_va':0x74F1508,'entry_bytes':24,
             'original_entries':5591,'entries':5631,'offset':0},
            {'name':'profile','got':0x592BB18,'original_va':0x7532200,'entry_bytes':4,
             'original_entries':820,'entries':1600,'offset':0x21000},
            {'name':'leaf','got':0x5928070,'original_va':0x7532ED0,'entry_bytes':24,
             'original_entries':1589,'entries':1600,'offset':0x22900}]
    fixups=[]
    for c in caches:
        c['va']=base+c['offset'];c['bytes']=c['entries']*c['entry_bytes']
        fixups.append({'va':c['got'],'target_va':c['va'],
                       'expected_hex':c['original_va'].to_bytes(8,'little').hex()})
    for a,b in zip(caches,caches[1:]):
        if a['offset']+a['bytes']>b['offset']:raise ValueError('Cache objects overlap')
    end=max(c['offset']+c['bytes']for c in caches)
    e=AppElf(ROOT/'analysis/targets/nflasha15/lib/appFw.so')
    site=0x1bdfe5c;op=e.u32(site)
    # Original CCMP W28,W0,#0,NE; preceding CMP X1,#0 supplies NE.
    if op!=0x7a401380:raise ValueError(f'Cache gate opcode differs: {op:#x}')
    plan={'schema':1,'status':'OFFLINE_NATIVE_UI_CACHE_PLAN','load_va':base,
          'file_bytes':0,'memory_bytes':0x30000,'load_flags':6,'alignment':0x10000,
          'objects':caches,'relative_fixups':fixups,
          'native_initializer':'0x1bdfcc0',
          'initializer_contract':'three typed-map traversals initialize leaf, option and profile cache flags/pointers, including new registered IDs',
          'option_initializer_upper_bound':0x2b34,'new_max_option_alias':5630,
          'initializer_code_patch_needed':True,
          'initializer_hooks':[{'va':hex(site),'expected_hex':struct.pack('<I',op).hex(),
                                 'symbol':'csnd_rv_cache_bound_gate'}],
          'original_descriptor_count_scalar':{'got':'0x5954f58','va':'0x3e62224','value':1473,'unchanged':True},
          'private_bound_gate':{'ids':[1592,1599],'requires_native_setter':True,
                                'allow':'0x1bdfe64','blocked':'0x1bdfe70',
                                'original_items_keep_original_count_condition':True},
          'used_bytes':end,
          'camera_io':False,'complete_firmware':False}
    if end>plan['memory_bytes']:raise ValueError('Cache LOAD capacity exceeded')
    return b'',plan


if __name__=='__main__':
    _,plan=build_cache_install()
    (ROOT/'analysis/sound-port-menu-cache-plan.json').write_text(json.dumps(plan,indent=2),encoding='utf8')
    print(json.dumps({k:plan[k]for k in('status','load_va','memory_bytes','used_bytes','initializer_code_patch_needed')},indent=2))
