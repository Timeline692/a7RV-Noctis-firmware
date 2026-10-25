"""Check expanded native UI cache LOAD, GOT relocations and its narrow ARM gate."""
import io
import json
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile
from build_common import ROOT,run
from emit_menu_cache import build_cache_install
from emit_menu_install import build_install
from patch_ap_elf import patch,RW_BASE
sys.path.insert(0,str(ROOT/'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf


def branch_target(pc,word):
    immediate=word&0x3ffffff
    if immediate&0x2000000:immediate-=0x4000000
    return pc+immediate*4


def run_gate(code,pc,mid,pointer,limit):
    start=pc;registers={0:limit&0xffffffff,1:pointer,28:mid&0xffffffff};flags=(0,0,0,0)
    def subtract(a,b):
        a&=0xffffffff;b&=0xffffffff;r=(a-b)&0xffffffff
        return (r>>31,r==0,a>=b,((a^b)&(a^r))>>31)
    for _ in range(20):
        if not start<=pc<start+len(code):return pc
        word=struct.unpack_from('<I',code,pc-start)[0];nextpc=pc+4
        if word&0x7f000000==0x34000000:
            immediate=(word>>5)&0x7ffff
            if immediate&0x40000:immediate-=0x80000
            if not registers.get(word&31,0):nextpc=pc+immediate*4
        elif word&0xff000010==0x54000000:
            n,z,c,v=flags;condition=word&15
            take={3:not c,9:not c or z,10:n==v}[condition]
            immediate=(word>>5)&0x7ffff
            if immediate&0x40000:immediate-=0x80000
            if take:nextpc=pc+immediate*4
        elif word&0x7f00001f==0x7100001f:
            flags=subtract(registers[(word>>5)&31],(word>>10)&0xfff)
        elif word&0x7fe0fc1f==0x6b00001f:
            flags=subtract(registers[(word>>5)&31],registers[(word>>16)&31])
        elif word&0xfc000000==0x14000000:nextpc=branch_target(pc,word)
        else:raise AssertionError(f'Unexpected gate opcode {word:#x}')
        pc=nextpc
    raise AssertionError('Gate did not terminate')


def main():
    directory=ROOT/'sound-port/build/menu-cache-contract'
    directory.mkdir(parents=True,exist_ok=True)
    ap=ROOT/'sound-port/build/ap/rv-sound-ap.elf'
    modules=[('RV_SOUND_AP',ap.read_bytes())]
    callbacks={}
    for name,data in modules:
        e=ELFFile(io.BytesIO(data))
        for symbol in e.get_section_by_name('.symtab').iter_symbols():
            if (symbol.name and symbol['st_shndx']!='SHN_UNDEF' and
                (symbol['st_info']['bind']in('STB_GLOBAL','STB_WEAK')or symbol['st_other']['visibility']=='STV_HIDDEN')):
                callbacks[symbol.name]=int(symbol['st_value'])
    # Actual gate machine code, not just the equivalent Python condition.
    e=ELFFile(io.BytesIO(modules[0][1]));text=e.get_section_by_name('.text');gateva=callbacks['csnd_rv_cache_bound_gate']
    gatesymbol=next(s for s in e.get_section_by_name('.symtab').iter_symbols()if s.name=='csnd_rv_cache_bound_gate')
    gateoff=gateva-int(text['sh_addr']);gatecode=text.data()[gateoff:gateoff+int(gatesymbol['st_size'])];cases=0
    for mid in[-1,0,1472,1473,1588,1591,*range(1592,1600),1600,0xca4]:
        for pointer in(0,1):
            expected=0x1bdfe64 if pointer and (1592<=mid<=1599 or mid<1473)else 0x1bdfe70
            assert run_gate(gatecode,gateva,mid,pointer,1473)==expected;cases+=1
    blob,menu=build_install(RW_BASE,callbacks);cache=build_cache_install();cacheplan=cache[1]
    originalpath=ROOT/'analysis/targets/nflasha15/lib/appFw.so';stamp=originalpath.stat().st_mtime_ns
    original=AppElf(originalpath)
    bindings=json.loads((ROOT/'sound-port/config/controller-hooks.json').read_text(encoding='utf8'))
    hooks=list(bindings['hooks'])
    for va,symbol in[(0x3556198,'rv_ap_exposure_entry'),(0x3255fa0,'rv_ap_postexecute_entry')]:
        off=original.offset(va);hooks.append({'va':hex(va),'expected_hex':original.data[off:off+4].hex(),'symbol':symbol})
    payload,report=patch(original.data,modules,hooks,bindings.get('relative_fixups',()),menu_install=(blob,menu),cache_install=cache)
    final=ELFFile(io.BytesIO(payload));loads=[p for p in final.iter_segments()if p['p_type']=='PT_LOAD']
    cacheload,=[p for p in loads if p['p_vaddr']==cacheplan['load_va']]
    assert cacheload['p_flags']==6 and cacheload['p_filesz']==0 and cacheload['p_memsz']==0x30000
    relocations={}
    for r in final.get_section_by_name('.rela.dyn').iter_relocations():
        if int(r['r_offset'])in [c['got']for c in cacheplan['objects']]:
            assert r['r_info_type']==1027
            relocations[int(r['r_offset'])]=int(r['r_addend'])
    assert relocations=={c['got']:c['va']for c in cacheplan['objects']},(relocations,cacheplan['objects'])
    assert struct.unpack_from('<I',payload,original.offset(0x3e62224))[0]==1473
    hookoff=original.offset(0x1bdfe5c)
    assert branch_target(0x1bdfe5c,struct.unpack_from('<I',payload,hookoff)[0])==gateva
    for hook in report['hooks']:
        va=int(hook['va'],0);word=struct.unpack_from('<I',payload,original.offset(va))[0]
        assert word&0xfc000000==(0x94000000 if hook.get('link',False)else 0x14000000)
        target=callbacks[hook['symbol']]if 'symbol'in hook else int(hook['target_va'],0)
        assert branch_target(va,word)==target
    manifest=json.loads((ROOT/'sound-port/menu/rv_menu_metadata.relocations.json').read_text(encoding='utf8'))
    counts=menu['registry_counts'];objects={c['name']:c for c in cacheplan['objects']}
    initial={name:bytearray(c['bytes'])for name,c in objects.items()}
    def read(va,n):
        if RW_BASE<=va and va+n<=RW_BASE+len(blob):return blob[va-RW_BASE:va-RW_BASE+n]
        off=original.offset(va);return original.data[off:off+n]
    def u64(va):return struct.unpack('<Q',read(va,8))[0]
    def rows(name):
        off=manifest['symbols']['rv_sound_replacement_'+name+'_registry']
        return [struct.unpack_from('<IIQ',blob,off+i*16)for i in range(counts[name])]
    private_leaf=private_profile=0
    for mid,_,pointer in rows('leaf'):
        assert mid*24+24<=len(initial['leaf'])
        entry=initial['leaf'];at=mid*24
        entry[at]=bool(u64(pointer+0x80)and u64(pointer+0xa8));entry[at+1]=bool(u64(pointer+0xb0));entry[at+4]=bool(u64(pointer+0x78))
        option=u64(pointer+0x58)
        if option:
            alias=struct.unpack('<I',read(option+4,4))[0]
            assert alias*24+24<=len(initial['option'])
            struct.pack_into('<Q',entry,at+16,objects['option']['va']+alias*24)
        if 1592<=mid<=1599:private_leaf+=1
    for mid,_,pointer in rows('profile'):
        assert mid*4+4<=len(initial['profile'])
        initial['profile'][mid*4]=bool(u64(pointer+0x50))
        if 1592<=mid<=1599:
            assert initial['profile'][mid*4]==1;private_profile+=1
    for alias,_,pointer in rows('option'):
        assert alias*24+24<=len(initial['option'])
    assert private_leaf==6 and private_profile==8
    assert originalpath.stat().st_mtime_ns==stamp
    component=directory/'RV_SOUND_OFFLINE_COMPONENT.appFw.so'
    with component.open('xb')as f:f.write(payload)
    report.update(component_only=True,complete_firmware=False,output=str(component.relative_to(ROOT)))
    (directory/'component-manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    result={'schema':1,'status':'PASS','scope':'offline native cache/ELF contract',
            'three_got_relative_redirects':relocations,'cache_load_filesz':0,'cache_load_memsz':0x30000,
            'cache_objects_fit':True,'existing_count1473_unchanged':True,
            'actual_gate_opcode_interpreter_cases':cases,
            'native_map_initialization_simulation':{'private_leaves':private_leaf,'private_profiles':private_profile,
               'all_registered_option_indices_fit':True,'default_option_pointers_use_expanded_option_cache':True},
            'original_source_unchanged':True,'menu_relocations':len(menu['loader_relative_relocations']),
            'actual_runtime_module':str(ap.relative_to(ROOT)),'all_entry_hooks':len(report['hooks']),
            'linked_callsite_hooks':sum(bool(r.get('link',False))for r in report['hooks']),
            'device_execution':'NOT_TESTED','complete_firmware':False,
            'output':str(component.relative_to(ROOT)),'component_only':True}
    (ROOT/'analysis/sound-port-menu-cache-contract.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
