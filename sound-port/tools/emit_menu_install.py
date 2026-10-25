"""Bind RV menu data and emit exact initializer/folder edits plus loader relocations.

Outputs are consumed by the parent AP ELF injector. This tool does not modify
the supplied appFw, build a firmware container, or communicate with a camera.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf


def integer(value):
    return int(value,0) if isinstance(value,str) else int(value)


def adrp_target(pc,word):
    if word&0x9f000000!=0x90000000:raise ValueError('Expected ADRP')
    imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2)
    if imm&0x100000:imm-=0x200000
    return (pc&~0xfff)+(imm<<12)


def encode_adrp(pc,target,old):
    pages=((target&~0xfff)-(pc&~0xfff))//4096
    if not -(1<<20)<=pages<(1<<20):raise ValueError('ADRP target out of range')
    imm=pages&0x1fffff
    word=(old&0x9f00001f)|((imm&3)<<29)|((imm>>2)<<5)
    if adrp_target(pc,word)!=(target&~0xfff):raise ValueError('ADRP encoding failed')
    return word


def build_install(menu_base:int,callbacks:dict[str,int],deferred=False):
    directory=ROOT/'sound-port/menu'
    meta=json.loads((directory/'metadata-manifest.json').read_text(encoding='utf8'))
    reloc=json.loads((directory/'rv_menu_metadata.relocations.json').read_text(encoding='utf8'))
    data=bytearray((directory/'rv_menu_metadata.data.bin').read_bytes())
    if menu_base&7 or menu_base<0x8fc0000 or menu_base+len(data)>0x9000000:
        raise ValueError('Menu data must fit the allocated aligned RV RW interval 0x8fc0000..0x9000000')
    symbols=reloc['symbols'];relative=[];unresolved=[]
    for row in reloc['relocations']:
        if row['target_kind']=='internal':value=menu_base+row['target_offset']
        elif row['target_kind']=='native':value=row['target_va']
        elif row['symbol'] in callbacks:value=callbacks[row['symbol']]+row['addend']
        else:
            unresolved.append(row);continue
        if not 0<value<0x100000000:raise ValueError('Non-RV address')
        struct.pack_into('<Q',data,row['offset'],value)
        relative.append({'r_offset':menu_base+row['offset'],'r_info':1027,'r_addend':value})
    if unresolved and not deferred:
        raise ValueError('Missing AP callback symbols: '+', '.join(sorted({r['symbol']for r in unresolved})))
    app=AppElf(ROOT/'analysis/targets/nflasha15/lib/appFw.so')
    patches=[]

    def edit(va:int,after:bytes,reason:str,before:bytes|None=None):
        off=app.offset(va);original=app.data[off:off+len(after)]
        if before is not None and original!=before:raise ValueError(f'Original bytes mismatch at {va:#x}')
        if any(va<r['va']+r['bytes'] and r['va']<va+len(after) for r in patches):raise ValueError('Overlapping menu edits')
        patches.append({'va':va,'file_offset':off,'bytes':len(after),'before_hex':original.hex(),
                        'after_hex':after.hex(),'reason':reason})

    def word_edit(va,word,reason):edit(va,struct.pack('<I',word),reason)

    def table_start(name,adrp,add,oldtarget):
        target=menu_base+symbols[f'rv_sound_replacement_{name}_registry']
        a,b=app.u32(adrp),app.u32(add)
        if b&0xff800000!=0x91000000 or b&(1<<22):raise ValueError('Expected unshifted ADD immediate')
        if adrp_target(adrp,a)+((b>>10)&0xfff)!=oldtarget:raise ValueError('Native table anchor mismatch')
        if (a&31)!=((b>>5)&31):raise ValueError('ADRP/ADD register mismatch')
        word_edit(adrp,encode_adrp(adrp,target,a),'Menu '+name+' registry page')
        word_edit(add,(b&~(0xfff<<10))|((target&0xfff)<<10),'Menu '+name+' registry offset')

    def mov_size(va,expected,value,name):
        old=app.u32(va)
        if old&0xff800000!=0xd2800000 or (old>>21)&3 or (old>>5)&0xffff!=expected or value>0xffff:
            raise ValueError('MOVZ size anchor mismatch '+name)
        word_edit(va,(old&~(0xffff<<5))|(value<<5),'Menu '+name+' registry byte span')

    def add_size(va,expected,value,name,shift=0):
        old=app.u32(va)
        if old&0xff800000!=0x91000000 or ((old>>22)&1)!=(shift//12) or (old>>10)&0xfff!=expected or value>0xfff:
            raise ValueError('ADD size anchor mismatch '+name)
        word_edit(va,(old&~(0xfff<<10))|(value<<10),'Menu '+name+' registry byte span')

    counts=meta['replacement_registry_counts']
    table_start('leaf',0x16f6554,0x16f6560,0x502a980)
    mov_size(0x16f655c,0x5c10,counts['leaf']*16,'leaf')
    table_start('option',0x16f65ec,0x16f65f0,0x5030590)
    span=counts['option']*16
    add_size(0x16f65f8,0x15,span>>12,'option high',12)
    add_size(0x16f6600,0xd70,span&0xfff,'option low')
    table_start('profile',0x16f6630,0x16f663c,0x5046300)
    mov_size(0x16f6634,0x3340,counts['profile']*16,'profile')
    table_start('parent',0x16f6674,0x16f667c,0x5049640)
    add_size(0x16f6680,0x740,counts['parent']*16,'parent')
    table_start('profile_alias',0x16f66b4,0x16f66c0,0x3e1ae10)
    mov_size(0x16f66b8,0x19a0,counts['profile_alias']*8,'profile_alias')
    table_start('option_owner',0x16f66f8,0x16f6704,0x3e1c7b0)
    mov_size(0x16f66fc,0xaeb8,counts['option_owner']*8,'option_owner')
    table_start('menu_profile',0x16f673c,0x16f6748,0x3e27668)
    mov_size(0x16f6740,0x31a8,counts['menu_profile']*8,'menu_profile')
    edit(0x5050de0,struct.pack('<I',13),'Shutter/Silent folder count 11 to 13',struct.pack('<I',11))
    reserved=bytearray()
    for index,slot in enumerate(('electronic','focus')):
        parent=menu_base+symbols[f'rv_{slot}_parent']
        reserved+=struct.pack('<IIQQ',1592+3*index,0,0,parent)
        relative.append({'r_offset':0x5050ef0+index*24+16,'r_info':1027,'r_addend':parent})
    edit(0x5050ef0,bytes(reserved),'Two custom sound parents in native zeroed capacity slots',bytes(48))
    result={'schema':1,'status':'DEFERRED_CALLBACK_BINDING' if unresolved else 'BOUND_INSTALL_DATA',
            'menu_base':menu_base,'menu_bytes':len(data),'menu_end':menu_base+len(data),
            'registry_counts':counts,'source_module':str(app.path.relative_to(ROOT)),
            'initializer_true_entry':0x16f6550,'code_and_folder_patches':sorted(patches,key=lambda r:r['va']),
            'loader_relative_relocations':sorted(relative,key=lambda r:r['r_offset']),
            'unresolved_callback_fixups':unresolved,'firmware_modified':False,'camera_io':False,
            'native_folder_capacity':30,'original_folder_count':11,'new_folder_count':13,
            'ui_runtime_callbacks_still_require_parent_ap_module':True}
    return bytes(data),result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=lambda v:int(v,0),required=True)
    p.add_argument('--callback-elf',type=Path,action='append',default=[])
    p.add_argument('--callbacks-json',type=Path)
    p.add_argument('--deferred',action='store_true',help='emit an explicitly unbound review plan')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();symbols={}
    for path in a.callback_elf:
        with path.open('rb')as f:
            e=ELFFile(f)
            for s in e.get_section_by_name('.symtab').iter_symbols():
                if s.name and s['st_shndx']!='SHN_UNDEF':symbols[s.name]=int(s['st_value'])
    if a.callbacks_json:
        symbols.update({k:integer(v)for k,v in json.loads(a.callbacks_json.read_text(encoding='utf8')).items()})
    blob,plan=build_install(a.base,symbols,a.deferred)
    if a.out.exists():raise ValueError('Choose a new output directory')
    a.out.mkdir(parents=True)
    (a.out/'menu.data.bin').write_bytes(blob)
    (a.out/'menu-install.json').write_text(json.dumps(plan,indent=2),encoding='utf8')
    print(json.dumps({'status':plan['status'],'bytes':len(blob),'edits':len(plan['code_and_folder_patches']),
                      'relative_relocations':len(plan['loader_relative_relocations']),
                      'unbound_callback_sites':len(plan['unresolved_callback_fixups'])},indent=2))


if __name__=='__main__':main()
