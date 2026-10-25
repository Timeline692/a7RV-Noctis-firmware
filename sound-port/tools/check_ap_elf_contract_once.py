"""One offline ELF contract check with real menu data and two callback fixtures.

The small callback fixtures exercise ELF binding only. They are not a camera
runtime and the generated component must not be used as a camera update.
"""
from __future__ import annotations
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from build_common import ROOT, run
from emit_menu_install import build_install
from patch_ap_elf import patch, RW_BASE, RX_BASE, RX_END, RW_END


def main():
    out=ROOT/'sound-port/build/patcher-contract-fixture'
    out.mkdir(parents=True,exist_ok=True)
    sourcepath=ROOT/'analysis/targets/nflasha15/lib/appFw.so'
    source=sourcepath.read_bytes();before_stat=sourcepath.stat()
    original=ELFFile(io.BytesIO(source))
    meta=json.loads((ROOT/'sound-port/menu/metadata-manifest.json').read_text(encoding='utf8'))
    zig=ROOT/'toolchains/zig-x86_64-windows-0.15.2/zig.exe'
    names=meta['callback_bindings']
    batches=[names[:8]+names[16:],names[8:16]]
    modules=[];symbols={};builds=[]
    for i,batch in enumerate(batches):
        c=out/f'callback-fixture-{i}.c';linker=out/f'callback-fixture-{i}.ld';elfpath=out/f'callback-fixture-{i}.elf'
        # Repeated LOCAL symbol names are deliberate: independent modules may
        # each have a static helper without conflicting with exported callbacks.
        c.write_text('#include <stdint.h>\nstatic volatile uint32_t marker=7;\n'
                     'static volatile uint32_t zero_state;\n'
                     '__attribute__((noinline)) static uint32_t local_helper(uint32_t v){return v+marker+zero_state;}\n'
                     +'\n'.join(f'uint32_t {name}(uint32_t v){{return local_helper(v);}}'for name in batch)+'\n',encoding='utf8')
        linker.write_text(f'SECTIONS {{ .text 0x{RX_BASE+0x1000+i*0x1000:x} : {{ *(.text*) *(.rodata*) }} '
                          f'.data 0x{0x8ff2000+i*0x1000:x} : {{ *(.data*) }} .bss (NOLOAD) : {{ *(.bss*) }} '
                          '/DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) } }',encoding='utf8')
        command=[str(zig),'cc','-target','aarch64-freestanding-none','-mgeneral-regs-only',
                 '-mno-outline-atomics','-ffreestanding','-fno-builtin','-fno-stack-protector',
                 '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-pic','-fno-pie',
                 '-O2','-nostdlib','-Wl,--build-id=none','-Wl,-T,'+str(linker),'-Wl,-e,'+batch[0],str(c),'-o',str(elfpath)]
        result=run(command,out/f'compile-{i}.log');builds.append(result)
        if result['exit_code']:raise RuntimeError('Callback fixture did not link')
        data=elfpath.read_bytes();modules.append((f'CALLBACK_FIXTURE_{i}',data))
        e=ELFFile(io.BytesIO(data))
        for s in e.get_section_by_name('.symtab').iter_symbols():
            if s.name and s['st_shndx']!='SHN_UNDEF' and s['st_info']['bind'] in('STB_GLOBAL','STB_WEAK'):
                symbols[s.name]=int(s['st_value'])
    blob,plan=build_install(RW_BASE,symbols)
    assert plan['status']=='BOUND_INSTALL_DATA' and not plan['unresolved_callback_fixups']
    oldrela=original.get_section_by_name('.rela.dyn');oldpayload=oldrela.data()
    loads=[p for p in original.iter_segments()if p['p_type']=='PT_LOAD']
    replacement=None
    for at in range(0,len(oldpayload),24):
        location,kind,addend=struct.unpack_from('<QQq',oldpayload,at)
        if kind==1027 and location%8==0:
            for p in loads:
                if p['p_flags']&2 and p['p_vaddr']<=location and location+8<=p['p_vaddr']+p['p_filesz']:
                    off=p['p_offset']+location-p['p_vaddr']
                    replacement={'va':location,'target_va':symbols[names[0]],'expected_hex':source[off:off+8].hex()}
                    replacement_index=at;break
        if replacement:break
    assert replacement is not None
    payload,report=patch(source,modules,[],[replacement],menu_install=(blob,plan))
    final=ELFFile(io.BytesIO(payload));newrela=final.get_section_by_name('.rela.dyn')
    actual=newrela.data();expected_prefix=bytearray(oldpayload)
    struct.pack_into('<QQq',expected_prefix,replacement_index,replacement['va'],1027,replacement['target_va'])
    assert actual[:len(oldpayload)]==expected_prefix
    assert len(actual)==len(oldpayload)+len(plan['loader_relative_relocations'])*24
    expected={r['r_offset']:r['r_addend']for r in plan['loader_relative_relocations']}
    appended={}
    for at in range(len(oldpayload),len(actual),24):
        location,kind,target=struct.unpack_from('<QQq',actual,at)
        assert kind==1027 and location not in appended
        appended[location]=target
    assert appended==expected
    tags={t.entry.d_tag:t.entry.d_val for t in final.get_section_by_name('.dynamic').iter_tags()}
    assert tags['DT_RELA']==newrela['sh_addr'] and tags['DT_RELASZ']==newrela['sh_size']
    assert tags['DT_RELAENT']==24
    newloads=[p for p in final.iter_segments()if p['p_type']=='PT_LOAD']

    def offset(va,size=1):
        p,=[p for p in newloads if p['p_vaddr']<=va and va+size<=p['p_vaddr']+p['p_filesz']]
        return p['p_offset']+va-p['p_vaddr']

    for r in plan['loader_relative_relocations']:
        assert struct.unpack_from('<Q',payload,offset(r['r_offset'],8))[0]==r['r_addend']
    for r in plan['code_and_folder_patches']:
        at=offset(r['va'],r['bytes'])
        assert payload[at:at+r['bytes']].hex()==r['after_hex']
    for section in report['sections']:
        if section['zero_initialized']:
            assert not any(payload[int(section['offset'],0):int(section['offset'],0)+section['size']])
    rela_segment,=[p for p in newloads if p['p_vaddr']==newrela['sh_addr']]
    assert rela_segment['p_flags']==4 and rela_segment['p_filesz']==newrela['sh_size']
    phdr,=[p for p in final.iter_segments()if p['p_type']=='PT_PHDR']
    assert phdr['p_offset']==final['e_phoff'] and phdr['p_filesz']==final['e_phnum']*56
    assert sourcepath.stat().st_mtime_ns==before_stat.st_mtime_ns and sourcepath.stat().st_size==len(source)
    component=out/'CALLBACK_FIXTURE_ONLY.appFw.so'
    with component.open('xb')as f:f.write(payload)
    report.update(fixture_only=True,fixture_callbacks_are_camera_runtime=False,
                  output=str(component.relative_to(ROOT)))
    (out/'component-manifest.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    result={'schema':1,'status':'PASS','scope':'offline ELF/container contract only',
            'real_rv_menu_bytes':len(blob),'menu_relocations':len(expected),
            'replacement_existing_relative':1,'total_requested_relative_fixups':report['relative_fixups'],
            'original_rela_prefix_preserved_except_declared_replacement':True,
            'exact_menu_edits_verified':len(plan['code_and_folder_patches']),
            'all_pointer_qwords_match_addends':True,'dynamic_section_view_and_readonly_load_agree':True,
            'two_modules_with_duplicate_local_symbol_names_accepted':True,
            'original_source_file_unchanged':True,'callback_fixture_builds':builds,
            'output':str(component.relative_to(ROOT)),'fixture_only':True,
            'complete_firmware':False,'device_execution':'NOT_TESTED'}
    (ROOT/'analysis/sound-port-ap-elf-contract.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in result.items()if k!='callback_fixture_builds'},indent=2))


if __name__=='__main__':main()
