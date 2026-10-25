"""Build the actual RV AArch64 extension; unresolved bindings are fatal."""
from pathlib import Path
import argparse
import json
import re
import subprocess
from elftools.elf.elffile import ELFFile

ROOT=Path(__file__).resolve().parents[2]
ZIG=ROOT/'toolchains/zig-x86_64-windows-0.15.2/zig.exe'
OUT=ROOT/'sound-port/build/ap'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--incremental',action='store_true')
    args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    includes=[ROOT/'sound-port/ap/runtime/include',ROOT/'sound-port/ap/shim',
              ROOT/'sound-port/ap/scheduler',ROOT/'sound-port/common/include',
              ROOT/'sound-port/ap/playback/include',ROOT/'sound-port/ap/ui/include']
    sources=[]
    for directory in ['runtime/src','volume/src','shim','scheduler','playback/src','ui/src']:
        for source in sorted((ROOT/'sound-port/ap'/directory).glob('*')):
            if source.suffix in ('.c','.S') and not source.name.startswith('test_'):sources.append(source)
    sources.append(ROOT/'sound-port/ap/runtime/rv_controller_trampolines.S')
    sources.append(ROOT/'sound-port/common/src/audio_convert.c')
    flags=['-target','aarch64-freestanding-none','-O2','-std=c11',
           '-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
           '-fno-stack-protector','-fno-pic','-fno-pie','-fvisibility=hidden',
           '-mno-outline-atomics','-mgeneral-regs-only','-fno-unwind-tables',
           '-fno-asynchronous-unwind-tables']+['-I'+str(p) for p in includes]
    def newest_dependency(source,seen=None):
        seen=set() if seen is None else seen
        if source in seen:return 0
        seen.add(source);newest=source.stat().st_mtime_ns
        for name in re.findall(r'^\s*#\s*include\s*[<"]([^>"\n]+)',source.read_text(encoding='utf-8',errors='replace'),re.M):
            for candidate in [source.parent/name,*[folder/name for folder in includes]]:
                if candidate.is_file():
                    newest=max(newest,newest_dependency(candidate,seen));break
        return newest
    flagsfile=OUT/'compile-flags.json'
    flags_changed=flagsfile.exists() and json.loads(flagsfile.read_text(encoding='utf-8'))!=flags
    objects=[];report={'schema':1,'status':'COMPILING','objects':[],'camera_execution':'NOT_TESTED','incremental':args.incremental}
    for source in sources:
        name='_'.join(source.relative_to(ROOT/'sound-port').parts)
        obj=OUT/(name+'.o')
        legacy_flags=['-Wno-unused-parameter','-Wno-unused-function'] if 'playback' in source.parts else []
        cmd=[str(ZIG),'cc',*flags,*legacy_flags,'-c',str(source),'-o',str(obj)]
        if args.incremental and not flags_changed and obj.exists() and obj.stat().st_mtime_ns>=newest_dependency(source):
            objects.append(obj);report['objects'].append({'source':str(source.relative_to(ROOT)),'returncode':0,'reused':True});continue
        r=subprocess.run(cmd,capture_output=True,text=True)
        (OUT/(name+'.log')).write_text(r.stdout+r.stderr,encoding='utf-8')
        report['objects'].append({'source':str(source.relative_to(ROOT)),'returncode':r.returncode})
        if r.returncode:report['status']='COMPILE_FAILED';break
        objects.append(obj)
    else:
        bindings=(ROOT/'sound-port/ap/runtime/rv_verified_bindings.ld').read_text(encoding='utf-8')
        bindings+=(ROOT/'sound-port/ap/runtime/rv_cache_bindings.ld').read_text(encoding='utf-8')
        bindings+=(ROOT/'sound-port/ap/scheduler/rv_scheduler_bindings.ld').read_text(encoding='utf-8')
        playback=ROOT/'sound-port/ap/playback/rv_playback_bindings.ld'
        if playback.exists():bindings+=playback.read_text(encoding='utf-8')
        ui=ROOT/'sound-port/ap/ui/rv_ui_bindings.ld'
        if ui.exists():bindings+=ui.read_text(encoding='utf-8')
        layout=OUT/'layout.ld'
        layout.write_text(bindings+'''\nENTRY(rv_ap_exposure_entry)
SECTIONS {
 .text 0x8f92000 : { *(.text.rv_gui_trampolines) *(.text*) }
 .rodata : { *(.rodata*) }
 ASSERT(. <= 0x8fc0000, "AP RX capacity exceeded")
 .data 0x8ff2000 : { *(.data*) *(.sdata*) }
 .bss (NOLOAD) : { *(.bss*) *(COMMON) }
 ASSERT(. <= 0x9000000, "AP RW state capacity exceeded")
 /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
}
''',encoding='utf-8')
        elf=OUT/'rv-sound-ap.elf'
        r=subprocess.run([str(ZIG),'cc',*flags,'-nostdlib','-static',
            '-Wl,--build-id=none','-Wl,--no-gc-sections','-Wl,--no-undefined',
            '-Wl,-e,rv_ap_exposure_entry',
            '-Wl,-T,'+str(layout),*[str(o) for o in objects],'-o',str(elf)],capture_output=True,text=True)
        (OUT/'link.log').write_text(r.stdout+r.stderr,encoding='utf-8')
        report['status']='LINK_FAILED' if r.returncode else 'LINKED_RV_AP_EXTENSION'
        report['link_error']=r.stderr
        if not r.returncode:
            with elf.open('rb') as f:
                e=ELFFile(f)
                report['sections']=[{'name':s.name,'va':hex(s['sh_addr']),'size':s['sh_size']} for s in e.iter_sections() if s['sh_flags']&2]
                report['undefined']=[s.name for s in e.get_section_by_name('.symtab').iter_symbols() if s.name and s['st_shndx']=='SHN_UNDEF']
            report['elf']=str(elf.relative_to(ROOT))
            flagsfile.write_text(json.dumps(flags,indent=2),encoding='utf-8')
    (ROOT/'analysis/sound-port-ap-build.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='objects'},ensure_ascii=False))
    raise SystemExit(0 if report['status']=='LINKED_RV_AP_EXTENSION' else 1)

if __name__=='__main__':main()
