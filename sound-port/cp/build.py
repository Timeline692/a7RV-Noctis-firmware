"""Cross-compile the RV CP port; emit relocatable objects, never camera patches."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--zig',type=Path,default=ROOT/'toolchains/zig-x86_64-windows-0.15.2/zig.exe');p.add_argument('--incremental',action='store_true')
p.add_argument('--profile',choices=['offline','reference-codec-experimental'],default='offline');a=p.parse_args()
experimental=a.profile=='reference-codec-experimental'
out=ROOT/('sound-port/build/cp-reference-codec-experimental' if experimental else 'sound-port/build/cp');out.mkdir(parents=True,exist_ok=True)
report_path=ROOT/('analysis/sound-port-cp-reference-codec-experimental-build.json' if experimental else 'analysis/sound-port-cp-build.json')
static_admission=None
if experimental:
 manifest_path=ROOT/'sound-port/build/components/all-busy-mapped/cpapp-b.offline.bin.manifest.json'
 manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
 default_elf=ROOT/'sound-port/build/cp/cp-port-candidate.elf'
 transport=json.loads((ROOT/'sound-port/config/ap-rpc-contract.json').read_text(encoding='utf-8'))
 source=(HERE/'src/rv_cp_abi.c').read_text(encoding='utf-8')
 codec_path=ROOT/'sound-port/config/reference-codec.json'
 codec=json.loads(codec_path.read_text(encoding='utf-8'))
 addresses=[int(x.strip(),0) for x in re.search(r'\.busy_address\s*=\s*\{([^}]+)\}',source).group(1).split(',')]
 widths=[int(x.strip(),0) for x in re.search(r'\.busy_width\s*=\s*\{([^}]+)\}',source).group(1).split(',')]
 checks={
  'default_component_exact_elf':manifest['elf_sha256']==hashlib.sha256(default_elf.read_bytes()).hexdigest(),
  'all_11_native_busy_mapped':manifest['readiness']['all_11_busy_mapped'] and len(addresses)==11 and all(addresses),
  'source_busy_equals_verified_default':len(addresses)==len(widths)==11 and all(row=={'address':hex(address),'width':width}for row,address,width in zip(manifest['readiness']['busy_bindings'],addresses,widths)),
  'memory_overlay':manifest['module_header']['installed_page_permissions_verified'],
  'cold_zero_before_secondary':manifest['cold_init']['private_bss_cleared_before_release'],
  'nine_hook_transfer_contracts':len(manifest['hooks'])==9 and all(hook['branch_decode_verified']for hook in manifest['hooks']),
  'AP_RPC_native_bound':transport['status']=='AP_PLAYBACK_OBJECTS_COMPILED_NATIVE_TRANSPORT_BOUND' and transport['rpc']['context_bytes']==116 and transport['verification']['host_run_exit']==0,
  'static_codec_compatibility_evidence':codec['status']=='STATIC_COMPATIBILITY_EVIDENCE' and len(codec['function_windows'])==10 and all(w['normalized_equal'] and not w['differences'] for w in codec['function_windows']) and not codec['external_mapping_conflicts'] and codec['all_40_stock_sound_assets_equal'] and codec['hardware_audio_or_decoder_output_verified'] is False,
 }
 if not all(checks.values()):raise RuntimeError('Experimental static admission requirements failed: '+str(checks))
 static_admission={'checks':checks,'default_component_manifest':str(manifest_path.relative_to(ROOT)),
  'codec_bit':'explicit acceptance of reference-format0 compatibility inference, not native audibility proof','hardware':'NOT_TESTED'}
 static_admission['codec_evidence']=str(codec_path.relative_to(ROOT))
flags=['-target','thumb-freestanding-eabi','-mcpu=cortex_a8','-mfloat-abi=soft',
 '-Oz','-g','-ffreestanding','-fno-builtin','-fno-stack-protector',
 '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-I',str(HERE/'include')]
if experimental:flags+=['-DRV_CP_REFERENCE_CODEC_EXPERIMENTAL=1']
rows=[];objs=[]
def dependency_time(source,seen=None):
 seen=set() if seen is None else seen
 if source in seen:return 0
 seen.add(source);latest=source.stat().st_mtime_ns
 for name in re.findall(r'^\s*#\s*include\s*"([^"]+)"',source.read_text(encoding='utf-8'),re.M):
  header=next((q for q in (source.parent/name,HERE/'include'/name) if q.exists()),None)
  if header is not None:latest=max(latest,dependency_time(header,seen))
 return latest
for src in sorted((HERE/'src').iterdir()):
 if src.suffix not in ('.c','.S'):continue
 obj=out/(src.stem+'.o');cmd=[str(a.zig),'cc',*flags,'-c',str(src),'-o',str(obj)]
 if a.incremental and obj.exists() and obj.stat().st_mtime_ns>=dependency_time(src):
  rows.append({'source':str(src.relative_to(ROOT)),'object':str(obj.relative_to(ROOT)),'returncode':0,'reused':True});objs.append(obj);print(src.name,'REUSED');continue
 r=subprocess.run(cmd,capture_output=True,text=True);rows.append({'source':str(src.relative_to(ROOT)),'object':str(obj.relative_to(ROOT)),'returncode':r.returncode,'stderr':r.stderr,'reused':False})
 print(src.name,'OK' if not r.returncode else r.stderr)
 if r.returncode:
  report_path.write_text(json.dumps({'status':'COMPILE_FAILED','profile':a.profile,'objects':rows},indent=2),encoding='utf-8');raise SystemExit(r.returncode)
 objs.append(obj)
archive=out/'libsound_cp.a'
r=subprocess.run([str(a.zig),'ar','rcs',str(archive),*[str(v) for v in objs]],capture_output=True,text=True)
report={'status':'OBJECTS_COMPILED' if not r.returncode else 'ARCHIVE_FAILED','profile':a.profile,'experimental':experimental,'admission_mask':63 if experimental else 0,
 'static_admission':static_admission,'hardware':'NOT_TESTED','compiler':str(a.zig),'target_flags':flags,'objects':rows,'archive':str(archive.relative_to(ROOT)),
 'deployable':False,'link_layout':'sound-port/cp/layout.ld',
 'remaining_boundaries':['referenceF0 native decoder compatibility is inferred; accepted only by explicit experimental profile','outer CP file/NOR transfer capacity','AP328-to-CP202 intermediate IPC proxy not individually traced','camera execution/audibility not tested']}
report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
if r.returncode:print(r.stderr);raise SystemExit(r.returncode)
print(report['status'],archive)
elf=ROOT/'sound-port/build/cp-reference-codec-experimental.elf' if experimental else out/'cp-port-candidate.elf'
cmd=[str(a.zig),'cc',*flags,'-Wl,--build-id=none','-Wl,-e,rv_cp_cold_zero_hook','-Wl,-T,'+str(HERE/'layout-candidate.ld'),*[str(v) for v in objs],'-o',str(elf)]
r=subprocess.run(cmd,capture_output=True,text=True)
report['candidate_link']={'returncode':r.returncode,'stderr':r.stderr,'elf':str(elf.relative_to(ROOT)),'deployable':False}
if not r.returncode:report['status']='CANDIDATE_ELF_LINKED'
report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(report['status'],r.stderr)
raise SystemExit(r.returncode)
