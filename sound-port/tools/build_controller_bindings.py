"""Emit RV native GUI entry trampolines with exact instruction guards."""
from pathlib import Path
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf

def main():
    elf=AppElf(ROOT/'analysis/targets/nflasha15/lib/appFw.so')
    config=json.loads((ROOT/'sound-port/config/menu-native-inputs.json').read_text(encoding='utf-8'))
    rows=config['hooks']
    for name,va in [('menu_route',0x21dd740),('submenu_render',0x21df4c0),('event',0x1998890)]:
        first=elf.data[elf.offset(va):elf.offset(va)+4].hex()
        rows.append({'name':'csnd_original_'+name,'rv_candidate':hex(va),
                     'displaced_first_instruction':first,'native_pointer_refs':[]})
    assembly=['/* RV 4.00, one displaced instruction per entry. */','.section .text.rv_gui_trampolines,"ax",%progbits','.p2align 2']
    hooks=[];resumes={}
    for row in rows:
        name=row['name']
        va=0x1ce7790 if name=='csnd_original_file_snapshot' else int(row['rv_candidate'],16)
        first=elf.data[elf.offset(va):elf.offset(va)+4]
        if name!='csnd_original_file_snapshot' and first.hex()!=row['displaced_first_instruction']:
            raise ValueError(f'{name}: first instruction no longer matches')
        word=struct.unpack('<I',first)[0]
        # All displaced instructions in this set are SP-relative stores/loads,
        # ADD immediates or MOV immediates. Relocating ADR/branch/literal reads
        # requires a separate implementation and cannot be copied unchanged.
        if word&0x9f000000 in (0x10000000,0x90000000) or word>>26 in (5,37) or word&0x3b000000==0x18000000:
            raise ValueError('PC-relative displaced instruction')
        suffix=name.removeprefix('csnd_original_')
        if suffix=='event':target='csnd_ui_event'
        elif suffix.endswith('_ctor'):target='csnd_controller_ctor_'+suffix.removesuffix('_ctor')
        elif suffix.endswith('_dtor'):target='csnd_controller_dtor_'+suffix.removesuffix('_dtor')
        elif suffix=='file_snapshot':target='csnd_controller_snapshot_thunk'
        else:target='csnd_controller_'+suffix
        resume='rv_native_resume_'+suffix
        resumes[resume]=va+4
        assembly += ['.global '+name,'.hidden '+name,'.type '+name+',%function',name+':',
                     '    .word '+hex(word),'    b '+resume,'.size '+name+', .-'+name]
        hooks.append({'va':hex(va),'expected_hex':first.hex(),'symbol':target,
                      'original_trampoline':name,'native_pointer_refs':row['native_pointer_refs']})
    dst=ROOT/'sound-port/ap/runtime'
    (dst/'rv_controller_trampolines.S').write_text('\n'.join(assembly)+'\n',encoding='utf-8')
    constants={'csnd_native_controller_arena':0x7546208,'csnd_native_presenter_slots':0x75461d8,
               'csnd_native_file_presenter_vtable':0x58cd4d8,'csnd_native_confirm_presenter_vtable':0x58cd530,
               'csnd_native_controller_state':0x1af11f0,'csnd_native_controller_set_state':0x1af3cdc,
               'csnd_native_base_construct':0x30c01dc,'csnd_native_base_destroy':0x30bed38,
               'csnd_native_sequence_rtti':0x58f6cc0,'csnd_native_empty_cancel':0x30bea30,
               'csnd_native_empty_finish':0x30bea34,'csnd_native_silent_get':0x1c3413c,
               'csnd_native_audio_get':0x1c0dcbc,'csnd_native_focus_get':0x1c23624,
               'csnd_native_shutter_60a_get':0x1bfadc0,'csnd_pthread_self':0x16dcc70}
    constants.update({'csnd_native_menu_mid':0x28a8720,
                      'csnd_native_submenu_presenter_vtable':0x58c1508,
                      'csnd_native_menu_body':0x1bc32b8,
                      'csnd_native_text_item':0x1834410,
                      'csnd_native_assign_text':0x1817bfc})
    constants['csnd_native_snprintf']=0x16da2d0
    constants.update({'csnd_parent_parameter':0x28a86d0,
                      'csnd_original_profile_update':0x1bdf83c,
                      'csnd_original_parent_refresh':0x21de284,
                      'rv_ap_exposure_resume':0x355619c})
    imports=config['imports']
    names={'__errno_location':'errno','dlsym':'native_dlsym'}
    for item in imports:
        if item['name'].startswith('Fsys_'):continue
        constants['csnd_'+names.get(item['name'],item['name'])]=int(item['plt'],16)
    (dst/'rv_verified_bindings.ld').write_text('/* Verified RV bindings; incomplete platform map. */\n'+
        '\n'.join(f'{name} = {va:#x};' for name,va in (constants|resumes).items())+'\n',encoding='utf-8')
    for va,target,symbol in [(0x23787a8,0x1817bfc,'csnd_rv_row_name_draw'),
                             (0x23791b8,0x16da2d0,'csnd_rv_confirmation_name_draw')]:
        word=elf.u32(va)
        destination=va+(((word&0x3ffffff)^0x2000000)-0x2000000)*4
        if word>>26!=37 or destination!=target:raise ValueError('Native name draw call differs')
        hooks.append({'va':hex(va),'expected_hex':word.to_bytes(4,'little').hex(),
                      'symbol':symbol,'link':True})
    report={'schema':1,'module':'RV 4.00 appFw.so','status':'GUI_ENTRY_BINDINGS_ONLY',
            'hooks':hooks,'constants':{k:hex(v) for k,v in constants.items()},
            'evidence':['analysis/sound-menu-constructors.txt','analysis/sound-menu-factory-bindings.txt',
                        'analysis/sound-menu-base.txt','analysis/sound-menu-probe.json'],
            'whole_gui_installation':False}
    (ROOT/'analysis/sound-port-controller-bindings.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'Generated {len(hooks)} guarded GUI entry trampolines')

if __name__=='__main__':main()
