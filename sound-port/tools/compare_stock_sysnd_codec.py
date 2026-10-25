"""Bounded Capstone comparison of M4/RV native short-sound format and clocks."""
import difflib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
DONOR=ROOT/'references/stock-a7m4-602'
sys.path.insert(0,str(DONOR/'python-deps'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_GRP_JUMP,CS_GRP_CALL
from capstone.arm import ARM_OP_IMM,ARM_OP_REG,ARM_OP_MEM,ARM_REG_PC,ARM_INS_MOVW,ARM_INS_MOVT

BASE=0x108000
VERIFIED_ACTOR_OBJECTS={0xFC6AD8,0x1117818}


def native_span(data):
    h=0x20000
    return BASE,max(BASE+len(data),struct.unpack_from('<I',data,h+0x150)[0]+struct.unpack_from('<I',data,h+0x14c)[0])


def decode(data,start,end):
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB);d.detail=True
    return list(d.disasm(data[start-BASE:end-BASE],start))


def normalize(data,instructions,start,end):
    tokens=[f'{i.mnemonic} {i.op_str}'for i in instructions];fixups=[];low={}
    lo,hi=native_span(data)
    for n,i in enumerate(instructions):
        if i.id==ARM_INS_MOVT and len(i.operands)==2 and i.operands[0].type==ARM_OP_REG:
            reg=i.operands[0].reg
            if reg in low:
                previous,imm=low[reg];value=imm|(i.operands[1].imm<<16)
                used_as_address=False
                for after in instructions[n+1:n+13]:
                    if any(o.type==ARM_OP_MEM and o.mem.base==reg for o in after.operands):used_as_address=True;break
                    if after.group(CS_GRP_CALL)and any(o.type==ARM_OP_REG and o.reg==reg for o in after.operands):used_as_address=True;break
                    if reg in after.regs_access()[1]:break
                raw=data[value-BASE:value-BASE+160]if BASE<=value<BASE+len(data)else b''
                string=raw.split(b'\0',1)[0]
                literal_string=(b'\0'in raw and len(string)>=5 and all(32<=x<127 or x in(9,10,13)for x in string))
                if lo<=value<hi and (used_as_address or value&1 or literal_string or value in VERIFIED_ACTOR_OBJECTS):
                    for k in(previous,n):
                        j=instructions[k];tokens[k]=f'{j.mnemonic} {j.reg_name(reg)}, <IMAGE_ADDRESS_PART>'
                    fixups.append({'kind':'image_address','at':hex(instructions[previous].address),'value':hex(value),
                                   'literal_string':string.decode('ascii')if literal_string else None,
                                   'verified_actor_object':value in VERIFIED_ACTOR_OBJECTS})
        # Track low MOVW only until another instruction overwrites the register.
        if i.mnemonic.startswith('movw') and len(i.operands)==2:low[i.operands[0].reg]=(n,i.operands[1].imm)
        elif i.id!=ARM_INS_MOVT:
            for reg in i.regs_access()[1]:low.pop(reg,None)
        if i.group(CS_GRP_JUMP)or i.group(CS_GRP_CALL):
            immediate=[o.imm for o in i.operands if o.type==ARM_OP_IMM]
            if immediate:
                target=immediate[-1]
                original=f'#{target:#x}'
                normalized=f'<LOCAL+{target-start:#x}>'if start<=target<end else '<EXTERNAL_CODE>'
                tokens[n]=tokens[n].replace(original,normalized)
                fixups.append({'kind':'code_target','at':hex(i.address),'value':hex(target),'local':start<=target<end})
    return tokens,fixups


def main():
    m4=(DONOR/'extracted/nflasha8/cpapp-b.bin').read_bytes()
    rv=(ROOT/'analysis/targets/nflasha8/cpapp-b.bin').read_bytes()
    delta=0xDEC80
    ranges=[('SysndConfig',0xB345A6,0xB345E6),('SysndPlay_and_local_helpers',0xB34618,0xB34C00),
            ('SysndStop',0xB34C00,0xB34C9E),('SysndRegConfig',0xB35042,0xB35102),
            ('SysndFormatBit',0xB35102,0xB3519C),('SysndLpcmBits_and_clock_enable',0xB3545A,0xB355B4),
            ('SysndInitFormat',0xB355B4,0xB35710),('SysndFormatDispatch',0xB35710,0xB357E8)]
    # Identify the rate-table counterpart by exact bytes, not an assumed delta.
    table_va=0x4F7748;ratebytes=rv[table_va-BASE:table_va-BASE+36]
    matches=[];at=0
    while True:
        offset=m4.find(ratebytes,at)
        if offset<0:break
        matches.append(offset+BASE);at=offset+1
    if not matches:raise ValueError('No exact M4 byte-rate table counterpart found')
    rate_match=min(matches,key=lambda x:abs(x-table_va))
    rv_matches=[];at=0
    while True:
        offset=rv.find(ratebytes,at)
        if offset<0:break
        rv_matches.append(offset+BASE);at=offset+1
    library_delta=table_va-rate_match
    pairs=[(name,a-delta,b-delta,a,b)for name,a,b in ranges]
    pairs += [('SysndRateNumerator',0x4F7700-library_delta,0x4F77A4-library_delta,0x4F7700,0x4F77A4),
              ('SysndClockDenominator',0x4F7694-library_delta,0x4F7700-library_delta,0x4F7694,0x4F7700)]
    results=[];lines=[];external={};conflicts=[]
    for name,old_start,old_end,new_start,new_end in pairs:
        old=decode(m4,old_start,old_end);new=decode(rv,new_start,new_end)
        a,af=normalize(m4,old,old_start,old_end);b,bf=normalize(rv,new,new_start,new_end)
        equal=a==b
        diffs=[]
        for tag,i,j,k,l in difflib.SequenceMatcher(a=a,b=b,autojunk=False).get_opcodes():
            if tag!='equal':diffs.append({'tag':tag,'m4':a[i:j],'rv':b[k:l],
                                        'm4_addresses':[hex(x.address)for x in old[i:j]],
                                        'rv_addresses':[hex(x.address)for x in new[k:l]]})
        if len(old)==len(new):
            for x,y in zip(old,new):
                if x.group(CS_GRP_CALL)and y.group(CS_GRP_CALL):
                    ox=[o.imm for o in x.operands if o.type==ARM_OP_IMM];oy=[o.imm for o in y.operands if o.type==ARM_OP_IMM]
                    if ox and oy:
                        if ox[-1]in external and external[ox[-1]]!=oy[-1]:conflicts.append([hex(ox[-1]),hex(external[ox[-1]]),hex(oy[-1])])
                        external[ox[-1]]=oy[-1]
        mmio=[]
        for i,x in enumerate(new):
            if x.id==ARM_INS_MOVT and x.operands[1].imm==0xf48a:
                for z in reversed(new[max(0,i-6):i]):
                    if z.mnemonic.startswith('movw') and z.operands[0].reg==x.operands[0].reg:
                        mmio.append(hex((0xf48a<<16)|z.operands[1].imm));break
        results.append({'name':name,'m4_start':hex(old_start),'rv_start':hex(new_start),
                        'm4_bytes':old_end-old_start,'rv_bytes':new_end-new_start,
                        'm4_instructions':len(old),'rv_instructions':len(new),'normalized_equal':equal,
                        'mmio_addresses_preserved':sorted(set(mmio)),'differences':diffs,
                        'm4_relocations':af,'rv_relocations':bf})
        lines.append(f'== {name} M4 {old_start:x} RV {new_start:x} normalized_equal={equal} ==')
        lines+=['M4 '+hex(x.address)+' '+x.mnemonic+' '+x.op_str for x in old]
        lines+=['RV '+hex(x.address)+' '+x.mnemonic+' '+x.op_str for x in new]
    report={'schema':1,'status':'STATIC_COMPATIBILITY_EVIDENCE','source_m4':'official 6.02 stock CP 7b9b137d...89e2c2b',
            'source_rv':'provided 4.00 stock CP','high_level_code_delta':hex(delta),
            'normalization':'only external code targets and complete MOVW/MOVT image pointers used as addresses, literal strings, callbacks or the paired verified Sysnd actor object; all MMIO and other immediates retained',
            'function_windows':results,'external_call_target_mapping':{hex(a):hex(b)for a,b in external.items()},
            'external_mapping_conflicts':conflicts,'verified_actor_pair':{'m4_va':'0xfc6ad8','rv_va':'0x1117818',
                'context':'paired tail entry computes actor+0x4c and passes it to the same normalized local method',
                'm4_first_word':hex(struct.unpack_from('<I',m4,0xFC6AD8-BASE)[0]),
                'rv_first_word':hex(struct.unpack_from('<I',rv,0x1117818-BASE)[0])},
            'byte_rate_table':{'rv_va':hex(table_va),'m4_exact_matches':[hex(a)for a in matches],'rv_exact_matches':[hex(a)for a in rv_matches],
                'values':list(struct.unpack('<9I',ratebytes)),'library_delta_from_table':hex(library_delta)},
            'all_40_stock_sound_assets_equal':True,'hardware_audio_or_decoder_output_verified':False,
            'codec_contract_boundary':'Static native-format/clock compatibility does not itself prove the reference custom F0 decoder waveform or on-camera sound.'}
    (DONOR/'codec-equivalence.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (DONOR/'codec-disassembly.txt').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps({'windows':[(x['name'],x['normalized_equal'],len(x['differences']))for x in results],
                      'rate_table':report['byte_rate_table'],'call_mapping_conflicts':conflicts},indent=2))


if __name__=='__main__':main()
