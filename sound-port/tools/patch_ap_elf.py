"""Install linked AArch64 modules into a copy of the exact RV 4.00 AP ELF.

The output is an offline component, not an installable camera update. Absolute
menu pointers are accepted only with a bound installation plan and explicit
R_AARCH64_RELATIVE loader records.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE_SHA256 = "41bd8f4cda1f44c7038912837737e1ce6a650065f2108061ada30e5c7f9ce7c7"
RX_BASE, RX_END = 0x8F90000, 0x8FC0000
RW_BASE, RW_END = 0x8FC0000, 0x9000000
PAGE = 0x10000
PH = struct.Struct("<IIQQQQQQ")


def align(value, size=PAGE):
    return (value + size - 1) & -size


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def branch(source, destination, link=False):
    delta = destination - source
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError("AArch64 B is unaligned or outside its 128 MiB range")
    return struct.pack("<I", (0x94000000 if link else 0x14000000) | ((delta // 4) & 0x3FFFFFF))


def pack_ph(kind, flags, offset, va, filesz, memsz, alignment):
    return PH.pack(kind, flags, offset, va, va, filesz, memsz, alignment)


def patch(source: bytes, modules, hooks, relative_fixups=(), *, menu_install=None, menu_base=None,
          cache_install=None, native_caches=False):
    hooks=list(hooks)
    if menu_install is not None and menu_base is not None:
        raise ValueError('Supply menu_install or menu_base, not both')
    if cache_install is not None and native_caches:
        raise ValueError('Supply cache_install or native_caches, not both')
    if native_caches:
        from emit_menu_cache import build_cache_install
        cache_install=build_cache_install()
    if hashlib.sha256(source).hexdigest() != BASE_SHA256:
        raise ValueError("Expected the exact original A7R V 4.00 appFw.so")
    elf = ELFFile(io.BytesIO(source))
    if elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_DYN':
        raise ValueError("Expected AArch64 ET_DYN")
    phoff, entsize, count = elf['e_phoff'], elf['e_phentsize'], elf['e_phnum']
    if entsize != PH.size or count != 6:
        raise ValueError("Unexpected original PHDR layout")
    originals = [PH.unpack_from(source, phoff + i * PH.size) for i in range(count)]
    loads = [p for p in originals if p[0] == 1]
    if any(p[3] + p[6] > RX_BASE for p in loads):
        raise ValueError("Private region overlaps an original LOAD")
    rxoff = align(len(source))
    rwoff = rxoff + RX_END - RX_BASE
    out = bytearray(source)
    out.extend(bytes(rwoff + RW_END - RW_BASE - len(out)))
    # Relocated PHDR is explicitly mapped. Keep it before the first LOAD entry.
    needs_rela = bool(relative_fixups) or menu_install is not None or menu_base is not None or cache_install is not None
    phnum = count + 3 + bool(needs_rela) + (cache_install is not None)
    headers = [pack_ph(6, 4, rxoff, RX_BASE, phnum * PH.size, phnum * PH.size, 8)]
    headers.extend(PH.pack(*p) for p in originals)
    headers.extend([
        pack_ph(1, 5, rxoff, RX_BASE, RX_END - RX_BASE, RX_END - RX_BASE, PAGE),
        pack_ph(1, 6, rwoff, RW_BASE, RW_END - RW_BASE, RW_END - RW_BASE, PAGE),
    ])
    initial_headers=b''.join(headers)
    out[rxoff:rxoff + len(initial_headers)] = initial_headers
    struct.pack_into('<Q', out, 32, rxoff)
    struct.pack_into('<H', out, 56, phnum)
    occupied = [(RX_BASE, RX_BASE + 0x1000, 'PHDR reserved page')]
    installed = []
    symbols = {}
    for name, data in modules:
        module = ELFFile(io.BytesIO(data))
        if module['e_machine'] != 'EM_AARCH64' or module['e_type'] != 'ET_EXEC':
            raise ValueError(f'{name}: expected fixed-address AArch64 ET_EXEC')
        symtab = module.get_section_by_name('.symtab')
        if symtab:
            for sym in symtab.iter_symbols():
                if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
                    raise ValueError(f'{name}: undefined symbol {sym.name}')
                if (sym.name and sym['st_shndx'] != 'SHN_UNDEF'
                        and (sym['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK')
                             or (sym['st_info']['bind']=='STB_LOCAL'
                                 and sym['st_other']['visibility']=='STV_HIDDEN'))):
                    # LLD localizes the extension's -fvisibility=hidden API
                    # functions. Ordinary static helpers and $x/$d stay local
                    # DEFAULT and must not conflict across independent modules.
                    if sym.name in symbols and symbols[sym.name] != sym['st_value']:
                        raise ValueError(f'Duplicate symbol differs: {sym.name}')
                    symbols[sym.name] = sym['st_value']
        for section in module.iter_sections():
            if section['sh_type'] in ('SHT_REL', 'SHT_RELA') and section['sh_size']:
                raise ValueError(f'{name}: review relocations before installation')
            if not section['sh_flags'] & 2 or not section['sh_size']:
                continue
            va, size = section['sh_addr'], section['sh_size']
            writable = bool(section['sh_flags'] & 1)
            lo, hi, filebase = (RW_BASE, RW_END, rwoff) if writable else (RX_BASE, RX_END, rxoff)
            if va < lo or va + size > hi:
                raise ValueError(f'{name}:{section.name} exceeds its LOAD region')
            for start, end, owner in occupied:
                if va < end and start < va + size:
                    raise ValueError(f'{name}:{section.name} overlaps {owner}')
            occupied.append((va, va + size, f'{name}:{section.name}'))
            payload = bytes(size) if section['sh_type'] == 'SHT_NOBITS' else section.data()
            off = filebase + va - lo
            out[off:off + size] = payload
            installed.append({'module': name, 'section': section.name, 'va': hex(va),
                              'offset': hex(off), 'size': size,
                              'zero_initialized': section['sh_type'] == 'SHT_NOBITS',
                              'sha256': hashlib.sha256(payload).hexdigest()})
    changed = []
    fixups = list(relative_fixups)
    menu_report = None
    cache_report = None
    if cache_install is not None:
        cache_blob,cache_plan=cache_install
        if cache_blob or integer(cache_plan['file_bytes'])!=0 or integer(cache_plan['load_flags'])!=6:
            raise ValueError('Native caches require an anonymous zero-initialized RW LOAD')
        cache_va,cache_size=integer(cache_plan['load_va']),integer(cache_plan['memory_bytes'])
        if cache_va<RW_END or cache_va%PAGE or not cache_size or cache_size%PAGE:
            raise ValueError('Invalid cache LOAD allocation')
        extents=[]
        for obj in cache_plan['objects']:
            start,size=integer(obj['va']),integer(obj['bytes'])
            if start<cache_va or not size or start+size>cache_va+cache_size:
                raise ValueError('Cache object exceeds its LOAD')
            if any(start<end and old<start+size for old,end in extents):
                raise ValueError('Cache objects overlap')
            extents.append((start,start+size))
        fixups.extend(cache_plan['relative_fixups'])
        hooks.extend(cache_plan.get('initializer_hooks',()))
        cache_report={'va':hex(cache_va),'memory_bytes':cache_size,'file_bytes':0,
                      'zero_initialized':True,'objects':cache_plan['objects'],
                      'got_relative_fixups':len(cache_plan['relative_fixups']),
                      'native_map_initializer_extended_by_registration':True,
                      'initializer_hooks':cache_plan.get('initializer_hooks',()),
                      'original_descriptor_count_scalar':cache_plan.get('original_descriptor_count_scalar')}

    def original_offset(va, size):
        selected = [p for p in loads if p[3] <= va and va + size <= p[3] + p[5]]
        if len(selected) != 1:
            raise ValueError(f'Native edit {va:#x}+{size:#x} is not uniquely file backed')
        p = selected[0]
        return p[2] + va - p[3]

    if menu_base is not None:
        from emit_menu_install import build_install
        menu_install = build_install(integer(menu_base), symbols)
    if menu_install is not None:
        blob, plan = menu_install
        blob = bytes(blob)
        if plan.get('status') != 'BOUND_INSTALL_DATA' or plan.get('unresolved_callback_fixups'):
            raise ValueError('Menu installation requires fully bound AP callbacks')
        va, size = integer(plan['menu_base']), integer(plan['menu_bytes'])
        if not size or size != len(blob) or va % 8 or va < RW_BASE or va + size > RW_END:
            raise ValueError('Menu data exceeds its initialized RW allocation')
        for start, end, owner in occupied:
            if va < end and start < va + size:
                raise ValueError(f'Menu data overlaps {owner}')
        off = rwoff + va - RW_BASE
        out[off:off + size] = blob
        occupied.append((va, va + size, 'menu metadata'))
        installed.append({'module': 'rv-menu', 'section': '.data.menu', 'va': hex(va),
                          'offset': hex(off), 'size': size, 'zero_initialized': False,
                          'sha256': hashlib.sha256(blob).hexdigest()})
        for edit in plan['code_and_folder_patches']:
            location = integer(edit['va'])
            before, after = bytes.fromhex(edit['before_hex']), bytes.fromhex(edit['after_hex'])
            if not before or len(before) != len(after) or len(before) != integer(edit['bytes']):
                raise ValueError('Invalid menu edit extent')
            editoff = original_offset(location, len(before))
            if editoff != integer(edit['file_offset']) or source[editoff:editoff + len(before)] != before:
                raise ValueError(f'Menu edit bytes differ at {location:#x}')
            if any(editoff < end and start < editoff + len(after) for start, end in changed):
                raise ValueError('Overlapping menu edits')
            out[editoff:editoff + len(after)] = after
            changed.append((editoff, editoff + len(after)))
        for relocation in plan['loader_relative_relocations']:
            if integer(relocation['r_info']) != 1027:
                raise ValueError('Only relative menu relocations are supported')
            location, target = integer(relocation['r_offset']), integer(relocation['r_addend'])
            if va <= location and location + 8 <= va + size:
                pointeroff = rwoff + location - RW_BASE
                native_expected = None
            else:
                pointeroff = original_offset(location, 8)
                native_expected = source[pointeroff:pointeroff + 8].hex()
                if not any(start <= pointeroff and pointeroff + 8 <= end for start, end in changed):
                    raise ValueError('Native menu pointer is outside the declared menu edits')
            if location % 8 or struct.unpack_from('<Q', out, pointeroff)[0] != target:
                raise ValueError(f'Menu pointer bytes and relocation addend differ at {location:#x}')
            row = {'va': location, 'target_va': target}
            if native_expected is not None:
                row['expected_hex'] = native_expected
            fixups.append(row)
        if not plan['loader_relative_relocations']:
            raise ValueError('Menu plan omits its pointer relocations')
        menu_report = {'status': 'BOUND_OFFLINE_MENU_DATA', 'va': hex(va), 'bytes': size,
                       'exact_edits': len(plan['code_and_folder_patches']),
                       'relative_fixups': len(plan['loader_relative_relocations']),
                       'registry_counts': plan['registry_counts']}

    if fixups:
        oldrela=elf.get_section_by_name('.rela.dyn')
        payload=bytearray(oldrela.data())
        by_target={struct.unpack_from('<Q',payload,i)[0]:i for i in range(0,len(payload),24)}
        seen=set()
        for fixup in fixups:
            va=integer(fixup['va'])
            target=symbols[fixup['symbol']] if 'symbol' in fixup else integer(fixup['target_va'])
            if va % 8 or not 0 <= target < (1 << 63):
                raise ValueError('Invalid relative pointer address/addend')
            if va in seen:raise ValueError('Duplicate pointer fixup')
            seen.add(va)
            if RW_BASE<=va and va+8<=RW_END:
                pass
            else:
                if not any(p[1]&2 and p[3]<=va and va+8<=p[3]+p[6] for p in loads):
                    raise ValueError('Pointer fixup targets nonwritable memory')
                if 'expected_hex' not in fixup:raise ValueError('Native pointer fixup requires expected_hex')
                p=next(p for p in loads if p[3]<=va and va+8<=p[3]+p[5])
                off=p[2]+va-p[3]
                if source[off:off+8].hex()!=fixup['expected_hex']:raise ValueError('Native pointer bytes differ')
            record=struct.pack('<QQq',va,1027,target)
            if va in by_target:
                off=by_target[va]
                if struct.unpack_from('<Q',payload,off+8)[0]!=1027:
                    raise ValueError('Cannot replace a nonrelative dynamic relocation')
                payload[off:off+24]=record
            else:payload.extend(record)
        relaoff=align(len(out));relava=0x9100000
        out.extend(bytes(relaoff-len(out)));out.extend(payload)
        headers.append(pack_ph(1,4,relaoff,relava,len(payload),len(payload),PAGE))
        packed_headers=b''.join(headers)
        # A later cache LOAD may not be appended yet. A shorter replacement
        # must never shrink the bytearray and shift every private file offset.
        out[rxoff:rxoff+len(packed_headers)]=packed_headers
        dynamic=elf.get_section_by_name('.dynamic')
        for i in range(0,dynamic['sh_size'],16):
            off=dynamic['sh_offset']+i;tag,value=struct.unpack_from('<qQ',source,off)
            if tag in (7,8):
                struct.pack_into('<Q',out,off+8,relava if tag==7 else len(payload))
                changed.append((off+8,off+16))
        # Keep the section view consistent with the loader's dynamic view.
        index=next(i for i,s in enumerate(elf.iter_sections()) if s.name=='.rela.dyn')
        off=elf['e_shoff']+index*elf['e_shentsize']+16
        struct.pack_into('<QQQ',out,off,relava,relaoff,len(payload))
        changed.append((off,off+24))
    if cache_install is not None:
        cacheoff=align(len(out))
        out.extend(bytes(cacheoff-len(out)))
        headers.append(pack_ph(1,6,cacheoff,cache_va,0,cache_size,PAGE))
        out[rxoff:rxoff+phnum*PH.size]=b''.join(headers)
    for hook in hooks:
        va = integer(hook['va'])
        expected = bytes.fromhex(hook['expected_hex'])
        target = symbols[hook['symbol']] if 'symbol' in hook else integer(hook['target_va'])
        replacement = branch(va, target, bool(hook.get('link',False)))
        if len(expected) != len(replacement):
            raise ValueError('Entry hook must guard exactly one instruction')
        selected = [p for p in loads if p[3] <= va and va + len(expected) <= p[3] + p[5]]
        if len(selected) != 1:
            raise ValueError('Hook is not uniquely file backed')
        p = selected[0]
        off = p[2] + va - p[3]
        if source[off:off + len(expected)] != expected:
            raise ValueError(f'Hook bytes differ at {va:#x}')
        if any(off < end and start < off + 4 for start, end in changed):
            raise ValueError('Duplicate hook')
        out[off:off + 4] = replacement
        changed.append((off, off + 4))
    # Audit the preservation contract by changed ranges, not by assumptions.
    allowed = [(32, 40), (56, 58)] + changed
    cursor = 0
    for start, end in sorted(allowed):
        if source[cursor:start] != out[cursor:start]:
            raise ValueError('Original bytes changed outside declared patch ranges')
        cursor = end
    if source[cursor:] != out[cursor:len(source)]:
        raise ValueError('Original tail changed')
    final = ELFFile(io.BytesIO(out))
    newloads = [p for p in final.iter_segments() if p['p_type'] == 'PT_LOAD']
    for p in newloads:
        if p['p_offset'] % p['p_align'] != p['p_vaddr'] % p['p_align']:
            raise ValueError('LOAD alignment mismatch')
    for a, b in zip(newloads, newloads[1:]):
        if a['p_vaddr'] + a['p_memsz'] > b['p_vaddr']:
            raise ValueError('Overlapping LOADs')
    return bytes(out), {'schema': 1, 'status': 'OFFLINE_AP_COMPONENT',
        'base_sha256': BASE_SHA256, 'output_sha256': hashlib.sha256(out).hexdigest(),
        'program_headers': phnum, 'sections': installed, 'hooks': hooks,
        'relative_fixups':len(fixups), 'menu':menu_report, 'native_ui_caches':cache_report,
        'original_bytes_preserved_outside_declared_ranges': True,
        'device_execution': 'NOT_TESTED', 'complete_firmware': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix(args.output.suffix + '.manifest.json').exists():
        raise FileExistsError('Output or manifest already exists')
    plan = json.loads(args.plan.read_text(encoding='utf-8'))
    modules = [(str(p), (args.plan.parent / p).read_bytes()) for p in plan['modules']]
    menu = plan.get('menu')
    payload, report = patch(args.base.read_bytes(), modules, plan.get('hooks', []),
                            plan.get('relative_fixups', []),
                            menu_base=integer(menu['base']) if menu is not None else None,
                            native_caches=bool(plan.get('native_ui_caches',False)))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as f:
        f.write(payload)
    with args.output.with_suffix(args.output.suffix + '.manifest.json').open('x', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
