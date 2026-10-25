"""Generate RV-shaped menu objects and replacement registries; never edits appFw."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'references/sony-a7iv-feature-research/scripts'))
from appfw_elf import AppElf
from build_common import run, elf_info

OUT = ROOT / 'sound-port/menu'


def u32(data, offset, value):
    struct.pack_into('<I', data, offset, value)


def byte_array(data):
    return '{' + ','.join(f'0x{x:02x}' for x in data) + '}'


def main():
    e = AppElf(ROOT / 'analysis/targets/nflasha15/lib/appFw.so')
    profile = json.loads((ROOT / 'references/sony-a7m4-custom-firmware/a7m4/profiles/custom-sounds-reference.json').read_text(encoding='utf8'))
    parts, position = [], 0
    for operation in profile['files'][0]['ops']:
        if 'copy' in operation:
            position += operation['copy'][1]
        else:
            b = base64.b64decode(operation['data'], validate=True)
            parts.append((position, b)); position += len(b)

    def public(offset, length):
        result, present = bytearray(length), bytearray(length)
        for start, b in parts:
            lo, hi = max(start, offset), min(start + len(b), offset + length)
            if lo < hi:
                result[lo - offset:hi - offset] = b[lo - start:hi - start]
                present[lo - offset:hi - offset] = bytes([1]) * (hi - lo)
        if not all(present):
            raise ValueError(f'No complete public ADD coverage for {offset:#x}+{length:#x}')
        return result

    def native(address, length):
        off = e.offset(address)
        return bytearray(e.data[off:off + length])

    tables = {'leaf': (0x502A980, 0x5030590), 'option': (0x5030590, 0x5046300),
              'profile': (0x5046300, 0x5049640), 'parent': (0x5049640, 0x5049D80)}
    original = {name: [(e.u32(a), e.ptr(a + 8)) for a in range(start, end, 16)]
                for name, (start, end) in tables.items()}
    if any(mid in dict(original[name]) for mid in range(1592, 1600) for name in ('leaf','profile','parent')):
        raise ValueError('A selected RV private menu ID is occupied')
    if any(alias in dict(original['option']) for alias in range(5607, 5631)):
        raise ValueError('A selected RV private option alias is occupied')

    c = ['/* Generated from RV native objects and complete public reference ADD records. */',
         '#include <stdint.h>', '#include <stddef.h>',
         '#define RV_MENU_DATA __attribute__((section(".data.menu"),used,aligned(8)))',
         'typedef struct { uint8_t bytes[128]; } rv_option;',
         'typedef struct { uint32_t id,pad; const void *value; } rv_row;',
         'typedef struct { uint32_t id,pad; const void *leaf,*parent; } rv_folder_row;',
         'typedef struct { uint8_t prefix[0x58]; const void *options; uint8_t middle[16]; const void *valid,*getter,*setter,*commit; uint8_t reserved[24]; const void *blocked; uint8_t tail[16]; } rv_leaf;',
         'typedef struct { uint8_t prefix[0x20]; const void *valid; uint8_t suffix[0x48]; rv_row children[3]; } rv_parent;',
         'typedef struct { uint8_t prefix[0x48]; const void *valid,*blocked,*reserved; uint8_t tail[16]; } rv_profile;',
         'typedef struct { uint8_t header[16]; rv_folder_row entries[13]; } rv_folder;',
         '_Static_assert(sizeof(rv_leaf)==192,"RV leaf ABI");',
         '_Static_assert(sizeof(rv_option)==128,"RV option ABI");',
         '_Static_assert(sizeof(rv_profile)==112,"RV profile ABI");',
         '_Static_assert(offsetof(rv_parent,children)==112,"RV parent ABI");',
         '_Static_assert(sizeof(rv_folder_row)==24,"RV folder ABI");']
    externs = {}

    def symbol(address):
        name = f'rv_original_{address:08x}'
        externs[name] = address
        return '&' + name

    callbacks = [f'csnd_menu_{slot}_{which}' for slot in ('electronic', 'focus')
                 for which in ('getter', 'setter', 'commit', 'available')]
    callbacks += [f'csnd_volume_{slot}_{which}' for slot in ('electronic', 'focus')
                  for which in ('getter', 'setter', 'commit', 'available')]
    callbacks += ['csnd_menu_zero', 'csnd_menu_no_direct_import']
    c += [f'extern const uint8_t {name}[];' for name in callbacks]
    # All original native valid callbacks are resolved from the supplied RV ELF.
    valid = symbol(e.ptr(0x583EA00 + 0x70))
    leaf_objects, parent_objects, profile_objects, option_objects = {}, {}, {}, {}
    option_owners, child_owners = {}, {}
    ref_electronic = public(0x5E10490, 192)
    ref_import = public(0x5E10550, 192)
    ref_volume = public(0x5E480A0, 192)
    source_profile = native(0x5847068, 112)
    reference_profile = public(0x5E13CA8, 112)
    source_parent = native(0x588D660, 112)
    parent_ids = (1592, 1595)
    for slot, slotname in enumerate(('electronic', 'focus')):
        parent = parent_ids[slot]
        enable, importing, volume = parent + 1, parent + 2, 1598 + slot
        aliases = (5607 + 2 * slot, 5611 + 10 * slot)
        for kind, count, aliasbase in [('enable', 2, aliases[0]), ('volume', 10, aliases[1])]:
            options = []
            for index in range(count):
                # Native RV on/off record layout (128 B) is the option template.
                b = native(0x3F45C80 + (index % 2) * 128, 128)
                alias = aliasbase + index
                u32(b, 0, alias); u32(b, 4, alias); u32(b, 0x34, index)
                u32(b, 0x3C, 20001); u32(b, 0x40, 20001)
                if kind == 'volume':
                    u32(b, 8, 0x0200ABD8 + index)
                options.append('{.bytes=' + byte_array(b) + '}')
                option_objects[alias] = f'&rv_{slotname}_{kind}_options[{index}]'
                option_owners[alias] = enable if kind == 'enable' else volume
            c.append(f'const rv_option rv_{slotname}_{kind}_options[{count}]={{' + ','.join(options) + '};')
        for kind, mid, reference, count in [('enable', enable, ref_electronic, 2),
                                          ('import', importing, ref_import, 0),
                                          ('volume', volume, ref_volume, 10)]:
            b = bytearray(reference)
            # These RV context fields differ from the reference build; inherit
            # the original RV Silent Mode leaf's native ABI, not its callbacks.
            u32(b, 0x14, e.u32(0x583EA00 + 0x14))
            u32(b, 0xBC, parent)
            options = f'rv_{slotname}_{kind}_options' if count else '0'
            if kind == 'import':
                get, set_, commit, block = (f'csnd_menu_{slotname}_available', 'csnd_menu_no_direct_import',
                                            'csnd_menu_no_direct_import', f'csnd_menu_{slotname}_available')
            else:
                prefix = 'csnd_menu' if kind == 'enable' else 'csnd_volume'
                get, set_, commit, block = [f'{prefix}_{slotname}_{v}' for v in ('getter', 'setter', 'commit', 'available')]
            name = f'rv_{slotname}_{kind}_leaf'
            c.append(f'const rv_leaf {name}={{.prefix={byte_array(b[:0x58])},.options={options},'
                     f'.middle={byte_array(b[0x60:0x70])},.valid={valid},.getter=&{get},.setter=&{set_},'
                     f'.commit=&{commit},.reserved={byte_array(b[0x90:0xA8])},.blocked=&{block},.tail={byte_array(b[0xB0:])}' + '};')
            leaf_objects[mid] = '&' + name
            child_owners[mid] = parent
        b = bytearray(source_parent)
        u32(b, 0, 0x0200AB5C + slot); u32(b, 4, 0xFFFFFFFF); u32(b, 8, 0xFFFFFFFF)
        u32(b, 0x64, 3)
        name = f'rv_{slotname}_parent'
        c.append(f'const rv_parent {name}={{.prefix={byte_array(b[:0x20])},.valid={valid},.suffix={byte_array(b[0x28:])},.children={{'
                 f'{{{enable},0,{leaf_objects[enable]}}},{{{importing},0,{leaf_objects[importing]}}},'
                 f'{{{volume},0,{leaf_objects[volume]}}}' + '}};')
        parent_objects[parent] = '&' + name
        for mid in (parent, enable, importing, volume):
            b = bytearray(source_profile)
            # Public custom profile flags, RV native 112-byte layout/tail.
            b[:0x48] = reference_profile[:0x48]
            u32(b, 0, mid); u32(b, 0x60, 20001)
            blocked = f'csnd_menu_{slotname}_available' if mid == importing else (
                f'csnd_volume_{slotname}_available' if mid == volume else None)
            name = f'rv_profile_{mid}'
            c.append(f'const rv_profile {name}={{.prefix={byte_array(b[:0x48])},.valid={valid},'
                     f'.blocked=&{blocked if blocked else "csnd_menu_zero"},.reserved=0,.tail={byte_array(b[0x60:0x70])}' + '};')
            profile_objects[mid] = '&' + name

    # Emit standalone custom maps. Root's install adapter chooses the native
    # lookup contract; the three native registries are preserved as evidence.
    for name, objects in [('leaf', leaf_objects), ('parent', parent_objects),
                          ('profile', profile_objects), ('option', option_objects)]:
        c.append(f'const rv_row rv_sound_{name}_map[{len(objects)}]={{' + ','.join(
            f'{{{mid},0,{value}}}' for mid, value in sorted(objects.items())) + '};')
        c.append(f'const uint32_t rv_sound_{name}_count={len(objects)};')
    replacement_counts = {}
    # Native initialization consumes sorted [id,pointer] ranges. Keeping the
    # full original rows makes replacement independent of hidden map internals.
    for name, extra in [('leaf', leaf_objects), ('option', option_objects),
                         ('profile', profile_objects), ('parent', parent_objects)]:
        rows = {mid: symbol(address) for mid, address in original[name]}
        rows.update(extra)
        replacement_counts[name] = len(rows)
        c.append(f'const rv_row rv_sound_replacement_{name}_registry[{len(rows)}]={{' + ','.join(
            f'{{{mid},0,{value}}}' for mid, value in sorted(rows.items())) + '};')
        c.append(f'const uint32_t rv_sound_replacement_{name}_count={len(rows)};')
    c.append('typedef struct { uint32_t from,to; } rv_id_pair;')
    for name, pairs in [('menu_alias', {mid: mid for mid in profile_objects}),
                         ('option_alias', {alias: alias for alias in option_objects}),
                         ('option_owner', option_owners), ('child_owner', child_owners)]:
        c.append(f'const rv_id_pair rv_sound_{name}[{len(pairs)}]={{' + ','.join(
            f'{{{a},{b}}}' for a,b in sorted(pairs.items())) + '};')
        c.append(f'const uint32_t rv_sound_{name}_count={len(pairs)};')
    integer_tables = {'profile_alias': (0x3E1AE10,0x3E1C7B0),
                      'option_owner': (0x3E1C7B0,0x3E27668),
                      'menu_profile': (0x3E27668,0x3E2A810)}
    for name, (start,end) in integer_tables.items():
        pairs = {e.u32(a):e.u32(a+4) for a in range(start,end,8)}
        pairs.update(option_owners if name=='option_owner' else {mid:mid for mid in profile_objects})
        replacement_counts[name]=len(pairs)
        c.append(f'const rv_id_pair rv_sound_replacement_{name}_registry[{len(pairs)}]={{' + ','.join(
            f'{{{a},{b}}}' for a,b in sorted(pairs.items())) + '};')
        c.append(f'const uint32_t rv_sound_replacement_{name}_count={len(pairs)};')
    folder = native(0x5050DD8, 16)
    if struct.unpack_from('<I', folder, 8)[0] != 11:
        raise ValueError('RV Shutter/Silent folder count changed')
    u32(folder, 8, 13)
    entries = []
    original_folder = []
    for index in range(11):
        at = 0x5050DE8 + index * 24
        mid, leaf, parent = e.u32(at), e.ptr(at + 8), e.ptr(at + 16)
        entries.append(f'{{{mid},0,{symbol(leaf) if leaf else "0"},{symbol(parent) if parent else "0"}}}')
        original_folder.append({'id': mid, 'leaf': hex(leaf), 'parent': hex(parent)})
    for mid in parent_ids:
        entries.append(f'{{{mid},0,0,{parent_objects[mid]}}}')
    c.append('const rv_folder rv_shutter_silent_folder={.header=' + byte_array(folder) + ',.entries={' + ','.join(entries) + '}};')
    # Declarations must precede generated initializers using original RV symbols.
    c[2:2] = [f'extern const uint8_t {name}[];' for name in sorted(externs)]
    OUT.mkdir(parents=True, exist_ok=True)
    source='\n'.join(('RV_MENU_DATA '+line) if line.startswith('const ') else line for line in c)+'\n'
    (OUT / 'rv_menu_metadata.c').write_text(source, encoding='utf8')
    (OUT / 'rv_original_symbols.ld').write_text('\n'.join(f'{name}=0x{address:x};' for name, address in sorted(externs.items())) + '\n', encoding='utf8')
    zig = ROOT / 'toolchains/zig-x86_64-windows-0.15.2/zig.exe'
    obj = OUT / 'rv_menu_metadata.o'
    build = run([str(zig), 'cc', '-target', 'aarch64-freestanding-none', '-mgeneral-regs-only',
                 '-fno-pic', '-fno-pie', '-ffreestanding', '-fno-builtin', '-O2', '-std=c11',
                 '-Wall', '-Wextra', '-Werror', '-c', str(OUT / 'rv_menu_metadata.c'), '-o', str(obj)],
                OUT / 'compile.log')
    manifest = {'schema': 1, 'native_module': str(e.path.relative_to(ROOT)),
                'source_templates': {'leaf': '0x583ea00', 'option': '0x3f45c80',
                                     'profile': '0x5847068', 'parent': '0x588d660'},
                'native_registries': {k: {'start': hex(v[0]), 'end': hex(v[1]),
                                         'count': len(original[k]), 'max_id': max(x[0] for x in original[k])}
                                      for k, v in tables.items()},
                'shutter_silent_folder': {'native_va': '0x5050dd8', 'native_bytes': 280,
                                          'new_bytes': 328, 'title_id': '0x0200607c',
                                          'original_entries': original_folder, 'new_parents': list(parent_ids)},
                'private_ids': {'parents': list(parent_objects), 'leaves': list(leaf_objects),
                                'profiles': list(profile_objects), 'option_aliases': list(option_objects)},
                'replacement_registry_counts': replacement_counts,
                'native_integer_maps': {name:{'start':hex(a),'end':hex(b),'count':(b-a)//8} for name,(a,b) in integer_tables.items()},
                'native_symbol_bindings': {name: hex(address) for name, address in externs.items()},
                'callback_bindings': callbacks, 'compile': build,
                'rv_header_abi': {'leaf': 192, 'parent': 112, 'option': 128, 'profile': 112,
                                  'reference_profile_bytes': 128},
                'integration_remaining': ['root native lookup/registration contracts and UI reachability',
                    'install folder via its product-catalogue reference',
                    'convert R_AARCH64_ABS64 object relocations into appFw loader-relative relocations',
                    'confirm inherited leaf context field +0x14 and import action type +0x20 via RV native consumer'],
                'firmware_modified': False, 'camera_io': False}
    if build['exit_code'] == 0:
        manifest['object'] = elf_info(obj)
        with obj.open('rb') as f:
            elf=ELFFile(f);data=elf.get_section_by_name('.data.menu');section_index=elf.get_section_index('.data.menu')
            symbols=elf.get_section_by_name('.symtab')
            offsets={s.name:int(s['st_value']) for s in symbols.iter_symbols() if s.name and s['st_shndx']==section_index}
            relocations=[]
            for section in elf.iter_sections():
                if section['sh_type']!='SHT_RELA' or int(section['sh_info'])!=section_index:continue
                for relocation in section.iter_relocations():
                    if int(relocation['r_info_type'])!=257:raise ValueError('Expected ABS64 data relocation')
                    sym=symbols.get_symbol(relocation['r_info_sym']);addend=int(relocation['r_addend'])
                    row={'offset':int(relocation['r_offset']),'type':'R_AARCH64_ABS64','symbol':sym.name,'addend':addend}
                    if sym['st_shndx']==section_index:
                        row.update(target_kind='internal',target_offset=int(sym['st_value'])+addend)
                    elif sym.name in externs:
                        row.update(target_kind='native',target_va=externs[sym.name]+addend)
                    elif sym.name in callbacks:
                        row.update(target_kind='callback')
                    else:raise ValueError('Unknown metadata relocation '+sym.name)
                    relocations.append(row)
            (OUT/'rv_menu_metadata.data.bin').write_bytes(data.data())
            relocation_manifest={'schema':1,'section':'.data.menu','bytes':int(data['sh_size']),
                                 'symbols':offsets,'relocations':relocations,
                                 'base_relative_pointer_relocation':'R_AARCH64_RELATIVE (1027) in final appFw',
                                 'native_addresses_are_app_elf_vas':True}
            (OUT/'rv_menu_metadata.relocations.json').write_text(json.dumps(relocation_manifest,indent=2),encoding='utf8')
            manifest['raw_data']={'bytes':int(data['sh_size']),'relocations':len(relocations),
                                  'data':'sound-port/menu/rv_menu_metadata.data.bin',
                                  'manifest':'sound-port/menu/rv_menu_metadata.relocations.json'}
    (OUT / 'metadata-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'compile_exit': build['exit_code'], 'maps': {k: len(v) for k, v in
                      [('parents', parent_objects), ('leaves', leaf_objects), ('profiles', profile_objects), ('options', option_objects)]}}, indent=2))
    raise SystemExit(build['exit_code'])


if __name__ == '__main__':
    main()
