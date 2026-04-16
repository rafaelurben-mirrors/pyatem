import glob
import os
import textwrap
import yaml
import pprint

INDENT = '    '

structtype = {
    'u8': 'B',
    'i8': 'b',
    'u16': 'H',
    'i16': 'h',
    'u32': 'I',
    'i32': 'i',
    'float': 'f',
}
pythontype = {
    'u8': 'int',
    'i8': 'int',
    'u16': 'int',
    'i16': 'int',
    'u32': 'int',
    'i32': 'int',
    'float': 'float',
    'bool': 'bool',
    'string': 'str',
    'bytes': 'bytes',
}


def generate_field_table(definition):
    result = ''
    result += '====== ==== ====== ===========\n'
    result += 'Offset Size Type   Description\n'
    result += '====== ==== ====== ===========\n'
    for field in definition:
        result += f'{field["offset"]:<6} {field["size"]:<4} {field["type"]:<6} {field["description"]}'
        result += '\n'
    result += '====== ==== ====== ===========\n\n'

    return result


def generate_docs(raw):
    result = ''
    ctype = raw['type'].title()
    if 'description' in raw:
        description = raw['description']
    else:
        if ctype == 'Field':
            description = f'Data from the `{raw["code"]}` field.'
        else:
            description = ''
            exit(1)

    result += '"""\n'
    for paragraph in description.split("\n\n"):
        result += textwrap.fill(paragraph.strip(), width=120, drop_whitespace=True) + "\n\n"

    result += generate_field_table(raw['fields'])
    if 'repeated' in raw:
        result += 'Followed by this repeated block:\n\n'
        result += generate_field_table(raw['repeated'])

    for field in raw['fields']:
        if 'enum' in field:
            result += f'The `{field["description"]}` is an enum of these values:\n\n'
            result += '=== ' + '=' * len(field['description']) + '\n'
            result += f'Key {field["description"]}\n'
            result += '=== ' + '=' * len(field['description']) + '\n'
            for key in field['enum']:
                result += f'{key:<3} {field["enum"][key]["description"]}\n'
            result += '=== ' + '=' * len(field['description']) + '\n\n'

    result += 'After parsing:\n\n'
    for field in raw['fields']:
        if field['type'] == '?':
            continue
        result += f':ivar {field["name"]}: {field["description"]}\n'
    if 'calculated' in raw:
        for key in raw['calculated']:
            cf = raw['calculated'][key]
            if 'access' in cf and cf['access'] != 'field':
                continue
            result += f':ivar {key}: {cf["description"]}\n'
    result += '"""\n'

    return result


def generate_enum_constants(fields):
    result = ''
    for field in fields:
        if 'enum_const' in field:
            for key in field['enum']:
                result += field['name'].upper() + '_' + field['enum'][key][field['enum_const']].upper()
                result += f' = {key}\n'
    return result


def process(field, loader):
    if 'process' not in field:
        return loader
    return f'self.{field["process"]}({loader})'


def load_field(field, var, i):
    if field['type'] == '?':
        return []
    if field['type'] == 'string' and isinstance(field['size'], int):
        return [(field['name'], process(field, f'self._get_string({var}[{i}])'))]
    elif field['type'] == 'string':
        return [(field['name'] + '_len', process(field, f"{var}[{i}]"))]
    elif 'bitfield' in field:
        result = []
        if 'bitfield_raw' in field:
            result.append((field['name'], process(field, f"{var}[{i}]")))
        for bit in field['bitfield']:
            bf = field['bitfield'][bit]
            result.append((bf["name"], f"{var}[{i}] & (1 << {bit}) != 0"))
        return result
    elif 'out_max' in field:
        in_min = field['min'] if 'min' in field else 0
        in_max = field['max']
        out_min = field['out_min'] if 'out_min' in field else 0.0
        out_max = field['out_max']
        if float(out_min) == float(in_min):
            factor = in_max / out_max
            return [(field['name'], process(field, f'{var}[{i}] / {factor}'))]
        else:
            raise RuntimeError("Not implemented")
    else:
        return [(field['name'], process(field, f"{var}[{i}]"))]


def generate_init(raw):
    result = 'def __init__(self, raw: bytes):\n'
    result += INDENT + '"""\n'
    result += INDENT + ':param raw: Bytes containing the field contents\n'
    result += INDENT + '"""\n'
    result += INDENT + 'self.raw = raw\n'
    if 'repeated' in raw:
        result += INDENT + 'field = self.STRUCT.unpack_from(raw, 0)\n'
    else:
        result += INDENT + 'field = self.STRUCT.unpack(raw)\n'

    i = 0
    for field in raw['fields']:
        if field['type'] == '?':
            continue
        for sf in load_field(field, 'field', i):
            result += INDENT + f'self.{sf[0]} = {sf[1]}\n'

        if 'repeat' in field:
            rs = {'store': 'list', 'name': field['repeat']['name'], 'format': 'dict', 'key': ''}
            if 'store' in field['repeat']:
                rs['store'] = field['repeat']['store']
            if 'format' in field['repeat']:
                rs['format'] = field['repeat']['format']
            if 'key' in field['repeat']:
                rs['key'] = field['repeat']['key']
            if 'key_format' in field['repeat']:
                rs['key_format'] = field['repeat']['key_format']
            if 'single' in field['repeat']:
                rs['single'] = field['repeat']['single']
            if rs['store'] == 'list':
                result += INDENT + f'self.{rs["name"]} = []\n'
            elif rs['store'] == 'dict':
                result += INDENT + f'self.{rs["name"]} = ' + '{}\n'
            elif rs['store'] == 'string':
                result += INDENT + f'self.{rs["name"]} = raw[self.STRUCT.size:(self.STRUCT.size + self.{field["name"]})]\n'
                continue
            result += INDENT + f'for i in range(self.{field["name"]}):\n'
            result += INDENT * 2 + 'rf = self.REPEATED.unpack_from(raw, self.STRUCT.size + (i * self.REPEATED.size))\n'

            if 'key_format' in rs:
                fstr = rs['key_format']
                i = 0
                for f in raw['repeated']:
                    if 'name' not in f:
                        continue
                    fstr = fstr.replace('{' + f['name'] + '}', '{rf[' + str(i) + ']}')
                    i += 1
                result += INDENT * 2 + f'key = f"{fstr}"\n'

            smap = {}
            j = 0
            for rf in raw['repeated']:
                if rf['type'] == '?':
                    continue
                smap[rf["name"]] = j
                j += 1

            result += INDENT * 2 + f'self.{rs["name"]}'
            if rs['store'] == 'list':
                result += '.append('
            elif rs['store'] == 'dict':
                if 'key_format' in rs:
                    result += f'[key] = '
                else:
                    result += f'[rf[{smap[rs["key"]]}]] = '

            if rs['format'] == 'tuple':
                result += '('
            elif rs['format'] == 'dict':
                result += '{\n'
            elif rs['format'] == 'single':
                pass

            j = 0
            for rf in raw['repeated']:
                if rf['type'] == '?':
                    continue
                if rs['store'] == "dict" and rf["name"] == rs["key"]:
                    j += 1
                    continue
                for srf in load_field(rf, 'rf', j):
                    if rs['format'] == 'tuple':
                        result += f'{srf[1]}, '
                    elif rs['format'] == 'dict':
                        result += INDENT * 3 + f'"{srf[0]}": {srf[1]},\n'
                    elif rs['format'] == 'single':
                        if rs['single'] == rf['name']:
                            result += srf[1]
                j += 1
            if 'calculated' in raw:
                for name in raw['calculated']:
                    cf = raw['calculated'][name]
                    if 'access' not in cf:
                        continue
                    if cf['access'] != 'repeated':
                        continue

                    if rs['format'] == 'tuple':
                        result += f'self.{cf["function"]}(rf[{smap[cf["source"]]}]),'
                    elif rs['format'] == 'dict':
                        result += INDENT * 3 + f'"{name}": self.{cf["function"]}(rf[{smap[cf["source"]]}]),\n'

            if rs['format'] == 'tuple':
                result += ')'
            elif rs['format'] == 'dict':
                result += INDENT * 2 + '}'
            if rs['store'] == 'list':
                result += ')\n'
            elif rs['store'] == 'dict':
                result += '\n'
        i += 1

    if 'calculated' in raw:
        result += "\n"

        enums = {}
        for key in raw['calculated']:
            if raw['calculated'][key]['type'] == 'enum':
                cf = raw['calculated'][key]
                if cf['source'] not in enums:
                    enums[cf['source']] = set()
                enums[cf['source']].add(cf['key'])

        pp = pprint.PrettyPrinter(indent=4, width=120 - 8)
        for field in raw['fields']:
            if field['type'] == '?':
                continue
            if field['name'] in enums:
                lut = {}
                keys = list(sorted(list(enums[field['name']])))
                for key in field['enum']:
                    row = []
                    for k in keys:
                        row.append(field['enum'][key][k])
                    lut[key] = tuple(row)
                lut = textwrap.indent(pp.pformat(lut), INDENT * 2)
                lut = lut.replace('{', ' ').replace('}', '') + '\n' + INDENT + '}'
                result += INDENT + 'lut_' + field['name'] + ' = {\n' + lut + '\n'

        for key in raw['calculated']:
            cf = raw['calculated'][key]
            if 'access' in cf and cf['access'] != 'field':
                continue
            result += INDENT + f'self.{key} = '
            if cf['type'] == 'format':
                fstr = cf['fstring']
                for f in raw['fields']:
                    if 'name' not in f:
                        continue
                    fstr = fstr.replace('{' + f['name'] + '}', '{self.' + f['name'] + '}')
                result += 'f"' + fstr + '"\n'
            elif cf['type'] == 'enum':
                keys = list(sorted(list(enums[cf['source']])))
                index = keys.index(cf["key"])
                result += f'lut_{cf["source"]}[self.{cf["source"]}][{index}]\n'
            elif cf['type'] == 'code':
                result += cf['code']['python'] + '\n'

    return result


def generate_create_uncreate(raw, cname):
    result = ''
    arglist = []
    packlist = []
    uncreatelist = []
    sort_default = sorted(raw['fields'], key=lambda k: 'default' in k)
    for field in sort_default:
        if field['type'] == '?':
            continue
        arg = field['name'] + ': ' + pythontype[field['type']]
        if 'default' in field:
            arg += f' = {repr(field["default"])}'
        arglist.append(arg)
        packlist.append(field['name'])
        uncreatelist.append('self.' + field['name'])
    arglist = ', '.join(arglist)
    packlist = ', '.join(packlist)
    uncreatelist = ', '.join(uncreatelist)
    result += '\n'
    result += '@classmethod\n'
    result += f'def create(cls, {arglist}) -> Self:\n'
    result += INDENT + '"""\n'
    for field in raw['fields']:
        if field['type'] == '?':
            continue
        result += INDENT + f':param {field["name"]}: {field["description"]}'
        if 'default' in field:
            result += f', defaults to {repr(field["default"])}'
        result += '\n'
    result += INDENT + f':return: Instance of {cname} with the data applied\n'
    result += INDENT + '"""\n'
    pcmd = f'raw = cls.STRUCT.pack({packlist})\n'
    result += textwrap.fill(pcmd, width=120, initial_indent=INDENT, subsequent_indent=INDENT * 2) + '\n'
    result += INDENT + 'return cls(raw)\n\n'

    result += f'def uncreate(self) -> tuple:\n'
    result += INDENT + f'"""Create arguments to feed into {cname}.create()"""\n'
    if ',' not in uncreatelist:
        uncreatelist += ','
    result += INDENT + f'return {uncreatelist}\n\n'
    return result


def generate_serialize_restore(raw, cname):
    result = ''
    result += f'def serialize(self) -> dict:\n'
    result += INDENT + f'"""Create dict with the contents of this field for {cname}.restore()"""\n'
    result += INDENT + 'return {\n'
    for field in raw['fields']:
        if field['type'] == '?':
            continue
        result += INDENT * 2 + f'"{field["name"]}": self.{field["name"]},\n'
    result += INDENT + '}\n\n'
    result += 'def instance_id(self) -> tuple:\n'
    result += INDENT + '"""Generate a tuple that uniquely identifies this instance on the hardware"""\n'
    result += INDENT + 'return ('
    for field in raw['fields']:
        if 'unique' in field:
            result += f'self.{field["name"]}, '
    result.rstrip()
    result += ')\n\n'

    result += '@classmethod\n'
    result += f'def restore(cls, data: dict, instance_override=None):\n'
    result += INDENT + f'"""Generate commands to restore the state for this {cname} based on the supplied data."""\n'
    result += INDENT + 'if instance_override is not None:\n'
    i = 0
    for field in raw['fields']:
        if 'unique' in field:
            result += INDENT * 2 + f'data["{field["name"]}"] = instance_override[{i}]\n'
            i += 1

    commands = {}
    for field in raw['fields']:
        if 'restore' not in field:
            continue
        cmds = []
        if isinstance(field['restore'], str):
            cmd = field['restore']
            target = field['name']
            cmds.append((cmd, target))
        elif isinstance(field['restore'], dict):
            cmd = field['restore']['cmd']
            target = field['restore']['key']
            cmds.append((cmd, target))
        elif isinstance(field['restore'], list):
            for item in field['restore']:
                cmds.append((item['cmd'], item['key']))
        else:
            raise RuntimeError("Not implemented")

        for cmd, target in cmds:
            cmd = cmd.replace('-', ' ').title().replace(' ', '') + "Command"
            if cmd not in commands:
                commands[cmd] = []
            commands[cmd].append(f'{target}=data["{field["name"]}"]')
    for cmd in commands:
        result += INDENT + f'from pyatem.command import {cmd}\n'
    result += INDENT + 'return [\n'
    for cmd in commands:
        result += INDENT * 2 + f'{cmd}({", ".join(commands[cmd])}),\n'
    result += INDENT + ']\n'
    result += '\n'
    return result


def generate_repr(raw):
    result = f'def __repr__(self):\n'
    result += INDENT + 'return f"<' + raw['name']
    for field in raw['fields']:
        if 'repr' in field:
            if field['repr'] == 'value':
                result += ' {self.' + field['name'] + '}'
            elif field['repr'] == 'full':
                result += ' ' + field['name'] + '={self.' + field['name'] + '}'
    if 'calculated' in raw:
        for key in raw['calculated']:
            field = raw['calculated'][key]
            if 'access' in field and field['access'] == 'method':
                key += '()'
            if 'repr' in field:
                if field['repr'] == 'value':
                    result += ' {self.' + key + '}'
                elif field['repr'] == 'full':
                    result += ' ' + key + '={self.' + key + '}'

    result += '>"\n\n'
    return result


def generate_calculated(raw, key, cf):
    result = ''
    args = ''
    if 'args' in cf:
        args = ', '
        arglist = []
        for arg in cf['args']:
            a = arg['name']
            if 'type' in arg:
                a += ': ' + arg['type']
            arglist.append(a)
        args += ', '.join(arglist)
    if 'function' in cf:
        key = cf['function']
    if cf['access'] == 'property':
        result += '@property\n'
    result += f'def {key}(self{args}):\n'
    result += INDENT + f'"""{cf["description"]}"""\n'

    if cf['type'] == 'format':
        fstr = cf['fstring']
        for f in raw['fields']:
            fstr = fstr.replace('{' + f['name'] + '}', '{self.' + f['name'] + '}')
        result += 'return f"' + fstr + '"\n'
    elif cf['type'] == 'lut':
        pp = pprint.PrettyPrinter(indent=4, width=120 - 8)
        lut = textwrap.indent(pp.pformat(cf['lut']), INDENT)
        lut = lut.replace('{', ' ').replace('}', '') + '\n' + INDENT + '}'
        result += INDENT + 'lut = {\n' + lut + '\n'
        result += INDENT + f'return lut[self.{cf["source"]}]\n'
    elif cf['type'] == 'code':
        result += textwrap.indent(cf['code']['python'].strip(), INDENT) + "\n"
    return result + "\n"


def make_struct(definition):
    struct_desc = '>'
    offset = 0

    for field in definition:
        if field['type'] == 'bool':
            struct_desc += '?'
        elif field['type'] == '?':
            if field['size'] > 1:
                struct_desc += f'{field["size"]}x'
            else:
                struct_desc += 'x'
        elif field['type'] in ['string', 'bytes'] and isinstance(field['size'], int):
            struct_desc += f'{field["size"]}s'
        elif field['type'] == 'string':
            struct_desc += structtype[field['size']]
        elif field['type'] in structtype:
            struct_desc += structtype[field['type']]

        if field['size'] == 'u8':
            offset += 1
        elif field['size'] == 'u16':
            offset += 2
        else:
            offset += field['size']
        if offset % 4 == 0:
            struct_desc += ' '

    return struct_desc.strip()


def update_descriptions(fields):
    for field in fields:
        if 'max' not in field:
            continue
        max = field['max']
        min = 0
        if 'min' in field:
            min = field['min']
        field['description'] += f', [{min}-{max}]'


def generate_single(path):
    with open(path, 'r') as handle:
        raw = yaml.safe_load(handle)
    code = raw['code']
    ctype = raw['type'].title()
    name = raw['name']
    cname = name.replace('-', ' ').title().replace(' ', '') + ctype

    update_descriptions(raw['fields'])
    if 'repeated' in raw['fields']:
        update_descriptions(raw['repeated'])

    result = f'class {cname}({ctype}Base):\n'
    result += textwrap.indent(generate_docs(raw), prefix=INDENT) + '\n'

    result += INDENT + f'CODE = "{code}"\n'

    struct_desc = make_struct(raw['fields'])
    result += INDENT + f'STRUCT = struct.Struct({repr(struct_desc)})\n'

    if 'repeated' in raw:
        repeated_desc = make_struct(raw['repeated'])
        result += INDENT + f'REPEATED = struct.Struct({repr(repeated_desc)})\n'

    result += '\n'

    constants = generate_enum_constants(raw['fields'])
    if 'repeated' in raw:
        constants += generate_enum_constants(raw['repeated'])
    if len(constants) > 0:
        result += textwrap.indent(constants, INDENT)
        result += '\n'

    result += textwrap.indent(generate_init(raw), INDENT)
    result += textwrap.indent(generate_create_uncreate(raw, cname), INDENT)
    if 'serialize' in raw:
        result += textwrap.indent(generate_serialize_restore(raw, cname), INDENT)

    if 'calculated' in raw:
        for key in raw['calculated']:
            cf = raw['calculated'][key]
            if 'access' not in cf:
                continue
            if cf['access'] not in ['method', 'property', 'repeated']:
                continue
            result += textwrap.indent(generate_calculated(raw, key, cf), INDENT)

    result += textwrap.indent(generate_repr(raw), INDENT)
    return result


def generate_tests(path, filename):
    with open(path, 'r') as handle:
        raw = yaml.safe_load(handle)
    if 'tests' not in raw:
        return None
    ctype = raw['type'].title()
    name = raw['name']
    cname = name.replace('-', ' ').title().replace(' ', '') + ctype

    result = f'from .{filename} import {cname}\n\n'
    result += f'class Test{cname}(TestCase):\n'
    for case in raw['tests']:
        result += INDENT + f'def test_{case["name"]}(self):\n'
        result += INDENT * 2 + f'raw = {repr(bytes.fromhex(case["raw"]))}\n'
        result += INDENT * 2 + f'field = {cname}(raw)\n'
        for fname in case['check']:
            result += INDENT * 2 + f'self.assertEqual({repr(case["check"][fname])}, field.{fname}, msg="{cname}.{fname}")\n'
        result += '\n'

    return result


def make_fieldbase():
    return """
class FieldBase:
    def _get_string(self, raw):
        return raw.split(b'\\x00')[0].decode()

    def make_packet(self):
        code = self.__class__.CODE
        if hasattr(self, 'fieldcode'):
            code = self.fieldcode

        header = struct.pack('!H2x 4s', len(self.raw) + 8, code.encode())
        return header + self.raw

    def serialize(self):
        return None

    @classmethod
    def restore(cls, data, instance_override=None):
        return

    """.strip()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('source', help="Input file or directory with yaml definition files")
    parser.add_argument('--output', '-o', type=argparse.FileType('w'), default='-')
    parser.add_argument('--tests', '-t', action='store_true', help='Generate testcases instead of classes')
    args = parser.parse_args()

    args.output.write("# Generated by generate.py\n")

    if os.path.isdir(args.source):
        if args.tests:
            args.output.write("from unittest import TestCase\n")
            args.output.write("\n\n")
            filename = os.path.basename(args.output.name).replace('.py', '').replace('test_', '')
            for file in glob.glob(os.path.join(args.source, '**/*.yaml')):
                t = generate_tests(file, filename)
                if t is not None:
                    args.output.write(t)
                    args.output.write("\n")
        else:
            args.output.write("import struct\n")
            args.output.write("import colorsys\n")
            args.output.write("from typing import Self\n")
            args.output.write("\n\n")
            args.output.write(make_fieldbase() + "\n\n\n")
            for file in glob.glob(os.path.join(args.source, '**/*.yaml')):
                args.output.write(generate_single(file))
                args.output.write("\n")
    else:
        if args.tests:
            filename = args.output.name
            res = generate_tests(args.source, filename)
        else:
            res = generate_single(args.source)
        args.output.write(res)


if __name__ == '__main__':
    main()
