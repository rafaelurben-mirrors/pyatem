import argparse

from pyatem.field import ManualField
from pyatem.protocol import AtemProtocol

parser = argparse.ArgumentParser(description="ATEM simulator model creator")
parser.add_argument('ip', help='IP of ATEM device to model')
parser.add_argument('out', help='Output file for the model')
args = parser.parse_args()

imports = set()


def getfield(code):
    for field in state:
        if field.CODE == code:
            return field


def dump_dict(data, indent, skip, key):
    result = '{\n'
    for name in data:
        if name == 'InCm':
            continue
        if name in skip:
            continue
        field = data[name]
        result += ('    ' * indent) + f'{repr(name)}: '
        if isinstance(field, dict):
            sl = skip
            if name == 'unimplemented':
                sl = set()
            result += dump_dict(field, indent + 1, sl, name) + ',\n'
        elif isinstance(field, bytes):
            imports.add('ManualField')
            code = name
            if isinstance(name, int):
                code = key
            result += f'ManualField(\'{code}\', {repr(field)}),\n'
        elif isinstance(field, ManualField):
            imports.add('ManualField')
            result += f'ManualField(\'{field.fieldcode}\', {repr(field.raw)}),\n'
        else:
            cname = field.__class__.__name__
            imports.add(cname)
            if hasattr(field, 'uncreate'):
                fargs = field.uncreate()
                fargs = list(map(repr, fargs))
                argstring = ', '.join(fargs)
                result += f'{cname}.create({argstring}),\n'
            else:
                result += f'{cname}({repr(field.raw)}),\n'
    result += ('    ' * (indent - 1)) + '}'
    return result


def check_unimplemented():
    codes = set()
    dupes = set()
    missing = set()
    dupcount = dict()
    for field in state:
        if isinstance(field, ManualField):
            code = field.fieldcode
            if code not in dupcount:
                dupcount[code] = 0
            dupcount[code] += 1
            if code in codes:
                dupes.add(code)
            codes.add(code)
    for d in dupes:
        dec = pt.mixerstate[d]
        if not isinstance(dec, dict):
            print(f"Needs decoder: {d} ({dupcount[d]} instances)")
            missing.add(d)
    if len(missing) > 0:
        print(f"Missing {len(missing)} decoders")
    return missing


def passthrough_done():
    order = []
    last = None
    for f in state:
        if f.CODE != last:
            last = f.CODE
            if last not in order:
                order.append(last)

    with open('state_order.py', 'w') as handle:
        handle.write('initial_state_order = [\n')
        for item in order:
            handle.write(f"    '{item}',\n")
        handle.write(']\n')
    print("Initial state received, doing sanity checks...")
    unimplemented = check_unimplemented()

    print("Creating model...")
    nested = pt.mixerstate
    nested['unimplemented'] = {}
    i = 0
    for f in state:
        if f.CODE in unimplemented:
            if f.CODE not in nested['unimplemented']:
                nested['unimplemented'][f.CODE] = {}

            nested['unimplemented'][f.CODE][i] = f
            i += 1

    model = 'from pyatem.simulations import VirtualATEM\n\n\n'
    product = getfield('_pin')
    modelname = product.name.replace(' ', '')
    model += f'class {modelname}(VirtualATEM):\n'
    model += '    def initialize(self):\n'
    model += '        self.state = '
    model += dump_dict(nested, 3, unimplemented, None) + '\n'

    imp = 'from pyatem.field import ' + ', '.join(imports) + '\n'

    with open(args.out, 'w') as handle:
        handle.write(imp + model)
    exit(0)


def proxy_state_change(key, raw):
    if not isinstance(raw, bytes):
        state.append(raw)
    else:
        state.append(ManualField(key, raw))


state = []

pt = AtemProtocol(ip=args.ip)
pt.on('change', proxy_state_change)
pt.on('connected', passthrough_done)
pt.connect()
print("Connecting to device...")
while True:
    pt.loop()
