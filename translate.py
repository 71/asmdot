import os.path
import sys

# Parse args and initialize common module

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from common import args, _translators, _arch_enter, _arch_leave, _header


# Initialize translators and binders

def execute_in_own_scope(filename):
    try:
        with open(filename) as file:
            code = compile(file.read(), filename, 'exec')
            locals = { '__file__': filename }
            
            exec(code, locals)
    except:
        print('Could not load file {}.'.format(file.name), file=sys.stderr)
        raise

for arch in args.arch:
    execute_in_own_scope(arch)

for binder in args.binder:
    execute_in_own_scope(binder)


# Translate everything

def translate(arch):
    """Translates the given architecture."""
    for f in _arch_enter:
        f(arch)

    with open('instructions/{}.txt'.format(arch), 'r') as i:
        with open('{}/{}.h'.format(args.output, arch), 'w') as o:
            o.write(_header.format(arch))

            _translators[arch](i, o)

    for f in _arch_leave:
        f(arch)

for arch in _translators:
    translate(arch)
