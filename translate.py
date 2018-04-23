import os.path
import sys

# Parse args and initialize common module

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from common import args, _translators, _arch_enter, _arch_leave, _header


# Initialize translators and binders

def execute_in_own_scope(filename):
    # from importlib.util import spec_from_file_location, module_from_spec

    try:
        path = os.path.dirname(filename)
        name, _ = os.path.splitext(os.path.basename(filename))

        if path not in sys.path:
            sys.path.append(path)
        
        exec('import {}'.format(name))
        # spec = spec_from_file_location(name, filename, submodule_search_locations=[])
        # module = module_from_spec(spec)
        # spec.loader.exec_module(module)

        # sys.modules[name] = module
    except:
        print('Could not load file {}.'.format(filename), file=sys.stderr)
        raise

for arch in args.arch:
    execute_in_own_scope(arch)

for binder in args.binder or []:
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
