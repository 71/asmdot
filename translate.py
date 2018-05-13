import os.path
import sys
import argparse

from glob import glob
from src.common import _architectures, _arch_enter, _arch_leave, _fun_define, _arg_parsers, _create_default_argument_parser, _initializers

import src.common

# Initialize translators and binders

def execute_in_own_scope(filename):
    if os.path.basename(filename) == '__init__.py':
        return

    try:
        path = os.path.dirname(filename)
        name, _ = os.path.splitext(os.path.basename(filename))
        if path not in sys.path:
            sys.path.append(path)
        
        exec('import {}'.format(name))
    except:
        print('Could not load file {}.'.format(filename), file=sys.stderr)
        raise

_args = _create_default_argument_parser().parse_args()

for arch in _args.arch:
    for f in glob(arch):
        execute_in_own_scope(f)

for emitter in _args.emitter:
    for f in glob(emitter):
        execute_in_own_scope(f)

def create_argument_parser():
    parser = _create_default_argument_parser()

    for argp in _arg_parsers:
        argp(parser)
    
    return parser

_parser = create_argument_parser()
_args = _parser.parse_args()

if _args.help:
    # Stop execution and show help message.
    _parser.print_help()
    quit(0)

src.common.args = _args

for init in _initializers:
    init(_args)


# Translate everything

def translate(arch):
    """Translates the given architecture."""
    for f in _arch_enter:
        f(arch)

    for fun in _architectures[arch]():
        for emitter in _fun_define:
            emitter(fun)
    
    for f in _arch_leave:
        f(arch)

for arch in _architectures:
    translate(arch)
