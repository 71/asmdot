#!/usr/bin/python3

import argparse, inspect, logging, logzero, os.path, pathlib, sys

from glob import glob
from io import StringIO
from importlib.util import spec_from_file_location, module_from_spec
from typing import no_type_check, TextIO, IO, List, Tuple

from asm.ast import expressionClasses, statementClasses, Expression, Statement, IrType, Operator, Builtin
from asm.emit import Emitter
from asm.parse import Architecture


# Helpers

def create_default_argument_parser():
    """Creates the default argument parser."""
    parser = argparse.ArgumentParser(description='Generate ASM. sources.',
                                     add_help=False)

    parser.add_argument('-h', '--help', action='store_true',
                        help='Shows a help message that accounts for all chosen architectures and emitters.')

    parser.add_argument('-a', '--arch', action='append', metavar='arch.py', nargs='+',
                        help='Use the specified architecture parser.')
    parser.add_argument('-e', '--emitter', action='append', metavar='emitter.py', nargs='+',
                        help='Use the specified emitter.')
    
    parser.add_argument('-o', '--output', default='build', metavar='output-dir/',
                        help='Change the output directory (default: build).')
    
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity (can be given multiple times to increase it further).')

    return parser

def emitter_hooks(emitter: Emitter):
    """Enters a block in which some global functions are managed by the architecture."""
    def get_stmt_str(x: Statement) -> str:
        s = StringIO(newline='\n')
        emitter.write_stmt(x, s)
        return s.getvalue()
    
    def get_expr_str(x: Expression) -> str:
        s = StringIO(newline='\n')
        emitter.write_expr(x, s)
        return s.getvalue()

    saved = {}

    class Wrapper:
        def __enter__(self):
            for stmtclass in statementClasses:
                saved[stmtclass] = stmtclass.__str__
                stmtclass.__str__ = get_stmt_str
            
            for exprclass in expressionClasses:
                saved[exprclass] = exprclass.__str__
                exprclass.__str__ = get_expr_str
            
            saved[IrType] = IrType.__str__
            IrType.__str__ = lambda x: emitter.get_type_name(x)

            saved[Operator] = Operator.__str__
            Operator.__str__ = lambda x: emitter.get_operator(x)

            saved[Builtin] = Builtin.__str__
            Builtin.__str__ = lambda x: emitter.get_builtin_name(x)
        
        def __exit__(self, *_):
            for k in saved:
                k.__str__ = saved[k]
        
    return Wrapper()

def ensure_directory_exists(path):
    """Ensures that the given directory exists, creating it and its parents if necessary."""
    # pylint: disable=E1101
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)

def relative(*args):
    """Returns the given path, relative to the current file."""
    caller_path = inspect.stack()[1].filename

    return pathlib.Path(caller_path).parent.joinpath(*args)


# Initialize architectures and emitters

archs : List[Architecture] = []
langs : List[type] = []

def execute_in_own_scope(filename: str):
    try:
        spec = spec_from_file_location(os.path.splitext(filename)[0], filename)

        if spec.loader is None:
            print(f'Unable to open file {filename}.', file=sys.stderr)
            return

        module = module_from_spec(spec)
        modulename = module.__name__

        spec.loader.exec_module(module)

        for _, k in inspect.getmembers(module, inspect.isclass):
            if inspect.isabstract(k) or k.__module__ != modulename:
                # Make sure we don't import abstract classes or import classes.
                continue
            
            if issubclass(k, Architecture):
                archs.append(k())
            elif issubclass(k, Emitter):
                langs.append(k)

    except:
        print('Could not load file {}.'.format(filename), file=sys.stderr)
        raise


# Configure logging

args = create_default_argument_parser().parse_args()
verbosity = args.verbose

if verbosity == 0:
    logzero.loglevel(logging.FATAL)
elif verbosity == 1:
    logzero.loglevel(logging.ERROR)
elif verbosity == 2:
    logzero.loglevel(logging.WARN)
elif verbosity == 3:
    logzero.loglevel(logging.INFO)
else:
    logzero.loglevel(logging.DEBUG)


# Load architectures and languages

def flatten(l):
    return [item for subl in l for item in subl]

for arch in flatten(args.arch):
    isinit = os.path.basename(arch) == '__init__.py'

    if isinit:
        execute_in_own_scope(arch)
        continue

    for f in glob(arch):
        if os.path.basename(f) == '__init__.py':
            # Handle glob which matches init file
            continue
    
        execute_in_own_scope(f)

for emitter in flatten(args.emitter):
    isinit = os.path.basename(emitter) == '__init__.py'

    if isinit:
        execute_in_own_scope(emitter)
        continue

    for f in glob(emitter):
        if os.path.basename(f) == '__init__.py':
            # Handle glob which matches init file
            continue
    
        execute_in_own_scope(f)

# Create new parser on top of previous one, but this time
# let loaded modules register new command line parameters,
# then parse arguments AGAIN.

parser = create_default_argument_parser()

for arch in archs:
    arch.__class__.register(parser)
for lang in langs:
    lang.register(parser) # type: ignore

args = parser.parse_args()

if args.help:
    # Stop execution and show help message.
    # We only do this now so that the help message also contains usage of arguments
    # registered by loaded modules.
    parser.print_help()
    quit(0)

for arch in archs:
    arch.initialize(args)


# Translate everything

output_dir = args.output

def translate(arch: Architecture):
    """Translates the given architecture."""
    assert isinstance(arch.name, str)

    with open(relative(f'./asm/data/{arch.name}.txt'), 'r', newline='\n') as i:
        functions = list( arch.translate(i) )

    logzero.logger.debug(f'Translating architecture {arch.name}.')

    for lang in langs:
        emitter : Emitter = lang(args, arch.name)
        emitter.initialize(args)

        logzero.logger.info(f'Initialized language {emitter.language.capitalize()}.')

        if len(langs) == 1:
            output_path = os.path.join(output_dir, emitter.filename)
        else:
            output_path = os.path.join(output_dir, emitter.language, emitter.filename)

        logzero.logger.debug(f'Opening output file {output_path}.')

        ensure_directory_exists(output_path)

        with emitter_hooks(emitter), open(output_path, 'w', newline='\n') as output:
            emitter.write_header(output)

            for decl in arch.declarations or []:
                emitter.write_decl(decl, output)

            emitter.write_separator(output)

            for fun in functions:
                emitter.write_function(fun, output)
            
            emitter.write_footer(output)
        
        logzero.logger.info(f'Translated architecture {arch.name} to {emitter.language.capitalize()}.')

logzero.logger.debug('Initialization done.')

for arch in archs:
    translate(arch)
