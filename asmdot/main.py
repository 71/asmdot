#!/usr/bin/python3

import argparse, inspect, logging, logzero, os.path, pathlib, sys

from glob           import glob
from io             import StringIO
from importlib.util import spec_from_file_location, module_from_spec
from typing         import no_type_check, TextIO, IO, List, Tuple

from .ast        import expressionClasses, statementClasses
from .ast        import Expression, Function, Statement, IrType, Operator, Builtin, TestCase
from .emit       import Emitter
from .arch.parse      import Architecture
from .arch.testsource import TestSource




# Initialize architectures and emitters

archs        : List[Architecture] = []
langs        : List[type]         = []
test_sources : List[TestSource]   = []

def load_module(filename: str):
    """Loads all classes inheriting `Architecture` or `Emitter` in the module found at the given path."""
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
            elif issubclass(k, TestSource):
                test_sources.append(k())

    except:
        print('Could not load file {}.'.format(filename), file=sys.stderr)
        raise


# Configure logging

args, _ = create_default_argument_parser().parse_known_args()
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

def load_modules(globs):
    for f in flatten(globs):
        isinit = os.path.basename(f) == '__init__.py'

        if isinit:
            load_module(f)
            continue

        for gf in glob(f):
            if os.path.basename(gf) == '__init__.py':
                # Handle glob which matches init file
                continue
        
            load_module(gf)

load_modules(args.arch)
load_modules(args.emitter)
load_modules(args.test_source or [])

# Create new parser on top of previous one, but this time
# let loaded modules register new command line parameters,
# then parse arguments AGAIN.

parser = create_default_argument_parser()

for arch in archs:
    arch.__class__.register(parser) # type: ignore
for lang in langs:
    lang.register(parser) # type: ignore
for tsrc in test_sources:
    tsrc.__class__.register(parser) # type: ignore

args = parser.parse_args()

if args.help:
    # Stop execution and show help message.
    # We only do this now so that the help message also contains usage of arguments
    # registered by loaded modules.
    parser.print_help()
    quit(0)

for arch in archs:
    arch.initialize(args)
for tsrc in test_sources:
    tsrc.initialize(args)


# Translate everything

root_output_dir = args.output

def translate(arch: Architecture):
    """Translates the given architecture."""
    assert isinstance(arch.name, str)

    with open(relative(f'./data/{arch.name}.txt'), 'r', newline='\n') as i:
        declarations = list( arch.declarations )
        functions    = list( arch.translate(i) )

    test_cases : List[TestCase] = []

    for test_source in test_sources:
        if test_source.arch != arch.name:
            continue
        
        test_source.declarations = declarations
        test_source.functions = functions

        test_cases.extend(test_source.test_cases)

    logzero.logger.debug(f'Translating architecture {arch.name}.')

    for lang in langs:
        emitter : Emitter = lang(args, arch.name)
        emitter.initialize(args)

        logzero.logger.info(f'Initialized language {emitter.language.capitalize()}.')

        if len(langs) > 1:
            output_dir = os.path.join(root_output_dir, emitter.language)
        else:
            output_dir = root_output_dir

        output_path = os.path.join(output_dir, emitter.filename)

        if emitter.test_filename:
            test_path = os.path.join(output_dir, emitter.test_filename)
        else:
            test_path = None

        logzero.logger.debug(f'Opening output file {output_path}.')

        ensure_directory_exists(output_path)
        ensure_directory_exists(test_path)

        with open(output_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
            emitter.write_header()

            for decl in declarations:
                emitter.write_decl(decl)

            emitter.write_separator()

            for fun in functions:
                emitter.write_function(fun)
            
            emitter.write_footer()
        
        if test_path is not None and len(test_cases) > 0:
            logzero.logger.debug(f'Opening output file {output_path}.')

            with open(test_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
                emitter.write_test_header()

                for test_case in test_cases:
                    emitter.write_test(test_case)

                emitter.write_test_footer()

        logzero.logger.info(f'Translated architecture {arch.name} to {emitter.language.capitalize()}.')

logzero.logger.debug('Initialization done.')

for arch in archs:
    translate(arch)
