from glob           import glob
from io             import StringIO
from importlib.util import spec_from_file_location, module_from_spec
from typing         import no_type_check, TextIO, IO, List, Tuple

from .ast        import expressionClasses, statementClasses
from .ast        import Expression, Function, Statement, IrType, Operator, Builtin, TestCase
from .emit       import Emitter
from .arch.testsource import TestSource

def create_default_argument_parser():
    """Creates the default argument parser."""
    import argparse

    parser = argparse.ArgumentParser(description='Generate ASM. sources.',
                                     add_help=False)

    parser.add_argument('-h', '--help', action='store_true',
                        help='Shows a help message that accounts for all chosen architectures and emitters.')

    parser.add_argument('-ns', '--no-source', action='store_true', help='Use the specified emitter.')
    parser.add_argument('-nt', '--no-tests', action='sture_true', help='Use the specified test source.')
    
    parser.add_argument('-o', '--output', default='dist', metavar='output-dir/',
                        help='Change the output directory (default: dist). If multiple emitters are given, created directories will be prefixed by each language name.')
    
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity (can be given multiple times to increase it further).')
    
    return parser

def emitter_hooks(emitter: Emitter, output: IO[str]):
    """Enters a block in which some global functions are managed by the architecture."""
    saved_output = emitter.output
    saved = {}

    def get_stmt_str(x: Statement) -> str:
        s = StringIO(newline = '\n')

        emitter.output = s
        emitter.write_stmt(x)
        emitter.output = output

        return s.getvalue()
    
    def get_expr_str(x: Expression) -> str:
        s = StringIO(newline = '\n')
        
        emitter.output = s
        emitter.write_expr(x)
        emitter.output = output

        return s.getvalue()

    class Wrapper:
        def __enter__(self):
            emitter.output = output

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

            Function.name = property(lambda x: emitter.get_function_name(x))

        def __exit__(self, *_):
            emitter.output = saved_output

            for k in saved:
                k.__str__ = saved[k]
            
            Function.name = lambda x: x.initname

    return Wrapper()

def ensure_directory_exists(path):
    """Ensures that the given directory exists, creating it and its parents if necessary."""
    import pathlib

    # pylint: disable=E1101
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)

def relative(*args):
    """Returns the given path, relative to the current file."""
    import inspect, pathlib

    caller_path = inspect.stack()[1].filename

    return pathlib.Path(caller_path).parent.joinpath(*args)
