from glob           import glob
from io             import StringIO
from importlib.util import spec_from_file_location, module_from_spec
from typing         import no_type_check, TextIO, IO, List, Tuple

from .ast     import expressionClasses, statementClasses
from .ast     import Expression, Function, Statement, IrType, Operator, Builtin, TestCase
from .emit    import Emitter

def create_default_argument_parser():
    """Creates the default argument parser."""
    import argparse

    parser = argparse.ArgumentParser(description='Generate ASM. sources.',
                                     add_help=False)

    parser.add_argument('-h', '--help', action='store_true',
                        help='Show the help message.')

    parser.add_argument('-ns', '--no-sources', action='store_true', help='Do not generate sources.')
    parser.add_argument('-nt', '--no-tests', action='store_true', help='Do not generate tests.')

    parser.add_argument('-be', '--big-endian', action='store_true',
                        help='Emit integers in big-endian.')
    
    parser.add_argument('-o', '--output', default=None, metavar='output-dir/',
                        help='Change the output directory ' +
                             '(default: directory of calling emitter).')
    
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

def parent(path: str):
    """Returns the parent `Path` of the given path."""
    from pathlib import Path

    return Path(path).parent.resolve()

def relative(*args, up: int = 1):
    """Returns the given path, relative to the current file."""
    import inspect, pathlib

    caller_path = inspect.stack()[up].filename

    return pathlib.Path(caller_path).parent.joinpath(*args)


# Lexer / parser built-ins

from parsy import eof, regex, seq, Parser

ws  = regex(r'[ \t]+').desc('whitespace')
ows = regex(r'[ \t]*').desc('whitespace')
end = (regex(r'\n+') | eof).desc('end of line')

def parse(*args):
    """Creates a parser that maps the given parse to the designated function."""
    if len(args) == 0:
        raise ValueError('At least one parser required.')

    parsers = []

    for arg in args:
        if isinstance(arg, str):
            parsers.append(regex(arg))
        elif isinstance(arg, Parser):
            parsers.append(arg)
        else:
            raise ValueError('Invalid parser provided.')

    if len(args) == 1:
        return parsers[0].map
    else:
        return seq(*parsers).combine


# Logging
from colorama import init, Fore, Style
import logging

init()

def create_logger():
    logger : logging.Logger = logging.getLogger('asm')
    formatter = logging.Formatter('%(message)s')

    console = logging.StreamHandler()
    console.setFormatter(formatter)

    logger.addHandler(console)

    return logger

ASMLOGGER = create_logger()
JUSTWIDTH = 15

def debug(title: str, *args, sep=''):
    ASMLOGGER.debug(Fore.BLUE + title.rjust(JUSTWIDTH) + Style.RESET_ALL + ' ' +
                    sep.join([ str(arg) for arg in args ]))

def info(title: str, *args, sep=''):
    ASMLOGGER.info(Fore.GREEN + title.rjust(JUSTWIDTH) + Style.RESET_ALL + ' ' +
                   sep.join([ str(arg) for arg in args ]))

def error(title: str, *args, sep=''):
    ASMLOGGER.error(Fore.RED + title.rjust(JUSTWIDTH) + Style.RESET_ALL + ' ' +
                    sep.join([ str(arg) for arg in args ]))

def warning(title: str, *args, sep=''):
    ASMLOGGER.warning(Fore.YELLOW + title.rjust(JUSTWIDTH) + Style.RESET_ALL + ' ' +
                      sep.join([ str(arg) for arg in args ]))

def exception(exc: Exception):
    ASMLOGGER.error(exc.__class__.__name__, exc)
