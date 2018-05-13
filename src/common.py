from typing import Callable, Dict, Iterator, IO, Optional, List, Sequence, Union
from src.ir import Expression, Function, Statement, expressionClasses, statementClasses

import inspect
import pathlib
import argparse

def _create_default_argument_parser():
    parser = argparse.ArgumentParser(description='Generate assembler sources and bindings.',
                                     add_help=False)

    parser.add_argument('-h', '--help', action='store_true',
                        help='Shows a help message that accounts for all chosen architectures and emitters.')

    parser.add_argument('-a', '--arch', action='append', metavar='arch.py', required='true',
                        help='Use the specified architecture translator.')
    parser.add_argument('-e', '--emitter', action='append', metavar='emitter.py', required='true',
                        help='Use the specified emitter.')

    parser.add_argument('-p', '--prefix', action='store_true',
                        help='Prefix function names by their architecture.')
    parser.add_argument('-nb', '--no-body', action='store_true',
                        help='Do not generate function bodies, thus only generating function signatures.')
    parser.add_argument('-r', '--return', choices=['size', 'success', 'void'], default='size',
                        help='Specify what functions should return.')
    parser.add_argument('-u', '--update-pointer', action='store_true',
                        help='Updates the value of the given pointer by the increase in index in generated functions.')
    parser.add_argument('-o', '--output', default='build', metavar='OUTPUT-DIR',
                        help='Change the output directory (default: ./build/)')
    
    return parser


# Initialize options and constants

args = _create_default_argument_parser().parse_args()
return_size, return_success = False, False

libname = "asmsq"
output_dir = args.output
mutable_buffer = args.update_pointer
no_body = args.no_body

if getattr(args, 'return') == 'size':
    returntype = 'int'
    return_size = True
elif getattr(args, 'return') == 'success':
    returntype = 'bool'
    return_success = True
else:
    returntype = 'void'


# Decorators

_arg_parsers  : List[Callable[[argparse.ArgumentParser], None]] = []
_initializers : List[Callable[[argparse.Namespace], None]] = []
_arch_enter : List[Callable[[str], None]] = []
_arch_leave : List[Callable[[str], None]] = []
_fun_define : List[Callable[[Function], None]] = []

def add_arguments(f: Callable[[argparse.ArgumentParser], None]):
    """Indicates that this function will be invoked before the initialization of a module, allowing additional arguments to be registered."""
    if f not in _arg_parsers:
        _arg_parsers.append(f)
    return f

def initialize(f: Callable[[argparse.Namespace], None]):
    """Indicates that this function will be invoked during initialization, after parsing every argument."""
    if f not in _initializers:
        _initializers.append(f)
    return f

def architecture_entered(f: Callable[[str], None]):
    """Indicates that this function will be invoked when a new architecture is being translated."""
    if f not in _arch_enter:
        _arch_enter.append(f)
    return f

def architecture_left(f: Callable[[str], None]):
    """Indicates that this function will be invoked when a new architecture is done being translated."""
    if f not in _arch_leave:
        _arch_leave.append(f)
    return f

def function_defined(f: Callable[[Function], None]):
    """Indicates that this function will be invoked when a new function is defined."""
    if f not in _fun_define:
        _fun_define.append(f)
    return f


_architectures: Dict[str, Callable[[], Iterator[Function]]] = {}

def architecture(arch: str):
    """Indicates that this function can translate instructions in the given architecture to IR code."""
    def inner(f: Callable[[], Iterator[Function]]):
        _architectures[arch] = f
        return f
    return inner


# Helpers

OutputType = Union[None, IO[str]]

_arch = None

@architecture_entered
def _set_local_arch(arch):
    """Sets the _arch and _prefix values when the architecture changes."""
    global _arch, _prefix

    _arch = arch

    if args.prefix:
        _prefix = '{}_'.format(arch)

def _ensure_directory_exists(path):
    """Ensures that the given directory exists, creating it and its parents if necessary."""
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)

def _rel(*args):
    """Returns the given path, relative to the current file."""
    if args[0].startswith('~/'):
        return pathlib.Path(output_dir).joinpath(args[0][2:], *args[1:])

    caller_path = inspect.stack()[2].filename

    return pathlib.Path(caller_path).joinpath('..', *args)

def prefixed(name):
    """Returns the given name, with the prefix corresponding to the current architecture added."""
    if args.prefix:
        return f'{arch}_{name}'
    else:
        return name

def read(*args):
    """Opens the file specified by the given path segments for reading."""
    path = _rel(*args)

    _ensure_directory_exists(path)

    return open(path, 'r')

def write(*args):
    """Opens the file specified by the given path segments for writing."""
    path = _rel(*args)

    _ensure_directory_exists(path)

    return open(path, 'w')

def stmts(statements: Sequence[Statement], indent: int = 2, eol: str = '\n') -> str:
    """Returns a string that merges all the given statements together."""
    r, ind = '', ' ' * indent

    for stmt in statements:
        r += ind + str(stmt) + eol

    return r

def visitors(stmtv: Callable[[Statement], str], exprv: Callable[[Expression], str]):
    """Enters a block in which all calls to str(Expression) and str(Statement) are replaced with the given functions."""
    saved = {}

    class VisitorsWrapper:
        def __enter__(self):
            for stmtclass in statementClasses:
                saved[stmtclass] = stmtclass.__str__
                stmtclass.__str__ = stmtv
            
            for exprclass in expressionClasses:
                saved[exprclass] = exprclass.__str__
                exprclass.__str__ = exprv
        
        def __exit__(self, *_):
            for cl, f in saved.items():
                cl.__str__ = f
        
    return VisitorsWrapper()


# Lexer / parser built-ins

from parsy import regex, eof, seq, whitespace, Parser

ws  = regex(r'[ \t]+').desc('whitespace')
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


# Indentation helpers

class Indent:
    """Defines the current indentation."""
    def __init__(self, indent_str: str = '  ', lvl: int = 0) -> None:
        self._str = indent_str
        self._lvl = lvl
    
    def __iadd__(self, i: int) -> 'Indent':
        self._lvl += i

        return self
    
    def __isub__(self, i: int) -> 'Indent':
        self._lvl -= i

        return self
    
    def __add__(self, i: int):
        return Indent(self._str, self._lvl + i)

    def __sub__(self, i: int):
        return Indent(self._str, self._lvl - i)
    
    def further(self, i: int = 1):
        class FurtherWrapper:
            @classmethod
            def __enter__(s, *_):
                self._lvl += i
            @classmethod
            def __exit__(s, *_):
                self._lvl -= i
        
        return FurtherWrapper()

    def __call__(self, fmt: str, *args) -> str:
        return str(self) + (fmt.format(*args) if len(args) else fmt) + '\n'

    def __str__(self) -> str:
        return self._str * self._lvl
