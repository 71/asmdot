def _parse_args():
    import argparse

    parser = argparse.ArgumentParser(description='Generate assembler sources and bindings.')

    parser.add_argument('-a', '--arch', action='append', metavar='arch.py', required='true',
                        help='Use the specified architecture translator.')
    parser.add_argument('-b', '--binder', action='append', metavar='lang.py',
                        help='Use the specified bindings generator.')

    parser.add_argument('-p', '--prefix', action='store_true',
                        help='Prefix function names by their architecture.')
    parser.add_argument('-nb', '--no-body', action='store_true',
                        help='Do not generate function bodies, thus only generating function signatures.')
    parser.add_argument('-r', '--return', choices=['size', 'success', 'void'], default='size',
                        help='Specify what functions should return.')

    parser.add_argument('-o', '--output', default='build', metavar='OUTPUT-DIR',
                        help='Change the output directory (default: ./build/)')
    parser.add_argument('-cc', '--calling-convention', default='', metavar='CALLING-CONVENTION',
                        help='Specify the calling convention of generated functions.')

    return parser.parse_args()

# Initialize options and constants

args = _parse_args()
bufname = "buf"

_prefix = ""

_header = """
// Automatically generated file.
// Please see ../asm/{}.py for more informations.

#define byte unsigned char
#define bool boolean
#define RET(x) %RET
#define CALLCONV %CC

""".replace('%CC', args.calling_convention)

if getattr(args, 'return') == 'size':
    _returntype = 'int'
    _header = _header.replace('%RET', 'return x')
elif getattr(args, 'return') == 'success':
    _returntype = 'bool'
    _header = _header.replace('%RET', 'return x != 0')
else:
    _returntype = 'void'
    _header = _header.replace('%RET', 'return')



# Decorators

_arch_enter = []
_arch_leave = []
_fun_define = []

def architecture_entered(f):
    """Indicates that this function will be invoked when a new architecture is being translated."""
    if f not in _arch_enter:
        _arch_enter.append(f)
    return f

def architecture_left(f):
    """Indicates that this function will be invoked when a new architecture is done being translated."""
    if f not in _arch_leave:
        _arch_leave.append(f)
    return f

def function_defined(f):
    """Indicates that this function will be invoked when a new function is defined."""
    if f not in _fun_define:
        _fun_define.append(f)
    return f


_translators = {}

def translator(arch):
    """Indicates that this function can translate instructions in the given architecture to C code."""
    def inner(f):
        _translators[arch] = f
        return f
    return inner


# Helpers

_arch = None

@architecture_entered
def set_local_arch(arch):
    """Sets the _arch and _prefix values when the architecture changes."""
    global _arch, _prefix

    _arch = arch

    if args.prefix:
        _prefix = '{}_'.format(arch)

def prefixed(name):
    """Returns the given name, with the prefix corresponding to the current architecture added."""
    return '{}_{}'.format(_arch, name)

def pswitch(name):
    """Returns a boolean switch parameter, given its name."""
    return 'switch', 'bool', name

def function(name, body, *params):
    """Produces a C function declaration with the given name, body and parameters."""
    for f in _fun_define:
        f(name, params)

    parameters = ""

    for (kind, ctype, name) in params:
        parameters += '/* {} */ {} {}, '.format(kind, ctype, name)

    sig = '{} CALLCONV {}{}({}void** {})'.format(_returntype, _prefix, name, parameters, bufname)

    if args.no_body:
        return '{};'.format(sig)
    else:
        return '{} {{\n  {}\n}}'.format(sig, body)

def functions(*args):
    """Joins multiple functions together into a single C code string."""
    return '\n'.join(args)

def stmts(*args):
    """Joins multiple statements together into a single C code string."""
    return '\n  '.join(args)

def ret(size):
    """Produces a C return statement, with the given size as output."""
    return 'RET({});'.format(size)


# Lexer / parser built-ins

tokens = (
    'OPCODE', 'MNEMO', 'END'
)

from ply.lex import lex as make_lexer
from ply.yacc import yacc as make_parser

t_ignore = ' \t'
t_MNEMO = r'[a-zA-Z]+'

def t_END(t):
    r'\n+'
    t.lexer.lineno += len(t.value)
    return t

def t_OPCODE(t):
    r'[0-9a-fA-F]+'
    t.value = int(t.value, base=16)
    return t

def t_error(t):
    pass

def p_error(p):
    pass
