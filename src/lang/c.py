from src import *  # pylint: disable=W0614

output: OutputType = None
indent: Indent = Indent('    ')

@add_arguments
def add_args(parser: argparse.ArgumentParser):
    group = parser.add_argument_group('c')

    group.add_argument('-cc', '--calling-convention', default='', metavar='CALLING-CONVENTION',
                       help='Specify the calling convention of generated functions.')

header = """
// Automatically generated file.
// Please see ../asm/{}.py for more informations.

#define byte unsigned char
#define bool _Bool
#define CALLCONV %CC

"""

@initialize
def init_header(args):
    global header
    
    header = header.replace('%CC', args.calling_convention)

x86_header = """
#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
"""

arm_header = """
#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define reg byte

typedef enum {
    ///
    /// Equal.
    EQ = 0b0000,
    ///
    /// Not equal.
    NE = 0b0001,
    ///
    /// Carry set.
    CS = 0b0010,
    ///
    /// Unsigned higher or same.
    HS = 0b0010,
    ///
    /// Carry clear.
    CC = 0b0011,
    ///
    /// Unsigned lower.
    LO = 0b0011,
    ///
    /// Minus / negative.
    MI = 0b0100,
    ///
    /// Plus / positive or zero.
    PL = 0b0101,
    ///
    /// Overflow.
    VS = 0b0110,
    ///
    /// No overflow.
    VC = 0b0111,
    ///
    /// Unsigned higher.
    HI = 0b1000,
    ///
    /// Unsigned lower or same.
    LS = 0b1001,
    ///
    /// Signed greater than or equal.
    GE = 0b1010,
    ///
    /// Signed less than.
    LT = 0b1011,
    ///
    /// Signed greater than.
    GT = 0b1100,
    ///
    /// Signed less than or equal.
    LE = 0b1101,
    ///
    /// Always (unconditional).
    AL = 0b1110,
    ///
    /// Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).
    UN = 0b1111
} condition;

typedef enum {
    /// User mode.
    USR = 0b10000,
    /// FIQ (high-speed data transfer) mode.
    FIQ = 0b10001,
    /// IRQ (general-purpose interrupt handling) mode.
    IRQ = 0b10010,
    /// Supervisor mode.
    SVC = 0b10011,
    /// Abort mode.
    ABT = 0b10111,
    /// Undefined mode.
    UND = 0b11011,
    /// System (privileged) mode.
    SYS = 0b11111
} Mode;

"""


def expr(x: Expression) -> str:
    """Translates the given expression to C code."""
    if isinstance(x, Binary):
        return f'({x.l} {x.op} {x.r})'
    if isinstance(x, Unary):
        return f'{x.op}{x.v}'
    if isinstance(x, Ternary):
        return f'({x.condition} ? {x.consequence} : {x.alternative})'
    if isinstance(x, (Var, Param)):
        return x.name
    if isinstance(x, Call):
        return f'{x.builtin}({", ".join(x.args)})'
    if isinstance(x, Literal):
        return str(x.value)

    raise Exception('Invalid expression.')

def stmt(s: Statement) -> str:
    """Translates the given statement to C code."""
    if isinstance(s, Return):
        if s.value:
            return indent(f'return {s.value};')
        else:
            assert()
    if isinstance(s, Assign):
        return indent(f'{s.variable} = {s.value};')
    if isinstance(s, Conditional):
        r = indent(f'if ({s.condition})')

        with indent.further():
            r += str(s.consequence)
        
        if s.alternative:
            r += indent('else')

            with indent.further():
                r += str(s.alternative)

        return r
    if isinstance(s, Block):
        r = ''

        with indent.further(-1):
            r += indent('{')
    
        for stmt in s.statements:
            r += str(stmt)

        with indent.further(-1):
            r += indent('}')
        
        return r
    if isinstance(s, Increase):
        if s.variable:
            return indent(f'{s.variable} += {s.by};')
        else:
            return indent(f'*(byte*)buf += {s.by};')
    if isinstance(s, Set):
        offset = f' + {s.offset}' if s.offset else ''

        if mutable_buffer:
            return indent(f'*({s.type}*)(*buf{offset}) = {s.value};')
        else:
            return indent(f'*({s.type}*)(buf{offset}) = {s.value};')
    if isinstance(s, Define):
        return indent(f'{s.type} {s.name} = {s.value};')
    
    raise Exception('Invalid statement')


@architecture_entered
def enter(arch):
    global output

    output = write(f'~/include/{arch}.c')
    output.write(header)

    if arch == 'x86':
        output.write(x86_header)

        for i, r in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '08', '09', '10', '11', '12', '13', '14', '15']):
            output.write(f'#define r_{r} 0x{i:01x}\n')
    
    elif arch == 'arm':
        output.write(arm_header)

        for i in range(16):
            output.write(f'#define r{i} 0x{i:01x}\n')
        for i, n in enumerate(['a1', 'a2', 'a3', 'a4', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'ip', 'sp', 'lr', 'pc']):
            output.write(f'#define {n} 0x{i:01x}\n')
        for i, n in [ (7, 'wr'), (9, 'sb'), (10, 'sl'), (11, 'fp') ]:
            output.write(f'#define {n} 0x{i:01x}\n')

@architecture_left
def leave(arch):
    global output
    
    output.close()
    output = None

@function_defined
def define(fun: Function):
    global indent

    assert(output is not None)

    output.write(f'{returntype} {prefixed(fun.fullname)}(')

    for name, ctype in fun.params:
        output.write(f'{ctype} {name}, ')

    if mutable_buffer:
        output.write('void** buf)')
    else:
        output.write('void* buf)')
    
    if no_body:
        output.write(';\n')
        return

    output.write(' {\n')

    indent += 1

    with visitors(stmt, expr):
        for s in fun.body:
            output.write(str(s))
        output.write('}\n\n')

        indent -= 1
