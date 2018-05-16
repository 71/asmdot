from asm.emit import *  # pylint: disable=W0614

header = '''// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV {}

'''

x86_header = '''
#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
'''

arm_header = '''
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

'''

class CEmitter(Emitter):

    @property
    def language(self):
        return 'c'

    @property
    def filename(self):
        return f'{self.arch}{".h" if self.bindings else ".c"}'
    
    @staticmethod
    def register(parser: ArgumentParser):
        group = parser.add_argument_group('C')

        # Useful when overloading is not available, and files have no concept of modules or namespaces.
        group.add_argument('-p', '--prefix', action='store_true',
                          help='Prefix function names by their architecture.')

        group.add_argument('-cc', '--calling-convention', default='', metavar='CALLING-CONVENTION',
                           help='Specify the calling convention of generated functions.')

    def initialize(self, args: Namespace):
        super().initialize(args)

        self.indent = Indent('    ')
        self.cc : str = args.calling_convention
        self.prefix : bool = args.prefix

    def write_header(self, out: IO[str]):
        out.write(header.format(self.cc))

        if self.arch == 'arm':
            out.write(arm_header)
        elif self.arch == 'x86':
            out.write(x86_header)
        else:
            raise UnsupportedArchitecture(self.arch)
    
    def write_footer(self, out: IO[str]):
        if self.arch == 'arm':
            for i in range(16):
                out.write(f'#define r{i} 0x{i:01x}\n')
            for i, n in enumerate(['a1', 'a2', 'a3', 'a4', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'ip', 'sp', 'lr', 'pc']):
                out.write(f'#define {n} 0x{i:01x}\n')
            for i, n in [ (7, 'wr'), (9, 'sb'), (10, 'sl'), (11, 'fp') ]:
                out.write(f'#define {n} 0x{i:01x}\n')
        elif self.arch == 'x86':
            for i, r in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '08', '09', '10', '11', '12', '13', '14', '15']):
                out.write(f'#define {"r" if isinstance(r, int) else ""}{r} 0x{i:01x}\n')
    
    def write_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            out.write(f'({expr.l} {expr.op} {expr.r})')
        elif isinstance(expr, Unary):
            out.write(f'{expr.op}{expr.v}')
        elif isinstance(expr, Ternary):
            out.write(f'({expr.condition} ? {expr.consequence} : {expr.alternative})')
        elif isinstance(expr, (Var, Param)):
            out.write(expr.name)
        elif isinstance(expr, Call):
            out.write(f'{expr.builtin}({", ".join(expr.args)})')
        elif isinstance(expr, Literal):
            out.write(str(expr.value))
        else:
            assert False

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Return):
            if stmt.value:
                self.write(f'return {stmt.value};')
            else:
                self.write(f'return;')
        elif isinstance(stmt, Assign):
            self.write(f'{stmt.variable} = {stmt.value};')
        elif isinstance(stmt, Conditional):
            self.write(f'if ({stmt.condition})')

            with self.indent.further():
                self.write_stmt(stmt.consequence, out)
            
            if stmt.alternative:
                self.write('else')

                with self.indent.further():
                    self.write_stmt(stmt.alternative, out)

        elif isinstance(stmt, Block):
            with self.indent.further(-1):
                self.write('{')
        
            for s in stmt.statements:
                self.write_stmt(s, out)

            with self.indent.further(-1):
                self.write('}')

        elif isinstance(stmt, Increase):
            if stmt.variable:
                self.write(f'{stmt.variable} += {stmt.by};')
            else:
                self.write(f'*(byte*)buf += {stmt.by};')

        elif isinstance(stmt, Set):
            offset = f' + {stmt.offset}' if stmt.offset else ''

            if self.mutable_buffer:
                self.write(f'*({stmt.type}*)(*buf{offset}) = {stmt.value};')
            else:
                self.write(f'*({stmt.type}*)(buf{offset}) = {stmt.value};')

        elif isinstance(stmt, Define):
            self.write(f'{stmt.type} {stmt.name} = {stmt.value};')

        else:
            assert False
    
    def write_function(self, fun: Function, out: IO[str]):
        name = fun.fullname

        if self.prefix:
            name = f'{self.arch}_{name}'
        
        out.write(f'{self.return_type} CALLCONV {name}(')

        for name, ctype in fun.params:
            out.write(f'{ctype} {name}, ')

        out.write(f'void*{"*" if self.mutable_buffer else ""} buf)')
        
        if self.bindings:
            out.write(';\n')
            return

        out.write(' {\n')

        self.indent += 1

        for stmt in fun.body:
            self.write_stmt(stmt, out)
        
        out.write('}\n\n')
        self.indent -= 1
