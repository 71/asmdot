from asm.emit import *  # pylint: disable=W0614

arm_header = '''
EQ = 0b0000
NE = 0b0001
HS = 0b0010
LO = 0b0011
MI = 0b0100
PL = 0b0101
VS = 0b0110
VC = 0b0111
HI = 0b1000
LS = 0b1001
GE = 0b1010
LT = 0b1011
GT = 0b1100
LE = 0b1101
AL = 0b1110
UN = 0b1111

MODE_USR = 0b10000
MODE_FIQ = 0b10001
MODE_IRQ = 0b10010
MODE_SVC = 0b10011
MODE_ABT = 0b10111
MODE_UND = 0b11011
MODE_SYS = 0b11111

LSL = 0b00
LSR = 0b01
ASR = 0b10
ROR = 0b11

NO_ROTATION = 0b00
ROR8  = 0b01
ROR16 = 0b10
ROR24 = 0b11

FIELDMASK_C = 0b0001
FIELDMASK_X = 0b0010
FIELDMASK_S = 0b0100
FIELDMASK_F = 0b1000

INTERRUPT_F = 0b001
INTERRUPT_I = 0b010
INTERRUPT_A = 0b100
'''

x86_header = '''

'''

class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'{self.arch}.py'
    
    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'reg\d*': 'ctypes.c_ubyte',
            r'(u?int\d+)': r'ctypes.c_\1',
            r'.+': 'ctypes.c_ubyte'
        }, ty.id)
    
    def initialize(self, args: Namespace):
        super().initialize(args)

        if not self.bindings:
            raise UnsupportedOption('no-bindings', 'The Python emitter can only generate bindings.')
        
        self.prefix = 'prefix' in args and args.prefix
        self.indent = Indent('    ')

    def write_header(self, out: IO[str]):
        self.write( 'import ctypes\nfrom . import voidptr, voidptrptr\n\n')

        if self.arch == 'arm':
            self.write(arm_header)
        elif self.arch == 'x86':
            self.write(x86_header)

        self.write(f'def load_{self.arch}(lib: str = "asmdot"):\n')
        self.indent += 1
        self.write(f'"""Loads the ASM. library using the provided path, and returns a wrapper around the {self.arch} architecture."""\n', indent=True)
        self.write( 'asm = ctypes.cdll.LoadLibrary(lib)\n\n', indent=True)

    def write_footer(self, out: IO[str]):
        self.write('return asm', indent=True)
        self.indent -= 1

    def write_expr(self, expr: Expression, out: IO[str]):
        pass
    
    def write_stmt(self, stmt: Statement, out: IO[str]):
        pass

    def write_function(self, fun: Function, out: IO[str]):
        keywords = ['and']
        name = prefix(self, fun.fullname)

        if name in keywords:
            name = f'["{name}"]'
        else:
            name = f'.{name}'

        self.write(f'asm{name}.restype = None\n', indent=True)
        self.write(f'asm{name}.argtypes = [ voidptrptr', indent=True)

        for _, ctype in fun.params:
            self.write(f', {ctype}')

        self.write(' ]\n')

        if self.prefix:
            # Create function name with no prefix, if C API has prefixes.
            name = fun.fullname

            if name in keywords:
                name = f'["{name}"]'
            else:
                name = f'.{name}'

            self.write(f'asm{name} = asm.{self.arch}_{fun.fullname}\n', indent=True)

        self.write('\n')
