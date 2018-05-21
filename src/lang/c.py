from asm.emit import *  # pylint: disable=W0614

header = '''// Automatically generated file.

#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV {}

'''

x86_header = '''
#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define get_prefix(r) (r > 7 && (r -= 8) == r)

'''

arm_header = '''

#define reg byte

'''

class CEmitter(Emitter):

    @property
    def language(self):
        return 'c'

    @property
    def filename(self):
        return f'{self.arch}.c'

    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'u?int\d+': r'\g<0>_t'
        }, ty.id)
    
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
    
    def write_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(', expr.condition, ' ? ', expr.consequence, ' : ', expr.alternative, ')')
        
        elif isinstance(expr, Var):
            self.write(expr.name)
        
        elif isinstance(expr, Call):
            self.write(expr.builtin, '(', join_any(', ', expr.args), ')')
        
        elif isinstance(expr, Literal):
            self.write(expr.value)
        
        else:
            assert False

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Assign):
            self.write(stmt.variable, ' = ', stmt.value, ';')
        
        elif isinstance(stmt, Conditional):
            self.write('if (', stmt.condition, ')')

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
            self.write(f'*(byte*)buf += {stmt.by};')

        elif isinstance(stmt, Set):
            self.write(f'*({stmt.type}*)(*buf) = ', stmt.value, ';')

        elif isinstance(stmt, Define):
            self.write(f'{stmt.type} {stmt.name} = ', stmt.value, ';')

        else:
            assert False
    
    def write_function(self, fun: Function, out: IO[str]):
        out.write(f'void CALLCONV {prefix(self, fun.fullname)}(void** buf')

        for name, ctype in fun.params:
            out.write(f', {ctype} {name}')

        out.write(') {\n')

        self.indent += 1

        for condition in fun.conditions:
            self.write('assert(', condition, ');')

        for stmt in fun.body:
            self.write_stmt(stmt, out)
        
        out.write('}\n\n')
        self.indent -= 1
    
    def write_decl(self, decl: Declaration, out: IO[str]):
        if isinstance(decl, Enumeration):
            self.write('///\n')
            self.write('/// ', decl.descr, '\n')
            self.write('typedef enum {\n')

            for _, value, descr, fullname in decl.members + decl.additional_members:
                self.write('    ///\n')
                self.write('    /// ', descr, '\n')
                self.write('    ', fullname, ' = ', value, ',\n')

            self.write('} ', decl.type, ';\n\n')
        
        elif isinstance(decl, DistinctType):
            self.write('#define ', decl.type, ' ', decl.type.underlying, '\n')

            for name, value in decl.constants:
                self.write('#define ', decl.type, '_', name, ' ', value, '\n')

        else:
            raise UnsupportedDeclaration(decl)
