from asm.emit import *  # pylint: disable=W0614

header = '''// Automatically generated file.

#include <assert.h>
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

    def write_header(self):
        self.write(header.format(self.cc))

        if self.arch in ['mips', 'arm']:
            self.write(arm_header)
        elif self.arch == 'x86':
            self.write(x86_header)
        else:
            raise UnsupportedArchitecture(self.arch)
    
    def write_expr(self, expr: Expression):
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
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value, ';')
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if (', stmt.condition, ')')

            with self.indent.further():
                self.write_stmt(stmt.consequence)
            
            if stmt.alternative:
                self.writelinei('else')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)

        elif isinstance(stmt, Block):
            with self.indent.further(-1):
                self.writelinei('{')
        
            for s in stmt.statements:
                self.write_stmt(s)

            with self.indent.further(-1):
                self.writelinei('}')

        elif isinstance(stmt, Set):
            self.writelinei(f'*({stmt.type}*)(*buf) = ', stmt.value, ';')
            self.writelinei(f'*(byte*)buf += {stmt.type.size};')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.type} {stmt.name} = ', stmt.value, ';')

        else:
            raise UnsupportedStatement(stmt)
    
    def write_function(self, fun: Function):
        self.write(f'void CALLCONV {prefix(self, fun.fullname)}(void** buf')

        for name, ctype, _ in fun.params:
            self.write(f', {ctype} {name}')

        self.write(') {\n')

        self.indent += 1

        for condition in fun.conditions:
            self.writelinei('assert(', condition, ');')

        for stmt in fun.body:
            self.write_stmt(stmt)
        
        self.write('}\n\n')
        self.indent -= 1
    
    def write_decl(self, decl: Declaration):
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
