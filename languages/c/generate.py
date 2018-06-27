from asmdot import *  # pylint: disable=W0614

header = '''// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV {}

'''


class CEmitter(Emitter):

    @property
    def language(self):
        return 'c'

    @property
    def filename(self):
        if self.header:
            return f'{self.arch}.h'
        else:
            return f'src/{self.arch}.c'

    @property
    def test_filename(self):
        return f'test/{self.arch}.c'


    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'u?int\d+': r'\g<0>_t'
        }, ty.id)
    
    def get_function_name(self, function: Function) -> str:
        if self.prefix:
            return f'{self.arch}_{function.initname}'
        elif function.initname in ('div'):
            return f'{function.initname}_'
        else:
            return function.initname
    

    @staticmethod
    def register(parser: ArgumentParser):
        group = parser.add_argument_group('C')

        # Useful when overloading is not available, and files have no concept of modules or namespaces.
        group.add_argument('-np', '--no-prefix', action='store_true',
                          help='Do not prefix function names by their architecture.')

        group.add_argument('-ah', '--as-header', action='store_true',
                           help='Generate headers instead of regular files.')

        group.add_argument('-cc', '--calling-convention', default='', metavar='CALLING-CONVENTION',
                           help='Specify the calling convention of generated functions.')

    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('    ')
        self.cc : str = args.calling_convention
        self.header = args.as_header
        self.prefix : bool = not args.no_prefix
        self.tests : List[str] = []


    def write_header(self):
        self.write(header.format(self.cc))

        if self.arch == 'x86':
            self.write('#define get_prefix(r) (r > 7 && (r -= 8) == r)\n\n')

    def write_separator(self):
        self.writeline()


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
        self.write(f'void CALLCONV {fun.name}(void** buf')

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


    def write_test_header(self):
        self.write( '#include "greatest.h"\n')
        self.write(f'#include "../{self.arch}.c"\n\n')
    
    def write_test_footer(self):
        self.write('GREATEST_MAIN_DEFS();\n\n')
        self.write('int main(int argc, char** argv) {\n')
        self.indent += 1

        self.writei('GREATEST_MAIN_BEGIN();\n\n')

        for test_name in self.tests:
            self.writei('RUN_TEST(', test_name, ');\n')

        self.writeline()
        self.writei('GREATEST_MAIN_END();\n')

        self.indent -= 1
        self.write('}\n')
        self.tests.clear()

    def write_test(self, test: TestCase):
        name = test.name.replace(' ', '_')

        self.tests.append(name)

        self.write('TEST ', name, '() {\n')
        self.indent += 1

        self.writei('void* buf = malloc(', len(test.expected), ');\n')
        self.writei('void* origin = buf;\n\n')

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.type.type}_{arg.const.name}'
            if isinstance(arg, ArgEnumMember):
                return arg.member.fullname
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            self.writei(func.name, '(&buf')

            for arg in args:
                self.write(', ', arg_str(arg))

            self.write(');\n')

        self.writeline()
        self.writei('ASSERT_EQ((char*)buf, (char*)origin + ', len(test.expected), ');\n')
        self.writei('ASSERT_MEM_EQ(origin, "', test.expected_string, '", ', len(test.expected), ');\n\n')
        self.writei('free(origin);\n')
        self.writei('PASS();\n')
        self.indent -= 1
        
        self.write('}\n\n')
