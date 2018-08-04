from asmdot import *  # pylint: disable=W0614

header = '''// Automatically generated file.

#include <cassert>
#include <cstdint>
#include <ostream>

namespace {}
{{
    namespace
    {{
        template<typename T>
        inline uint8_t get_prefix(T& r)
        {{
            if (r.value < 8)
                return r.value;
            
            r.value -= 8;
            return 1;
        }}

        template<typename T>
        inline void write_binary(std::ostream& os, T value, std::streamsize size)
        {{
            os.write(reinterpret_cast<const char*>(&value), size);
        }}

        inline uint16_t swap16(uint16_t value) 
        {{
            return (value << 8) | (value >> 8);
        }}

        inline uint32_t swap32(uint32_t value)
        {{
            value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
            return (value << 16) | (value >> 16);
        }}

        inline uint64_t swap64(uint64_t value)
        {{
            value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
            value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
            return (value << 32) | (value >> 32);
        }}
    }}

'''

@handle_command_line()
class CppEmitter(Emitter):
    var_map: Dict[str, IrType] = {}

    @property
    def language(self):
        return 'cpp'

    @property
    def filename(self):
        if self.header:
            return f'{self.arch}.hpp'
        else:
            return f'src/{self.arch}.cpp'

    @property
    def test_filename(self):
        return f'test/{self.arch}.cpp'


    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'u?int\d+': r'\g<0>_t'
        }, ty.id)
    
    def get_function_name(self, function: Function) -> str:
        if function.initname in ('and', 'not', 'or', 'xor'):
            return function.initname + '_'
        else:
            return function.initname
    

    @staticmethod
    def register(parser: ArgumentParser):
        group = parser.add_argument_group('C++')

        # Useful when overloading is not available, and files have no concept of modules or namespaces.
        group.add_argument('-ah', '--as-header', action='store_true',
                           help='Generate headers instead of regular files.')

    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('    ')
        self.header = args.as_header


    def write_header(self):
        self.write(header.format(self.arch))
        self.indent += 1

    def write_separator(self):
        self.writeline()
    
    def write_footer(self):
        self.indent -= 1
        self.writeline('}')


    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(', expr.condition, ' ? ', expr.consequence, ' : ', expr.alternative, ')')
        
        elif isinstance(expr, Var):
            self.write('(', self.var_map[expr.name], ')', expr.name)
        
        elif isinstance(expr, Call):
            assert( all([ isinstance(arg, Var) for arg in expr.args ]) )

            args_str = ', '.join([ arg.name for arg in expr.args ])

            self.write(expr.builtin, '(', args_str, ')')
        
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
            if stmt.type.under in (TYPE_U8, TYPE_I8):
                self.writelinei('os.put(', stmt.value, ');')
            else:
                size = stmt.type.under.size
                swap = f'swap{size * 8}'

                self.writelinei('#if BIGENDIAN')

                if self.bigendian:
                    self.writelinei('write_binary(os, ', stmt.value, ', ', size, ');')
                    self.writelinei('#else')
                    self.writelinei('write_binary(os, ', swap, '(', stmt.value, '), ', size, ');')
                else:
                    self.writelinei('write_binary(os, ', swap, '(', stmt.value, '), ', size, ');')
                    self.writelinei('#else')
                    self.writelinei('write_binary(os, ', stmt.value, ', ', size, ');')

                self.writelinei('#endif\n')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.type} {stmt.name} = ', stmt.value, ';')

        else:
            raise UnsupportedStatement(stmt)
    
    def write_function(self, fun: Function):
        self.writei(f'std::ostream& {fun.name}(std::ostream& os')

        for name, ctype, usagetyp in fun.params:
            self.write(f', {ctype} {name}')
            self.var_map[name] = usagetyp

        self.write(') {\n')

        self.indent += 1

        for condition in fun.conditions:
            self.writelinei('assert(', condition, ');')

        for stmt in fun.body:
            self.write_stmt(stmt)
        
        self.writelinei('return os;')
        self.indent -= 1
        self.writei('}\n\n')


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writei('///\n')
            self.writei('/// ', decl.descr, '\n')
            self.writei('enum class ', decl.type, ' {\n')

            for name, value, descr, _ in decl.members + decl.additional_members:
                self.writei('    ///\n')
                self.writei('    /// ', descr, '\n')
                self.writei('    ', name, ' = ', value, ',\n')

            self.writei('};\n\n')
        
        elif isinstance(decl, DistinctType):
            self.writelinei('///')
            self.writelinei('/// ', decl.descr, '')
            self.writelinei('struct ', decl.type, ' {')

            with self.indent.further():
                self.writelinei('/// Underlying value.')
                self.writelinei(decl.type.underlying, ' value;\n')
                self.writelinei('/// Creates a new ', decl.type, ', given its underlying value.')
                self.writelinei(decl.type, '(const ', decl.type.underlying, ' underlyingValue) : value(underlyingValue) {}\n')
                self.writelinei('/// Converts the wrapper to its underlying value.')
                self.writelinei('operator ', decl.type.underlying, '() { return value; }\n')

                for name, value in decl.constants:
                    self.writei('static const ', decl.type, ' ', name.upper(), ';\n')
            
            self.writelinei('};\n')

            for name, value in decl.constants:
                self.writei('const ', decl.type, ' ', decl.type, '::', name.upper(), ' = ', value, ';\n')
            
            self.writeline()

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        self.write( '#ifndef ASM_ALL_TESTS\n  #define CATCH_CONFIG_MAIN\n#endif\n\n')
        self.write( '#include <sstream>\n')
        self.write( '#include "catch.hpp"\n')
        self.write(f'#include "../src/{self.arch}.cpp"\n\n')
        self.write( 'using Catch::Matchers::Equals;\n\n')
        self.write( 'using namespace std::string_literals;\n\n')
        self.writei(f'TEST_CASE("{self.arch} tests", "[{self.arch}]") {{\n')
        self.indent += 1
        self.writei('std::ostringstream buf;\n')

    def write_test_footer(self):
        self.indent -= 1
        self.write('}\n')

    def write_test(self, test: TestCase):
        self.writeline()
        self.writei('SECTION("', test.name, '") {\n')
        self.indent += 1

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{self.arch}::{arg.type.type}::{arg.const.name.upper()}'
            elif isinstance(arg, ArgEnumMember):
                return f'{self.arch}::{arg.enum.type}::{arg.member.name}'
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            self.writei(self.arch, '::', func.name, '(buf')

            for arg in args:
                self.write(', ', arg_str(arg))

            self.write(');\n')

        self.writeline()
        self.writei('REQUIRE( buf.tellp() == ', len(test.expected), ' );\n')
        self.writei('REQUIRE_THAT(buf.str(), Equals("', test.expected_string, '"s));\n')
        self.indent -= 1
        self.writei('}\n')
