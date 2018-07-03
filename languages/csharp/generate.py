from asmdot import *  # pylint: disable=W0614

from logzero import logger
from itertools import groupby

header = '''using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net.{}
{{
'''

@handle_command_line()
class CSharpEmitter(Emitter):
    var_map: Dict[str, IrType] = {}
    modified_list: List[str] = []

    @property
    def language(self):
        return 'csharp'

    @property
    def filename(self):
        return f'Asm.Net/{self.arch.capitalize()}.g.cs'

    @property
    def test_filename(self):
        return f'Asm.Net.Tests/{self.arch.capitalize()}.cs'


    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('    ', 1)


    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            'int8'  : 'sbyte',
            'int16' : 'short',
            'int32' : 'int',
            'int64' : 'long',
            'uint8' : 'byte',
            'uint16': 'ushort',
            'uint32': 'uint',
            'uint64': 'ulong',

            r'Reg(\d*)': r'Register\1'
        }, ty.id)
    
    def get_function_name(self, function: Function) -> str:
        return function.initname.capitalize()


    def write_header(self):
        self.write(header.format(self.arch.capitalize()))
    
    def write_separator(self):
        self.writelinei('partial class ', self.arch.capitalize())
        self.writelinei('{')
        self.indent += 1

    def write_footer(self):
        self.writelinei('/// <summary>Assembles an instruction, given its opcode and operands.</summary>')
        self.writelinei('public static bool Assemble(this Stream stream, string opcode, params object[] operands)')
        self.writelinei('{')
        self.indent += 1

        self.writelinei('switch (opcode)')
        self.writelinei('{')
        self.indent += 1

        for name, funs in groupby(self.functions, lambda f: f.initname.lower()):
            self.writelinei('case "', name, '":')
            self.indent += 1
            
            for fun in funs:
                cond = ' && '.join([ f'operands[{i}] is {ctype} {name}' for i, (name, ctype, _) in enumerate(fun.params) ])
                args = ', '.join([ name for name, _, _ in fun.params ])

                L = len(fun.params)

                if L == 0:
                    self.writei('if (operands.Length == 0) { ')
                else:
                    self.writei('if (operands.Length == ', len(fun.params), ' && ', cond, ') { ')

                self.writeline('stream.', fun.name, '(', args, '); return true; }')

            self.writelinei('return false;')
            self.indent -= 1

        self.indent -= 1
        self.writelinei('}')
        self.writelinei('return false;')

        self.indent -= 1
        self.writelinei('}')

        self.write('    }\n}\n')
        self.indent -= 2


    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            if expr.op in (OP_SHL, OP_SHR):
                self.write('(', expr.l, ' ', expr.op, ' (int)', expr.r, ')')
            else:
                self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(', expr.condition, ' ? ', expr.consequence, ' : ', expr.alternative, ')')

        elif isinstance(expr, Var):
            if expr.name in self.modified_list:
                self.write(expr.name, '_')
            else:
                self.write('(', self.var_map[expr.name], ')', expr.name)
        
        elif isinstance(expr, Call):
            self.write(expr.builtin, '(', join_any(', ', expr.args), ')')
        
        elif isinstance(expr, Literal):
            self.write('(', expr.type, ')', expr.value)
        
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
                # Write byte
                self.writelinei('stream.WriteByte(', stmt.value, ');')
            else:
                endian = 'WriteBE' if self.bigendian else 'WriteLE'
                
                self.writelinei('stream.', endian, '((', stmt.type.under, ')', stmt.value, ');')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.type} {stmt.name} = ', stmt.value, ';')
            self.var_map[stmt.name] = stmt.type.under

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writei(f'/// <summary>', fun.descr, '</summary>\n')
        self.writei(f'public static void {fun.name}(this Stream stream')

        for name, typ, usagetyp in fun.params:
            self.write(f', {typ} {name}')
            self.var_map[name] = usagetyp

        self.write(f')\n{self.indent}{{\n')
        self.indent += 1

        for name, typ, usagetyp in fun.params:
            # Define local vars for booleans, in order to allow bitwise operations on them.
            if typ is TYPE_BOOL and usagetyp is not TYPE_BOOL:
                self.writelinei(usagetyp.under, ' ', name, '_ = ', name, ' ? 1 : 0;')
                self.modified_list.append(name)
        
        for condition in fun.conditions:
            self.writei('Debug.Assert(', condition, ', "', condition, '");\n')

        for stmt in fun.body:
            self.write_stmt(stmt) # type: ignore
        
        self.indent -= 1
        self.writei('}\n\n')


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writei('/// <summary>\n')
            self.writei('///   ', decl.descr, '\n')
            self.writei('/// </summary>\n')

            if decl.flags:
                self.writei('[Flags]\n')

            self.writei('public enum ', decl.type, '\n')
            self.writei('{\n')

            for name, value, descr, _ in decl.members + decl.additional_members:
                self.writei('    /// <summary>\n')
                self.writei('    ///   ', descr, '\n')
                self.writei('    /// </summary>\n')
                self.writei('    ', name, ' = ', value, ',\n')

            self.writei('}\n\n')
        
        elif isinstance(decl, DistinctType):
            self.writei('/// <summary>', decl.descr, '</summary>\n')
            self.writei('public struct ', decl.type, '\n')
            self.writei('{\n')
            self.writei('    /// <summary>Underlying value.</summary>\n')
            self.writei('    public readonly ', decl.type.underlying, ' Value;\n\n')
            self.writei('    /// <summary>Converts the wrapper to its underlying value.</summary>\n')
            self.writei('    public static explicit operator ', decl.type.underlying, '(', decl.type, ' wrapper) => wrapper.Value;\n\n')
            self.writei('    /// <summary>Wraps the given underlying value.</summary>\n')
            self.writei('    public static explicit operator ', decl.type, '(', decl.type.underlying, ' value) => new ', decl.type, '(value);\n\n')
            self.writei('    /// <summary>Creates a new ', decl.type, ', given its underlying value.</summary>\n')
            self.writei('    public ', decl.type, '(', decl.type.underlying, ' underlyingValue) { Value = underlyingValue; }\n')
            
            if decl.constants:
                self.write('\n')

            for name, value in decl.constants:
                self.writei('    public static readonly ', decl.type, ' ', name.upper(), ' = new ', decl.type, '(', value, ');\n')

            self.writei('}\n\n')

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        arch = self.arch.capitalize()

        self.write(f'using System.IO;\nusing NUnit.Framework;\nusing Asm.Net.{arch};\n\n')
        self.write(f'namespace Asm.Net.Tests.{arch}\n{{\n')
        self.indent += 1
        self.writelinei( '[TestFixture]')
        self.writelinei(f'public class {arch}Test')
        self.writelinei( '{')
        self.indent += 1

    def write_test_footer(self):
        self.indent -= 1
        self.writei('}\n')
        self.indent -= 1
        self.writei('}\n')

    def write_test(self, test: TestCase):
        self.writelinei('[Test(Description = "', test.name, '")]')
        self.writelinei('public void ', test.name.replace(' ', '_'), '()')
        self.writelinei('{')

        self.indent += 1

        self.writelinei('using (MemoryStream stream = new MemoryStream())')
        self.writelinei('{')

        self.indent += 1

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.type.type}.{arg.const.name}'
            elif isinstance(arg, ArgEnumMember):
                return f'{arg.enum.type}.{arg.member.name}'
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            args_str = ', '.join([ arg_str(arg) for arg in args ])

            self.writelinei('stream.', func.name, '(', args_str, ');')
        
        expected = f'new byte[] {{ {join_any(", ", test.expected)} }}'
        
        self.writeline()
        self.writelinei('Assert.AreEqual(stream.ToArray(), ', expected, ');')
        self.indent -= 1
        self.writelinei('}')
        self.indent -= 1
        self.writelinei('}\n')
