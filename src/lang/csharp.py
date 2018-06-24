from asm.emit import *  # pylint: disable=W0614

from logzero import logger

header = '''using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net
{{
'''

class CSharpEmitter(Emitter):
    var_map: Dict[str, IrType] = {}

    @property
    def language(self):
        return 'csharp'

    @property
    def filename(self):
        return f'Asm.Net/{self.arch.capitalize()}.g.cs'
    
    def initialize(self, args: Namespace):
        Emitter.initialize(self, args)

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
    
    def write_header(self):
        self.write(header.format(self.arch.capitalize()))
    
    def write_separator(self):
        self.writelinei('partial class ', self.arch.capitalize())
        self.writelinei('{')
        self.indent += 1

    def write_footer(self):
        self.write('    }\n}\n')

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
            if stmt.type in (TYPE_U8, TYPE_I8):
                # Write byte
                self.writelinei('stream.WriteByte(', stmt.value, ');')
            else:
                self.writelinei('stream.Write(BitConverter.GetBytes((', stmt.type, ')',
                                stmt.value, '), 0, ', stmt.type.size, ');')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.type} {stmt.name} = ', stmt.value, ';')
            self.var_map[stmt.name] = stmt.type.under

        elif not isinstance(stmt, Increase):
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writei(f'/// <summary>', fun.descr, '</summary>\n')
        self.writei(f'public static void {fun.name}(Stream stream')

        for name, typ in fun.params:
            self.write(f', {typ} {name}')
            self.var_map[name] = typ.under

        self.write(f')\n{self.indent}{{\n')
        self.indent += 1

        for name, typ in fun.params:
            # Define local vars for booleans, in order to allow bitwise operations on them.
            if typ is TYPE_BOOL:
                # TODO
                pass
        
        for condition in fun.conditions:
            self.writei('Debug.Assert(', condition, ', "', condition, '");\n')

        for stmt in fun.body:
            self.write_stmt(stmt) # type: ignore
        
        self.indent -= 1
        self.writei('}\n\n')

    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writei('/// <summary>\n')
            self.writei('/// ', decl.descr, '\n')
            self.writei('/// </summary>\n')

            if decl.flags:
                self.writei('[Flags]\n')

            self.writei('public enum ', decl.type, '\n')
            self.writei('{\n')

            for name, value, descr, _ in decl.members + decl.additional_members:
                self.writei('    /// <summary>\n')
                self.writei('    /// ', descr, '\n')
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
