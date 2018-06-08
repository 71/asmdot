from asm.emit import *  # pylint: disable=W0614

from logzero import logger

header = '''using System;
using System.Diagnostics;
using System.IO;

namespace Asm.Net
{{
'''

def get_type_size(ty: IrType) -> Optional[int]:
    if ty in (TYPE_U8, TYPE_I8):   return None
    if ty in (TYPE_BOOL):          return 1
    if ty in (TYPE_U16, TYPE_I16): return 2
    if ty in (TYPE_U32, TYPE_I32): return 4
    if ty in (TYPE_U64, TYPE_I64): return 8
    
    logger.error(f'Unknown type {ty} in stream write.')
    
    return None

class CSharpEmitter(Emitter):
    diff: int = 0
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
    
    def write_header(self, out: IO[str]):
        out.write(header.format(self.arch.capitalize()))
    
    def write_footer(self, out: IO[str]):
        out.write('    }\n}\n')
    
    def write_separator(self, out: IO[str]):
        self.write('partial class ', self.arch.capitalize(), '\n', indent=True)
        self.write('{\n', indent=True)
        self.indent += 1

    def write_expr(self, expr: Expression, out: IO[str]):
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
            self.diff -= stmt.by

        elif isinstance(stmt, Set):
            size = get_type_size(stmt.type)

            if size is None:
                # Write byte
                self.write('stream.WriteByte(', stmt.value, ');')
                self.diff += 1
            else:
                self.write('stream.Write(BitConverter.GetBytes((', stmt.type, ')', stmt.value, '), 0, ', size, ');')
                self.diff += size

        elif isinstance(stmt, Define):
            self.write(f'{stmt.type} {stmt.name} = ', stmt.value, ';')
            self.var_map[stmt.name] = stmt.type.under

        else:
            assert False

    def write_function(self, fun: Function, out: IO[str]):
        self.write(f'/// <summary>', fun.descr, '</summary>\n', indent=True)
        self.write(f'public static void {fun.name}(Stream stream', indent=True)

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
            self.write('Debug.Assert(', condition, ', "', condition, '");\n', indent=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out) # type: ignore
        
        if self.diff != 0:
            logger.error('Invalid function offset.')

            self.diff = 0
        
        self.indent -= 1
        self.write('}\n\n', indent=True)

    def write_decl(self, decl: Declaration, out: IO[str]):
        if isinstance(decl, Enumeration):
            self.write('/// <summary>\n', indent=True)
            self.write('/// ', decl.descr, '\n', indent=True)
            self.write('/// </summary>\n', indent=True)

            if decl.flags:
                self.write('[Flags]\n', indent=True)

            self.write('public enum ', decl.type, '\n', indent=True)
            self.write('{\n', indent=True)

            for name, value, descr, _ in decl.members + decl.additional_members:
                self.write('    /// <summary>\n', indent=True)
                self.write('    /// ', descr, '\n', indent=True)
                self.write('    /// </summary>\n', indent=True)
                self.write('    ', name, ' = ', value, ',\n', indent=True)

            self.write('}\n\n', indent=True)
        
        elif isinstance(decl, DistinctType):
            self.write('/// <summary>', decl.descr, '</summary>\n', indent=True)
            self.write('public struct ', decl.type, '\n', indent=True)
            self.write('{\n', indent=True)
            self.write('    /// <summary>Underlying value.</summary>\n', indent=True)
            self.write('    public readonly ', decl.type.underlying, ' Value;\n\n', indent=True)
            self.write('    /// <summary>Converts the wrapper to its underlying value.</summary>\n', indent=True)
            self.write('    public static explicit operator ', decl.type.underlying, '(', decl.type, ' wrapper) => wrapper.Value;\n\n', indent=True)
            self.write('    /// <summary>Wraps the given underlying value.</summary>\n', indent=True)
            self.write('    public static explicit operator ', decl.type, '(', decl.type.underlying, ' value) => new ', decl.type, '(value);\n\n', indent=True)
            self.write('    /// <summary>Creates a new ', decl.type, ', given its underlying value.</summary>\n', indent=True)
            self.write('    public ', decl.type, '(', decl.type.underlying, ' underlyingValue) { Value = underlyingValue; }\n', indent=True)
            
            if decl.constants:
                self.write('\n')

            for name, value in decl.constants:
                self.write('    public static readonly ', decl.type, ' ', name.upper(), ' = new ', decl.type, '(', value, ');\n', indent=True)

            self.write('}\n\n', indent=True)

        else:
            raise UnsupportedDeclaration(decl)
