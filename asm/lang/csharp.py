from asm.emit import *  # pylint: disable=W0614
from asm.lang.c import CEmitter

header = '''using System;
using System.Diagnostics;

namespace Asm.Net
{{
'''

class CSharpEmitter(CEmitter):
    # The C# emitter relies heavily on the C emitter, since most syntactic
    # elements are the same.
    # There are a few changes though (type names, expressions, casts).

    @property
    def language(self):
        return 'csharp'

    @property
    def filename(self):
        return f'{self.arch.capitalize()}.g.cs'
    
    def initialize(self, args: Namespace):
        Emitter.initialize(self, args)

        self.indent = Indent('    ', 1)
        self.unsafe = args.unsafe
    
    @staticmethod
    def register(parser: ArgumentParser):
        Emitter.register(parser)

        group = parser.add_argument_group('C#')
        group.add_argument('--unsafe', action='store_true', help='Use raw pointers instead of IntPtr.')

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
        out.write('\n    }\n}\n')
    
    def write_separator(self, out: IO[str]):
        self.write('partial class ', self.arch.capitalize(), '\n', indent=True)
        self.write('{\n', indent=True)
        self.indent += 1

    def write_function(self, fun: Function, out: IO[str]):
        self.write(f'/// <summary>', fun.descr, '</summary>\n', indent=True)
        self.write(f'public static void {fun.name}(ref IntPtr buffer', indent=True)

        for name, typ in fun.params:
            self.write(f', {typ} {name}')

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

            for name, value, descr in decl.members + decl.additional_members:
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
            self.write('    public static explicit operator ', decl.type, '(', decl.type.underlying, ' value) => new ', decl.type, ' { Value = value };\n', indent=True)
            
            if decl.constants:
                self.write('\n')

            for name, value in decl.constants:
                self.write('    public static readonly ', name.upper(), ' = ', value, ';\n', indent=True)

            self.write('}\n\n', indent=True)

        else:
            raise UnsupportedDeclaration(decl)
