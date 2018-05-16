from asm.emit import *  # pylint: disable=W0614
from asm.lang.c import CEmitter

header = '''using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{{
    partial class {}
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

        self.indent = Indent('    ', 2)
        self.unsafe = args.unsafe
    
    @staticmethod
    def register(parser: ArgumentParser):
        Emitter.register(parser)

        group = parser.add_argument_group('C#')
        group.add_argument('--unsafe', action='store_true', help='Use raw pointers instead of IntPtr.')

    def get_type_name(self, ty: IrType) -> str:
        typemap = {
            'int8'  : 'sbyte',
            'int16' : 'short',
            'int32' : 'int',
            'int64' : 'long',
            'uint8' : 'byte',
            'uint16': 'ushort',
            'uint32': 'uint',
            'uint64': 'ulong',

            'reg8' : 'Register8',
            'reg16': 'Register16',
            'reg32': 'Register32',
            'reg64': 'Register64',
            'condition': 'Condition'
        }

        if ty.original in typemap:
            return typemap[ty.original]
        else:
            return ty.original
    
    def write_header(self, out: IO[str]):
        out.write(header.format(self.arch.capitalize()))
    
    def write_footer(self, out: IO[str]):
        out.write('\n    }\n}\n')

    def write_function(self, fun: Function, out: IO[str]):
        a = 'an' if fun.name[0] in 'aeiouy' else 'a' # words are important, kids

        self.write(f'/// <summary>Emits {a} <c>{fun.name}</c> instruction.</summary>\n', indent=True)

        if self.bindings:
            self.write(f'[DllImport(LIBNAME, EntryPoint = "{fun.fullname}", CallingConvention = CallingConvention.Cdecl)]\n', indent=True)
        
        self.write(f'public static {self.return_type} {fun.name}(', indent=True)

        for name, ctype in fun.params:
            self.write(f'{ctype} {name}, ')

        self.write(f'{"ref " if self.mutable_buffer else ""}IntPtr buffer)', newline=True)

        if self.bindings:
            out.write(';\n')
            return
        
        self.write('{\n', indent=True)
        self.indent += 1

        for stmt in fun.body:
            self.write_stmt(stmt, out)
        
        self.indent -= 1
        self.write('}\n\n', indent=True)
