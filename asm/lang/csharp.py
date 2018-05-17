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
        return replace_pattern({
            'int8'  : 'sbyte',
            'int16' : 'short',
            'int32' : 'int',
            'int64' : 'long',
            'uint8' : 'byte',
            'uint16': 'ushort',
            'uint32': 'uint',
            'uint64': 'ulong',

            r'reg(\d*)': r'Register\1',
            'condition': 'Condition'
        }, ty.id)
    
    def write_header(self, out: IO[str]):
        out.write(header.format(self.arch.capitalize()))
    
    def write_footer(self, out: IO[str]):
        out.write('\n    }\n}\n')

    def write_function(self, fun: Function, out: IO[str]):
        a = 'an' if fun.name[0] in 'aeiouy' else 'a' # words are important, kids

        self.write(f'/// <summary>Emits {a} <c>{fun.name}</c> instruction.</summary>\n', indent=True)

        if self.bindings:
            self.write(f'[DllImport(LIBNAME, EntryPoint = "{fun.fullname}", CallingConvention = CallingConvention.Cdecl)]\n', indent=True)
        
        self.write(f'public static void {fun.name}(ref IntPtr buffer', indent=True)

        for name, typ in fun.params:
            self.write(f', {typ} {name}')

        if self.bindings:
            out.write(');\n')
            return
        
        self.write(f')\n{self.indent}{{\n')
        self.indent += 1

        for name, typ in fun.params:
            # Define local vars for booleans, in order to allow bitwise operations on them.
            if typ is TYPE_BOOL:
                # TODO
                pass

        for stmt in fun.body:
            self.write_stmt(stmt, out) # type: ignore
        
        self.indent -= 1
        self.write('}\n\n', indent=True)
