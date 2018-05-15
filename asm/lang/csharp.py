from asm.emit import *  # pylint: disable=W0614

header = '''using System;
using System.Runtime.InteropServices;

namespace AsmSq
{{
    public static class {}
    {{
        public const string LIBNAME = "asmdot";
'''

class CSharpEmitter(Emitter):
    
    @property
    def language(self):
        return 'csharp'

    @property
    def filename(self):
        return f'{self.arch.capitalize()}.cs'
    
    def __init__(self, args, arg):
        super().__init__(args, arg)
        self.indent = Indent('     ', 2)
    
    def get_type_name(self, ty: IrType) -> str:
        typemap = {
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
    
    def write_expr(self, expr: Expression, out: IO[str]):
        pass
    
    def write_stmt(self, stmt: Statement, out: IO[str]):
        pass
    
    def write_function(self, fun: Function, out: IO[str]):
        if self.bindings:
            self.write(f'[DllImport(LIBNAME, EntryPoint = "{fun.fullname}", CallingConvention = CallingConvention.Cdecl)]\n', indent=True)
        
        self.write(f'public static {self.return_type} {fun.name}(', indent=True)

        for name, ctype in fun.params:
            self.write(f'{ctype} {name}, ')

        self.write(f'{"ref " if self.mutable_buffer else ""}IntPtr buffer)', newline=True)

        if self.bindings:
            out.write(';\n')
            return
        
        out.write(' {\n')

        self.indent += 1

        for stmt in fun.body:
            self.write_stmt(stmt, out)
        
        self.indent -= 1

        out.write('}\n')
