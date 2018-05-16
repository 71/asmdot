from asm.emit import *  # pylint: disable=W0614

class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'{self.arch}.py'
    
    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'reg\d*': 'unsigned char',
            r'^(?!u?int\d*).+': 'unsigned char'
        }, ty.id)
    
    def initialize(self, args: Namespace):
        super().initialize(args)

        if not self.bindings:
            raise UnsupportedOption('no-bindings', 'The Python emitter can only generate bindings.')
        
        self.prefix = 'prefix' in args and args.prefix

    def write_header(self, out: IO[str]):
        out.write(f'from cffi import FFI\n\n{self.arch}builder = FFI()\n\n')

    def write_footer(self, out: IO[str]):
        out.write(f'\ndef load{self.arch}(libpath = "asmdot"): return {self.arch}builder.dlopen(libpath)\n\n')

    def write_expr(self, expr: Expression, out: IO[str]):
        pass
    
    def write_stmt(self, stmt: Statement, out: IO[str]):
        pass

    def write_function(self, fun: Function, out: IO[str]):
        out.write(f'{self.arch}builder.cdef("{self.return_type} {prefix(self, fun.fullname)}(')

        for _, ctype in fun.params:
            out.write(f'{ctype}, ')

        out.write(f'void{"*" if self.mutable_buffer else ""}*);")\n')
