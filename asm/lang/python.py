from asm.emit import *  # pylint: disable=W0614

class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'{self.arch}.py'
    
    def initialize(self, args: Namespace):
        super().initialize(args)

        if not self.bindings:
            raise UnsupportedOption('no-bindings', 'The Python emitter can only generate bindings.')

    def write_header(self, out: IO[str]):
        out.write('from cffi import FFI\n\nffi = FFI()\n\n')

    def write_expr(self, expr: Expression, out: IO[str]):
        pass
    
    def write_stmt(self, stmt: Statement, out: IO[str]):
        pass

    def write_function(self, fun: Function, out: IO[str]):
        out.write('ffi.cdef("bool {}('.format(fun.fullname))

        for _, ctype in fun.params:
            out.write('{}, '.format(ctype))

        out.write(f'void{"*" if self.mutable_buffer else ""}*);")\n')
