from binder import OutputBinder

class PythonBinder(OutputBinder):

    def enter(self, arch):
        self.output = open('bindings/raw.py', 'w')
        self.output.write("""from cffi import FFI

ffi = FFI()
""")

    def leave(self, arch):
        self.output.close()
        self.output = None

    def define(self, name, params):
        self.output.write('ffi.cdef("bool {}('.format(name))

        for (_, ctype, _) in params:
            self.output.write('{}, '.format(ctype))

        self.output.write('void**);")')
