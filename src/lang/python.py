from ..common import *  # pylint: disable=W0614

output = OutputType()

@architecture_entered
def enter(arch):
    global output

    ensure_directory_exists('bindings/python')

    output = open('bindings/python/{}.py'.format(arch), 'w')
    output.write("""from cffi import FFI

ffi = FFI()
""")

@architecture_left
def leave(arch):
    global output
    
    output.close()
    output = None

@function_defined
def define(fun: Function):
    output.write('ffi.cdef("bool {}('.format(prefixed(fun.name)))

    for _, ctype in fun.params:
        output.write('{}, '.format(ctype))

    output.write('void**);")\n')
