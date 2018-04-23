from common import *  # pylint: disable=W0614

output = None

@architecture_entered
def enter(arch):
    global output

    ensure_directory_exists('bindings/python')

    output = open('bindings/python/raw.py', 'w')
    output.write("""from cffi import FFI

ffi = FFI()
""")

@architecture_left
def leave(arch):
    global output
    
    output.close()
    output = None

@function_defined
def define(name, params):
    output.write('ffi.cdef("bool {}('.format(prefixed(name)))

    for (_, ctype, _) in params:
        output.write('{}, '.format(ctype))

    output.write('void**);")\n')
