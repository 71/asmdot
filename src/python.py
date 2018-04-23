from common import architecture_entered, architecture_left, function_defined
from pathlib import Path

output = None

@architecture_entered
def enter(arch):
    global output

    Path('bindings/python').mkdir(parents=True, exist_ok=True)

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
    output.write('ffi.cdef("bool {}('.format(name))

    for (_, ctype, _) in params:
        output.write('{}, '.format(ctype))

    output.write('void**);")\n')
