from ..common import *  # pylint: disable=W0614

output = OutputType()

typemap = {
    'reg8':  'Register8',
    'reg16': 'Register16',
    'reg32': 'Register32',
    'reg64': 'Register64',
    'condition': 'Condition'
}

@architecture_entered
def enter(arch):
    global output

    output = write(f'~/bindings/csharp/{arch.capitalize()}.cs')
    output.write("""using System;
using System.Runtime.InteropServices;

namespace AsmSq
{{
    public static class {}
    {{
""".format(arch.capitalize()))

@architecture_left
def leave(arch):
    global output
    
    output.write("""
    }
}
""")
    output.close()
    output = None

@function_defined
def define(fun: Function):
    i = fun.name.find('_')

    fname = fun.name if i == -1 else fun.name[:i]

    output.write('        [DllImport("{}", EntryPoint = "{}", CallingConvention = CallingConvention.Cdecl)]\n'.format(libname, fun.name))
    output.write('        public static {} {}('.format(returntype, fname))

    for name, ctype in fun.params:
        if ctype in typemap:
            ctype = typemap[ctype]

        output.write('{} {}, '.format(ctype, name))

    output.write('ref IntPtr {});\n'.format(bufname))
