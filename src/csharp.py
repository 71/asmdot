from common import *  # pylint: disable=W0614

output = None

@architecture_entered
def enter(arch):
    global output

    ensure_directory_exists('bindings/csharp')

    output = open('bindings/csharp/{}.cs'.format(arch.capitalize()), 'w')
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
def define(name, params):
    i = name.find('_')

    fname = name if i == -1 else name[:i]

    output.write('        [DllImport("{}", EntryPoint = "{}", CallingConvention = CallingConvention.Cdecl)]\n'.format(libname, name))
    output.write('        public static {} {}('.format(returntype, fname))

    for (_, ctype, name) in params:
        output.write('{} {}, '.format(ctype, name))

    output.write('ref IntPtr {});\n'.format(bufname))
