import sys

def disas(md):
    """Returns a function that disassembles a string."""

    def inner(buf):
        s = ''

        for _, _, mnemonic, op_str in md.disasm_lite(buf, 0):
            if len(s):
                s += '\n'

            if op_str:
                s += f'{mnemonic} {op_str}'
            else:
                s += f'{mnemonic}'

        return s
    return inner

if sys.platform in ('win32', 'cygwin'):
    libpath = 'build/asmdot.dll'
else:
    libpath = 'build/asmdot.so'
