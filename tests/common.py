from sys import platform
from capstone import Cs

def disas(md: Cs):
    """Returns a function that, given a buffer, disassembles a string."""

    def inner(buf: bytes):
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

if platform in ('win32', 'cygwin'):
    libpath = 'build/asmdot.dll'
else:
    libpath = 'build/asmdot.so'
