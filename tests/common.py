from capstone import Cs
from os import path
from sys import path as syspath, platform

def disas(md: Cs):
    """Returns a function that, given a buffer, disassembles a string."""

    def inner(asm):
        s = ''

        for _, _, mnemonic, op_str in md.disasm_lite(bytes(asm.buf)[:asm.pos], 0):
            if len(s):
                s += '\n'

            if op_str:
                s += f'{mnemonic} {op_str}'
            else:
                s += mnemonic

        return s

    return inner

syspath.append( path.join(path.dirname(__file__), '..') )
