from asm.x86 import *  # pylint: disable=W0614

def should_assemble_single_ret_instruction():
    asm = X86Assembler(1)

    asm.ret()

    assert asm.buf == b"\xc3"

