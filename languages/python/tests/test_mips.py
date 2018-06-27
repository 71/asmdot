from asm.mips import *  # pylint: disable=W0614

def should_assemble_single_addi_instruction():
    asm = MipsAssembler(4)

    asm.addi(Reg.T1, Reg.T2, 0)

    assert asm.buf == b"\x00\x00\x49\x21"

