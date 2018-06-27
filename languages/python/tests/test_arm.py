from asm.arm import *  # pylint: disable=W0614

def should_encode_single_cps_instruction():
    asm = ArmAssembler(4)

    asm.cps(Mode.USR)

    assert asm.buf == b"\x10\x00\x02\xf1"

