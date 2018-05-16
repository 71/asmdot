from common import disas, libpath

from bindings.python import allocate
from bindings.python.arm import load_arm
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

asm = load_arm(libpath)
disasarm = disas( Cs(CS_ARCH_ARM, CS_MODE_ARM) )

def test_instr_with_no_operand():
    buf, read = allocate(10)

    asm.bkpt(buf)

    assert disasarm(read()) == 'bkpt'
