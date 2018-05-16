from common import disas, libpath

from bindings.python import allocate
from bindings.python.arm import loadarm
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

asm = loadarm(libpath)
disasarm = disas( Cs(CS_ARCH_ARM, CS_MODE_ARM) )

def test_instr_with_no_operand():
    buf, read = allocate(10)

    asm.bkpt(buf)

    assert disasarm(read()) == 'bkpt'
