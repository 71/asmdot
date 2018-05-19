from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from common import disas
from src.python.arm import ArmAssembler, Mode

disasarm = disas( Cs(CS_ARCH_ARM, CS_MODE_ARM) )

def test_instr_with_no_operand():
    asm = ArmAssembler(10)

    asm.cps(Mode.USR)

    assert disasarm(asm) == 'cps #0x10'
