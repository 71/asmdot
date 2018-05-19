from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from common import disas
from src.python.x86 import X86Assembler

disasx86 = disas( Cs(CS_ARCH_X86, CS_MODE_32) )
disasx64 = disas( Cs(CS_ARCH_X86, CS_MODE_64) )

def test_instr_with_no_operand():
    asm = X86Assembler(10)

    asm.ret()

    assert disasx86(asm) == 'ret'
    assert disasx64(asm) == 'ret'
