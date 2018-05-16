from common import disas, libpath

from bindings.python import allocate
from bindings.python.x86 import load_x86
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

asm = load_x86(libpath)

disasx86 = disas( Cs(CS_ARCH_X86, CS_MODE_32) )
disasx64 = disas( Cs(CS_ARCH_X86, CS_MODE_64) )

def test_instr_with_no_operand():
    buf, read = allocate(10)

    asm.ret(buf)

    assert disasx86(read()) == 'ret'
    assert disasx64(read()) == 'ret'
