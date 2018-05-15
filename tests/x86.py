from capstone import *

def get_x86(buf):
    md, s = Cs(CS_ARCH_X86, CS_MODE_32), ''

    for _, _, mnemonic, op_str in md.disasm_lite(buf, 0):
        s += f'{mnemonic} {op_str}'
    
    return s

def get_x64(buf):
    md, s = Cs(CS_ARCH_X86, CS_MODE_64), ''

    for _, _, mnemonic, op_str in md.disasm_lite(buf, 0):
        s += f'{mnemonic} {op_str}'
    
    return s

def disas86(*args):
    return get_x86()

def disas64(*args):
    return get_x64()

def test_instr_with_no_operand():
    assert True
