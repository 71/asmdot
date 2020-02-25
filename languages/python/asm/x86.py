import struct
from enum import Enum, Flag
from typing import NewType

Reg8 = NewType("Reg8", int)
setattr(Reg8, "AL", Reg8(0))
setattr(Reg8, "CL", Reg8(1))
setattr(Reg8, "DL", Reg8(2))
setattr(Reg8, "BL", Reg8(3))
setattr(Reg8, "SPL", Reg8(4))
setattr(Reg8, "BPL", Reg8(5))
setattr(Reg8, "SIL", Reg8(6))
setattr(Reg8, "DIL", Reg8(7))
setattr(Reg8, "R8B", Reg8(8))
setattr(Reg8, "R9B", Reg8(9))
setattr(Reg8, "R10B", Reg8(10))
setattr(Reg8, "R11B", Reg8(11))
setattr(Reg8, "R12B", Reg8(12))
setattr(Reg8, "R13B", Reg8(13))
setattr(Reg8, "R14B", Reg8(14))
setattr(Reg8, "R15B", Reg8(15))

Reg16 = NewType("Reg16", int)
setattr(Reg16, "AX", Reg16(0))
setattr(Reg16, "CX", Reg16(1))
setattr(Reg16, "DX", Reg16(2))
setattr(Reg16, "BX", Reg16(3))
setattr(Reg16, "SP", Reg16(4))
setattr(Reg16, "BP", Reg16(5))
setattr(Reg16, "SI", Reg16(6))
setattr(Reg16, "DI", Reg16(7))
setattr(Reg16, "R8W", Reg16(8))
setattr(Reg16, "R9W", Reg16(9))
setattr(Reg16, "R10W", Reg16(10))
setattr(Reg16, "R11W", Reg16(11))
setattr(Reg16, "R12W", Reg16(12))
setattr(Reg16, "R13W", Reg16(13))
setattr(Reg16, "R14W", Reg16(14))
setattr(Reg16, "R15W", Reg16(15))

Reg32 = NewType("Reg32", int)
setattr(Reg32, "EAX", Reg32(0))
setattr(Reg32, "ECX", Reg32(1))
setattr(Reg32, "EDX", Reg32(2))
setattr(Reg32, "EBX", Reg32(3))
setattr(Reg32, "ESP", Reg32(4))
setattr(Reg32, "EBP", Reg32(5))
setattr(Reg32, "ESI", Reg32(6))
setattr(Reg32, "EDI", Reg32(7))
setattr(Reg32, "R8D", Reg32(8))
setattr(Reg32, "R9D", Reg32(9))
setattr(Reg32, "R10D", Reg32(10))
setattr(Reg32, "R11D", Reg32(11))
setattr(Reg32, "R12D", Reg32(12))
setattr(Reg32, "R13D", Reg32(13))
setattr(Reg32, "R14D", Reg32(14))
setattr(Reg32, "R15D", Reg32(15))

Reg64 = NewType("Reg64", int)
setattr(Reg64, "RAX", Reg64(0))
setattr(Reg64, "RCX", Reg64(1))
setattr(Reg64, "RDX", Reg64(2))
setattr(Reg64, "RBX", Reg64(3))
setattr(Reg64, "RSP", Reg64(4))
setattr(Reg64, "RBP", Reg64(5))
setattr(Reg64, "RSI", Reg64(6))
setattr(Reg64, "RDI", Reg64(7))
setattr(Reg64, "R8", Reg64(8))
setattr(Reg64, "R9", Reg64(9))
setattr(Reg64, "R10", Reg64(10))
setattr(Reg64, "R11", Reg64(11))
setattr(Reg64, "R12", Reg64(12))
setattr(Reg64, "R13", Reg64(13))
setattr(Reg64, "R14", Reg64(14))
setattr(Reg64, "R15", Reg64(15))

Reg128 = NewType("Reg128", int)


class X86Assembler:
    """Assembler that targets the x86 architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

    def pushf(self) -> None:
        """Emits a 'pushf' instruction."""
        self.buf[self.pos] = 156
        self.pos += 1

    def popf(self) -> None:
        """Emits a 'popf' instruction."""
        self.buf[self.pos] = 157
        self.pos += 1

    def ret(self) -> None:
        """Emits a 'ret' instruction."""
        self.buf[self.pos] = 195
        self.pos += 1

    def clc(self) -> None:
        """Emits a 'clc' instruction."""
        self.buf[self.pos] = 248
        self.pos += 1

    def stc(self) -> None:
        """Emits a 'stc' instruction."""
        self.buf[self.pos] = 249
        self.pos += 1

    def cli(self) -> None:
        """Emits a 'cli' instruction."""
        self.buf[self.pos] = 250
        self.pos += 1

    def sti(self) -> None:
        """Emits a 'sti' instruction."""
        self.buf[self.pos] = 251
        self.pos += 1

    def cld(self) -> None:
        """Emits a 'cld' instruction."""
        self.buf[self.pos] = 252
        self.pos += 1

    def std(self) -> None:
        """Emits a 'std' instruction."""
        self.buf[self.pos] = 253
        self.pos += 1

    def jo_imm8(self, operand: int) -> None:
        """Emits a 'jo' instruction."""
        self.buf[self.pos] = 112
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jno_imm8(self, operand: int) -> None:
        """Emits a 'jno' instruction."""
        self.buf[self.pos] = 113
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jb_imm8(self, operand: int) -> None:
        """Emits a 'jb' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnae_imm8(self, operand: int) -> None:
        """Emits a 'jnae' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jc_imm8(self, operand: int) -> None:
        """Emits a 'jc' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnb_imm8(self, operand: int) -> None:
        """Emits a 'jnb' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jae_imm8(self, operand: int) -> None:
        """Emits a 'jae' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnc_imm8(self, operand: int) -> None:
        """Emits a 'jnc' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jz_imm8(self, operand: int) -> None:
        """Emits a 'jz' instruction."""
        self.buf[self.pos] = 116
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def je_imm8(self, operand: int) -> None:
        """Emits a 'je' instruction."""
        self.buf[self.pos] = 116
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnz_imm8(self, operand: int) -> None:
        """Emits a 'jnz' instruction."""
        self.buf[self.pos] = 117
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jne_imm8(self, operand: int) -> None:
        """Emits a 'jne' instruction."""
        self.buf[self.pos] = 117
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jbe_imm8(self, operand: int) -> None:
        """Emits a 'jbe' instruction."""
        self.buf[self.pos] = 118
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jna_imm8(self, operand: int) -> None:
        """Emits a 'jna' instruction."""
        self.buf[self.pos] = 118
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnbe_imm8(self, operand: int) -> None:
        """Emits a 'jnbe' instruction."""
        self.buf[self.pos] = 119
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def ja_imm8(self, operand: int) -> None:
        """Emits a 'ja' instruction."""
        self.buf[self.pos] = 119
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def js_imm8(self, operand: int) -> None:
        """Emits a 'js' instruction."""
        self.buf[self.pos] = 120
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jns_imm8(self, operand: int) -> None:
        """Emits a 'jns' instruction."""
        self.buf[self.pos] = 121
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jp_imm8(self, operand: int) -> None:
        """Emits a 'jp' instruction."""
        self.buf[self.pos] = 122
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jpe_imm8(self, operand: int) -> None:
        """Emits a 'jpe' instruction."""
        self.buf[self.pos] = 122
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnp_imm8(self, operand: int) -> None:
        """Emits a 'jnp' instruction."""
        self.buf[self.pos] = 123
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jpo_imm8(self, operand: int) -> None:
        """Emits a 'jpo' instruction."""
        self.buf[self.pos] = 123
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jl_imm8(self, operand: int) -> None:
        """Emits a 'jl' instruction."""
        self.buf[self.pos] = 124
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnge_imm8(self, operand: int) -> None:
        """Emits a 'jnge' instruction."""
        self.buf[self.pos] = 124
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnl_imm8(self, operand: int) -> None:
        """Emits a 'jnl' instruction."""
        self.buf[self.pos] = 125
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jge_imm8(self, operand: int) -> None:
        """Emits a 'jge' instruction."""
        self.buf[self.pos] = 125
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jle_imm8(self, operand: int) -> None:
        """Emits a 'jle' instruction."""
        self.buf[self.pos] = 126
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jng_imm8(self, operand: int) -> None:
        """Emits a 'jng' instruction."""
        self.buf[self.pos] = 126
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnle_imm8(self, operand: int) -> None:
        """Emits a 'jnle' instruction."""
        self.buf[self.pos] = 127
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jg_imm8(self, operand: int) -> None:
        """Emits a 'jg' instruction."""
        self.buf[self.pos] = 127
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def inc_r16(self, operand: Reg16) -> None:
        """Emits an 'inc' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (64 + operand)
        self.pos += 1

    def inc_r32(self, operand: Reg32) -> None:
        """Emits an 'inc' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (64 + operand)
        self.pos += 1

    def dec_r16(self, operand: Reg16) -> None:
        """Emits a 'dec' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (72 + operand)
        self.pos += 1

    def dec_r32(self, operand: Reg32) -> None:
        """Emits a 'dec' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (72 + operand)
        self.pos += 1

    def push_r16(self, operand: Reg16) -> None:
        """Emits a 'push' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (80 + operand)
        self.pos += 1

    def push_r32(self, operand: Reg32) -> None:
        """Emits a 'push' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (80 + operand)
        self.pos += 1

    def pop_r16(self, operand: Reg16) -> None:
        """Emits a 'pop' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def pop_r32(self, operand: Reg32) -> None:
        """Emits a 'pop' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def pop_r64(self, operand: Reg64) -> None:
        """Emits a 'pop' instruction."""
        self.buf[self.pos] = (72 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def add_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp_rm8_imm8(self, reg: Reg8, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def add_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def add_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def add_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def add_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def or_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def or_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def or_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def or_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def adc_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def adc_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def adc_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def adc_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sbb_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sbb_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sbb_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sbb_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def and_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def and_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def and_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def and_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sub_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sub_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sub_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sub_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def xor_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def xor_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def xor_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def xor_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def cmp_rm16_imm16(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def cmp_rm16_imm32(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def cmp_rm32_imm16(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def cmp_rm32_imm32(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def add_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def add_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp_rm16_imm8(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp_rm32_imm8(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

