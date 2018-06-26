import struct
from enum import Enum, Flag
from typing import NewType

Reg8 = NewType("Reg8", int)
setattr(Reg8, "al", Reg8(0))
setattr(Reg8, "cl", Reg8(1))
setattr(Reg8, "dl", Reg8(2))
setattr(Reg8, "bl", Reg8(3))
setattr(Reg8, "spl", Reg8(4))
setattr(Reg8, "bpl", Reg8(5))
setattr(Reg8, "sil", Reg8(6))
setattr(Reg8, "dil", Reg8(7))
setattr(Reg8, "r8b", Reg8(8))
setattr(Reg8, "r9b", Reg8(9))
setattr(Reg8, "r10b", Reg8(10))
setattr(Reg8, "r11b", Reg8(11))
setattr(Reg8, "r12b", Reg8(12))
setattr(Reg8, "r13b", Reg8(13))
setattr(Reg8, "r14b", Reg8(14))
setattr(Reg8, "r15b", Reg8(15))

Reg16 = NewType("Reg16", int)
setattr(Reg16, "ax", Reg16(0))
setattr(Reg16, "cx", Reg16(1))
setattr(Reg16, "dx", Reg16(2))
setattr(Reg16, "bx", Reg16(3))
setattr(Reg16, "sp", Reg16(4))
setattr(Reg16, "bp", Reg16(5))
setattr(Reg16, "si", Reg16(6))
setattr(Reg16, "di", Reg16(7))
setattr(Reg16, "r8w", Reg16(8))
setattr(Reg16, "r9w", Reg16(9))
setattr(Reg16, "r10w", Reg16(10))
setattr(Reg16, "r11w", Reg16(11))
setattr(Reg16, "r12w", Reg16(12))
setattr(Reg16, "r13w", Reg16(13))
setattr(Reg16, "r14w", Reg16(14))
setattr(Reg16, "r15w", Reg16(15))

Reg32 = NewType("Reg32", int)
setattr(Reg32, "eax", Reg32(0))
setattr(Reg32, "ecx", Reg32(1))
setattr(Reg32, "edx", Reg32(2))
setattr(Reg32, "ebx", Reg32(3))
setattr(Reg32, "esp", Reg32(4))
setattr(Reg32, "ebp", Reg32(5))
setattr(Reg32, "esi", Reg32(6))
setattr(Reg32, "edi", Reg32(7))
setattr(Reg32, "r8d", Reg32(8))
setattr(Reg32, "r9d", Reg32(9))
setattr(Reg32, "r10d", Reg32(10))
setattr(Reg32, "r11d", Reg32(11))
setattr(Reg32, "r12d", Reg32(12))
setattr(Reg32, "r13d", Reg32(13))
setattr(Reg32, "r14d", Reg32(14))
setattr(Reg32, "r15d", Reg32(15))

Reg64 = NewType("Reg64", int)
setattr(Reg64, "rax", Reg64(0))
setattr(Reg64, "rcx", Reg64(1))
setattr(Reg64, "rdx", Reg64(2))
setattr(Reg64, "rbx", Reg64(3))
setattr(Reg64, "rsp", Reg64(4))
setattr(Reg64, "rbp", Reg64(5))
setattr(Reg64, "rsi", Reg64(6))
setattr(Reg64, "rdi", Reg64(7))
setattr(Reg64, "r8", Reg64(8))
setattr(Reg64, "r9", Reg64(9))
setattr(Reg64, "r10", Reg64(10))
setattr(Reg64, "r11", Reg64(11))
setattr(Reg64, "r12", Reg64(12))
setattr(Reg64, "r13", Reg64(13))
setattr(Reg64, "r14", Reg64(14))
setattr(Reg64, "r15", Reg64(15))

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

    def jo(self, operand: int) -> None:
        """Emits a 'jo' instruction."""
        self.buf[self.pos] = 112
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jno(self, operand: int) -> None:
        """Emits a 'jno' instruction."""
        self.buf[self.pos] = 113
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jb(self, operand: int) -> None:
        """Emits a 'jb' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnae(self, operand: int) -> None:
        """Emits a 'jnae' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jc(self, operand: int) -> None:
        """Emits a 'jc' instruction."""
        self.buf[self.pos] = 114
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnb(self, operand: int) -> None:
        """Emits a 'jnb' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jae(self, operand: int) -> None:
        """Emits a 'jae' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnc(self, operand: int) -> None:
        """Emits a 'jnc' instruction."""
        self.buf[self.pos] = 115
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jz(self, operand: int) -> None:
        """Emits a 'jz' instruction."""
        self.buf[self.pos] = 116
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def je(self, operand: int) -> None:
        """Emits a 'je' instruction."""
        self.buf[self.pos] = 116
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnz(self, operand: int) -> None:
        """Emits a 'jnz' instruction."""
        self.buf[self.pos] = 117
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jne(self, operand: int) -> None:
        """Emits a 'jne' instruction."""
        self.buf[self.pos] = 117
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jbe(self, operand: int) -> None:
        """Emits a 'jbe' instruction."""
        self.buf[self.pos] = 118
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jna(self, operand: int) -> None:
        """Emits a 'jna' instruction."""
        self.buf[self.pos] = 118
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnbe(self, operand: int) -> None:
        """Emits a 'jnbe' instruction."""
        self.buf[self.pos] = 119
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def ja(self, operand: int) -> None:
        """Emits a 'ja' instruction."""
        self.buf[self.pos] = 119
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def js(self, operand: int) -> None:
        """Emits a 'js' instruction."""
        self.buf[self.pos] = 120
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jns(self, operand: int) -> None:
        """Emits a 'jns' instruction."""
        self.buf[self.pos] = 121
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jp(self, operand: int) -> None:
        """Emits a 'jp' instruction."""
        self.buf[self.pos] = 122
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jpe(self, operand: int) -> None:
        """Emits a 'jpe' instruction."""
        self.buf[self.pos] = 122
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnp(self, operand: int) -> None:
        """Emits a 'jnp' instruction."""
        self.buf[self.pos] = 123
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jpo(self, operand: int) -> None:
        """Emits a 'jpo' instruction."""
        self.buf[self.pos] = 123
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jl(self, operand: int) -> None:
        """Emits a 'jl' instruction."""
        self.buf[self.pos] = 124
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnge(self, operand: int) -> None:
        """Emits a 'jnge' instruction."""
        self.buf[self.pos] = 124
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnl(self, operand: int) -> None:
        """Emits a 'jnl' instruction."""
        self.buf[self.pos] = 125
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jge(self, operand: int) -> None:
        """Emits a 'jge' instruction."""
        self.buf[self.pos] = 125
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jle(self, operand: int) -> None:
        """Emits a 'jle' instruction."""
        self.buf[self.pos] = 126
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jng(self, operand: int) -> None:
        """Emits a 'jng' instruction."""
        self.buf[self.pos] = 126
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jnle(self, operand: int) -> None:
        """Emits a 'jnle' instruction."""
        self.buf[self.pos] = 127
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def jg(self, operand: int) -> None:
        """Emits a 'jg' instruction."""
        self.buf[self.pos] = 127
        self.pos += 1
        self.buf[self.pos] = operand
        self.pos += 1

    def inc(self, operand: Reg16) -> None:
        """Emits an 'inc' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (64 + operand)
        self.pos += 1

    def inc(self, operand: Reg32) -> None:
        """Emits an 'inc' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (64 + operand)
        self.pos += 1

    def dec(self, operand: Reg16) -> None:
        """Emits a 'dec' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (72 + operand)
        self.pos += 1

    def dec(self, operand: Reg32) -> None:
        """Emits a 'dec' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (72 + operand)
        self.pos += 1

    def push(self, operand: Reg16) -> None:
        """Emits a 'push' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (80 + operand)
        self.pos += 1

    def push(self, operand: Reg32) -> None:
        """Emits a 'push' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (80 + operand)
        self.pos += 1

    def pop(self, operand: Reg16) -> None:
        """Emits a 'pop' instruction."""
        self.buf[self.pos] = (102 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def pop(self, operand: Reg32) -> None:
        """Emits a 'pop' instruction."""
        if (operand > 7):
            self.buf[self.pos] = 65
            self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def pop(self, operand: Reg64) -> None:
        """Emits a 'pop' instruction."""
        self.buf[self.pos] = (72 + get_prefix(operand))
        self.pos += 1
        self.buf[self.pos] = (88 + operand)
        self.pos += 1

    def add(self, reg: Reg8, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_(self, reg: Reg8, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc(self, reg: Reg8, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb(self, reg: Reg8, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_(self, reg: Reg8, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub(self, reg: Reg8, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor(self, reg: Reg8, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp(self, reg: Reg8, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 128
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def add(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def add(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def add(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def add(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def or_(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def or_(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def or_(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def or_(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def adc(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def adc(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def adc(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def adc(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sbb(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sbb(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sbb(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sbb(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def and_(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def and_(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def and_(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def and_(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sub(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sub(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def sub(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def sub(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def xor(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def xor(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def xor(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def xor(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def cmp(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def cmp(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def cmp(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 2

    def cmp(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 129
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        struct.pack_into("<I", self.buf, self.pos, value)
        self.pos += 4

    def add(self, reg: Reg16, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def add(self, reg: Reg32, value: int) -> None:
        """Emits an 'add' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 0)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_(self, reg: Reg16, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def or_(self, reg: Reg32, value: int) -> None:
        """Emits an 'or' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 1)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc(self, reg: Reg16, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def adc(self, reg: Reg32, value: int) -> None:
        """Emits an 'adc' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 2)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb(self, reg: Reg16, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sbb(self, reg: Reg32, value: int) -> None:
        """Emits a 'sbb' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 3)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_(self, reg: Reg16, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def and_(self, reg: Reg32, value: int) -> None:
        """Emits an 'and' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 4)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub(self, reg: Reg16, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def sub(self, reg: Reg32, value: int) -> None:
        """Emits a 'sub' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 5)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor(self, reg: Reg16, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def xor(self, reg: Reg32, value: int) -> None:
        """Emits a 'xor' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 6)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp(self, reg: Reg16, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 102
        self.pos += 1
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

    def cmp(self, reg: Reg32, value: int) -> None:
        """Emits a 'cmp' instruction."""
        self.buf[self.pos] = 131
        self.pos += 1
        self.buf[self.pos] = (reg + 7)
        self.pos += 1
        self.buf[self.pos] = value
        self.pos += 1

