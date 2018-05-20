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

