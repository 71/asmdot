import struct
from enum import Enum, Flag

Reg8 = int

Reg16 = int

Reg32 = int

Reg64 = int

Reg128 = int


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

