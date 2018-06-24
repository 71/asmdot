import struct
from enum import Enum, Flag
from typing import NewType

Reg = NewType("Reg", int)
setattr(Reg, "zero", Reg(0))
setattr(Reg, "at", Reg(1))
setattr(Reg, "v0", Reg(2))
setattr(Reg, "v1", Reg(3))
setattr(Reg, "a0", Reg(4))
setattr(Reg, "a1", Reg(5))
setattr(Reg, "a2", Reg(6))
setattr(Reg, "a3", Reg(7))
setattr(Reg, "t0", Reg(8))
setattr(Reg, "t1", Reg(9))
setattr(Reg, "t2", Reg(10))
setattr(Reg, "t3", Reg(11))
setattr(Reg, "t4", Reg(12))
setattr(Reg, "t5", Reg(13))
setattr(Reg, "t6", Reg(14))
setattr(Reg, "t7", Reg(15))
setattr(Reg, "s0", Reg(16))
setattr(Reg, "s1", Reg(17))
setattr(Reg, "s2", Reg(18))
setattr(Reg, "s3", Reg(19))
setattr(Reg, "s4", Reg(20))
setattr(Reg, "s5", Reg(21))
setattr(Reg, "s6", Reg(22))
setattr(Reg, "s7", Reg(23))
setattr(Reg, "t8", Reg(24))
setattr(Reg, "t9", Reg(25))
setattr(Reg, "k0", Reg(26))
setattr(Reg, "k1", Reg(27))
setattr(Reg, "gp", Reg(28))
setattr(Reg, "sp", Reg(29))
setattr(Reg, "fp", Reg(30))
setattr(Reg, "ra", Reg(31))


class MipsAssembler:
    """Assembler that targets the mips architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

    def add(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'add' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((32 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def addu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'addu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((33 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def and_(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'and' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((36 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def div(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'div' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((26 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def divu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'divu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((27 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def jr(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'jr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((8 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def mfhi(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mfhi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((16 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def mflo(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mflo' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((18 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def mhc0(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mhc0' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((1073741824 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def mult(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mult' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((24 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def multu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'multu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((25 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def nor(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'nor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((39 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def xor(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'xor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((38 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def or(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'or' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((37 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def slt(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'slt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((42 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def sltu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sltu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((43 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def sll(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sll' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((0 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def srl(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'srl' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((2 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def sra(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sra' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((3 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def sub(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((34 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def subu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'subu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((35 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)))
        self.pos += 4

    def addi(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'addi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((536870912 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def addiu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'addiu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((603979776 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def andi(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'andi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((805306368 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def beq(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'beq' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((268435456 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def blez(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'blez' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((402653184 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def bne(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'bne' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((335544320 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def lbu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lbu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2415919104 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def lhu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lhu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2483027968 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def lui(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lui' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((1006632960 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def ori(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'ori' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((872415232 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def sb(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2684354560 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def sh(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2751463424 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def slti(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'slti' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((671088640 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def sltiu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sltiu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((738197504 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def sw(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sw' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2885681152 | (rs << 21)) | (rt << 16)) | imm))
        self.pos += 4

    def j(self, addr: int) -> None:
        """Emits a 'j' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (2885681152 | (67108863 & (addr << 2))))
        self.pos += 4

    def jal(self, addr: int) -> None:
        """Emits a 'jal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (2885681152 | (67108863 & (addr << 2))))
        self.pos += 4

