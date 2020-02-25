import struct
from enum import Enum, Flag
from typing import NewType

Reg = NewType("Reg", int)
setattr(Reg, "ZERO", Reg(0))
setattr(Reg, "AT", Reg(1))
setattr(Reg, "V0", Reg(2))
setattr(Reg, "V1", Reg(3))
setattr(Reg, "A0", Reg(4))
setattr(Reg, "A1", Reg(5))
setattr(Reg, "A2", Reg(6))
setattr(Reg, "A3", Reg(7))
setattr(Reg, "T0", Reg(8))
setattr(Reg, "T1", Reg(9))
setattr(Reg, "T2", Reg(10))
setattr(Reg, "T3", Reg(11))
setattr(Reg, "T4", Reg(12))
setattr(Reg, "T5", Reg(13))
setattr(Reg, "T6", Reg(14))
setattr(Reg, "T7", Reg(15))
setattr(Reg, "S0", Reg(16))
setattr(Reg, "S1", Reg(17))
setattr(Reg, "S2", Reg(18))
setattr(Reg, "S3", Reg(19))
setattr(Reg, "S4", Reg(20))
setattr(Reg, "S5", Reg(21))
setattr(Reg, "S6", Reg(22))
setattr(Reg, "S7", Reg(23))
setattr(Reg, "T8", Reg(24))
setattr(Reg, "T9", Reg(25))
setattr(Reg, "K0", Reg(26))
setattr(Reg, "K1", Reg(27))
setattr(Reg, "GP", Reg(28))
setattr(Reg, "SP", Reg(29))
setattr(Reg, "FP", Reg(30))
setattr(Reg, "RA", Reg(31))


class MipsAssembler:
    """Assembler that targets the mips architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

    def sll(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sll' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def movci(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'movci' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def srl(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'srl' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def sra(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sra' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def sllv_r(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sllv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def srlv(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'srlv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def srav(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'srav' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def jr(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'jr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def jalr_r(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'jalr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def movz(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'movz' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def movn(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'movn' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def syscall(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'syscall' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def breakpoint(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'breakpoint' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def sync(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sync' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def mfhi(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mfhi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def mthi(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mthi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def mflo(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mflo' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsllv_r(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsllv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsrlv(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsrlv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsrav(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsrav' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def mult(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mult' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def multu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'multu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def div(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'div' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def divu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'divu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dmult(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dmult' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dmultu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dmultu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def ddiv(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'ddiv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def ddivu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'ddivu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def add(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'add' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def addu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'addu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def sub(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def subu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'subu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def and_(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'and' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def or_(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits an 'or' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def xor(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'xor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def nor(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'nor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def slt(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'slt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def sltu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'sltu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dadd(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dadd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def daddu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'daddu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsub(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsubu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsubu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def tge(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'tge' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def tgeu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'tgeu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def tlt(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'tlt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def tltu(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'tltu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def teq(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'teq' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def tne(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'tne' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsll(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsll' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dslr(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dslr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def dsra(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'dsra' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def mhc0(self, rd: Reg, rs: Reg, rt: Reg, shift: int) -> None:
        """Emits a 'mhc0' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)))
        self.pos += 4

    def btlz(self, rs: Reg, target: int) -> None:
        """Emits a 'btlz' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bgez(self, rs: Reg, target: int) -> None:
        """Emits a 'bgez' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bltzl(self, rs: Reg, target: int) -> None:
        """Emits a 'bltzl' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bgezl(self, rs: Reg, target: int) -> None:
        """Emits a 'bgezl' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def sllv_ri(self, rs: Reg, target: int) -> None:
        """Emits a 'sllv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def tgei(self, rs: Reg, target: int) -> None:
        """Emits a 'tgei' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def jalr_ri(self, rs: Reg, target: int) -> None:
        """Emits a 'jalr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def tlti(self, rs: Reg, target: int) -> None:
        """Emits a 'tlti' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def tltiu(self, rs: Reg, target: int) -> None:
        """Emits a 'tltiu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def teqi(self, rs: Reg, target: int) -> None:
        """Emits a 'teqi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def tnei(self, rs: Reg, target: int) -> None:
        """Emits a 'tnei' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bltzal(self, rs: Reg, target: int) -> None:
        """Emits a 'bltzal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bgezal(self, rs: Reg, target: int) -> None:
        """Emits a 'bgezal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bltzall(self, rs: Reg, target: int) -> None:
        """Emits a 'bltzall' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def bgezall(self, rs: Reg, target: int) -> None:
        """Emits a 'bgezall' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def dsllv_ri(self, rs: Reg, target: int) -> None:
        """Emits a 'dsllv' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def synci(self, rs: Reg, target: int) -> None:
        """Emits a 'synci' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)))
        self.pos += 4

    def addi(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'addi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def addiu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'addiu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def andi(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'andi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def beq(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'beq' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)))
        self.pos += 4

    def blez(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'blez' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)))
        self.pos += 4

    def bne(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'bne' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)))
        self.pos += 4

    def lw(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lw' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def lbu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lbu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def lhu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lhu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def lui(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'lui' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def ori(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits an 'ori' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def sb(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def sh(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def slti(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'slti' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def sltiu(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sltiu' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def sw(self, rs: Reg, rt: Reg, imm: int) -> None:
        """Emits a 'sw' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)))
        self.pos += 4

    def j(self, address: int) -> None:
        """Emits a 'j' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (134217728 | ((address >> 2) & 67108863)))
        self.pos += 4

    def jal(self, address: int) -> None:
        """Emits a 'jal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (201326592 | ((address >> 2) & 67108863)))
        self.pos += 4

