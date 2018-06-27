import struct
from enum import Enum, Flag
from typing import NewType

Reg = NewType("Reg", int)
setattr(Reg, "r0", Reg(0))
setattr(Reg, "r1", Reg(1))
setattr(Reg, "r2", Reg(2))
setattr(Reg, "r3", Reg(3))
setattr(Reg, "r4", Reg(4))
setattr(Reg, "r5", Reg(5))
setattr(Reg, "r6", Reg(6))
setattr(Reg, "r7", Reg(7))
setattr(Reg, "r8", Reg(8))
setattr(Reg, "r9", Reg(9))
setattr(Reg, "r10", Reg(10))
setattr(Reg, "r11", Reg(11))
setattr(Reg, "r12", Reg(12))
setattr(Reg, "r13", Reg(13))
setattr(Reg, "r14", Reg(14))
setattr(Reg, "r15", Reg(15))
setattr(Reg, "a1", Reg(0))
setattr(Reg, "a2", Reg(1))
setattr(Reg, "a3", Reg(2))
setattr(Reg, "a4", Reg(3))
setattr(Reg, "v1", Reg(4))
setattr(Reg, "v2", Reg(5))
setattr(Reg, "v3", Reg(6))
setattr(Reg, "v4", Reg(7))
setattr(Reg, "v5", Reg(8))
setattr(Reg, "v6", Reg(9))
setattr(Reg, "v7", Reg(10))
setattr(Reg, "v8", Reg(11))
setattr(Reg, "ip", Reg(12))
setattr(Reg, "sp", Reg(13))
setattr(Reg, "lr", Reg(14))
setattr(Reg, "pc", Reg(15))
setattr(Reg, "wr", Reg(7))
setattr(Reg, "sb", Reg(9))
setattr(Reg, "sl", Reg(10))
setattr(Reg, "fp", Reg(11))

class RegList(int, Flag):
    """A list of ARM registers, where each register corresponds to a single bit."""
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    A1 = 0
    A2 = 1
    A3 = 2
    A4 = 3
    V1 = 4
    V2 = 5
    V3 = 6
    V4 = 7
    V5 = 8
    V6 = 9
    V7 = 10
    V8 = 11
    IP = 12
    SP = 13
    LR = 14
    PC = 15
    WR = 7
    SB = 9
    SL = 10
    FP = 11

Coprocessor = NewType("Coprocessor", int)
setattr(Coprocessor, "cp0", Coprocessor(0))
setattr(Coprocessor, "cp1", Coprocessor(1))
setattr(Coprocessor, "cp2", Coprocessor(2))
setattr(Coprocessor, "cp3", Coprocessor(3))
setattr(Coprocessor, "cp4", Coprocessor(4))
setattr(Coprocessor, "cp5", Coprocessor(5))
setattr(Coprocessor, "cp6", Coprocessor(6))
setattr(Coprocessor, "cp7", Coprocessor(7))
setattr(Coprocessor, "cp8", Coprocessor(8))
setattr(Coprocessor, "cp9", Coprocessor(9))
setattr(Coprocessor, "cp10", Coprocessor(10))
setattr(Coprocessor, "cp11", Coprocessor(11))
setattr(Coprocessor, "cp12", Coprocessor(12))
setattr(Coprocessor, "cp13", Coprocessor(13))
setattr(Coprocessor, "cp14", Coprocessor(14))
setattr(Coprocessor, "cp15", Coprocessor(15))

class Condition(int, Enum):
    """Condition for an ARM instruction to be executed."""
    EQ = 0
    NE = 1
    HS = 2
    LO = 3
    MI = 4
    PL = 5
    VS = 6
    VC = 7
    HI = 8
    LS = 9
    GE = 10
    LT = 11
    GT = 12
    LE = 13
    AL = 14
    UN = 15
    CS = 2
    CC = 3

class Mode(int, Enum):
    """Processor mode."""
    USR = 16
    FIQ = 17
    IRQ = 18
    SVC = 19
    ABT = 23
    UND = 27
    SYS = 31

class Shift(int, Enum):
    """Kind of a shift."""
    LSL = 0
    LSR = 1
    ASR = 2
    ROR = 3
    RRX = 3

class Rotation(int, Enum):
    """Kind of a right rotation."""
    NOP = 0
    ROR8 = 1
    ROR16 = 2
    ROR24 = 3

class FieldMask(int, Flag):
    """Field mask bits."""
    C = 1
    X = 2
    S = 4
    F = 8

class InterruptFlags(int, Flag):
    """Interrupt flags."""
    F = 1
    I = 2
    A = 4

class Addressing(int, Enum):
    """Addressing type."""
    PostIndexed = 0
    PreIndexed = 1
    Offset = 1

class OffsetMode(int, Enum):
    """Offset adding or subtracting mode."""
    Subtract = 0
    Add = 1


class ArmAssembler:
    """Assembler that targets the arm architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

    def adc(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits an 'adc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((10485760 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def add(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits an 'add' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((8388608 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def and_(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits an 'and' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((0 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def eor(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits an 'eor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((2097152 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def orr(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits an 'orr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((25165824 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def rsb(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'rsb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((6291456 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def rsc(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'rsc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((14680064 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def sbc(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'sbc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((12582912 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def sub(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'sub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((4194304 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def bkpt(self, immed: int) -> None:
        """Emits a 'bkpt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((3776970864 or ((immed and 65520) << 8)) or ((immed and 15) << 0)))
        self.pos += 4

    def b(self, cond: Condition) -> None:
        """Emits a 'b' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (167772160 or cond))
        self.pos += 4

    def bic(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'bic' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((29360128 or cond) or (update_cprs << 20)) or (rn << 16)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def blx(self, cond: Condition) -> None:
        """Emits a 'blx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922736 or cond))
        self.pos += 4

    def bx(self, cond: Condition) -> None:
        """Emits a 'bx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922704 or cond))
        self.pos += 4

    def bxj(self, cond: Condition) -> None:
        """Emits a 'bxj' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922720 or cond))
        self.pos += 4

    def blxun(self) -> None:
        """Emits a 'blxun' instruction."""
        struct.pack_into("<I", self.buf, self.pos, 4194304000)
        self.pos += 4

    def clz(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'clz' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((24055568 or cond) or (rd << 12)))
        self.pos += 4

    def cmn(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'cmn' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((24117248 or cond) or (rn << 16)))
        self.pos += 4

    def cmp(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'cmp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((22020096 or cond) or (rn << 16)))
        self.pos += 4

    def cpy(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'cpy' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((27262976 or cond) or (rd << 12)))
        self.pos += 4

    def cps(self, mode: Mode) -> None:
        """Emits a 'cps' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4043440128 or (mode << 0)))
        self.pos += 4

    def cpsie(self, iflags: InterruptFlags) -> None:
        """Emits a 'cpsie' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4043833344 or (iflags << 6)))
        self.pos += 4

    def cpsid(self, iflags: InterruptFlags) -> None:
        """Emits a 'cpsid' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4044095488 or (iflags << 6)))
        self.pos += 4

    def cpsie_mode(self, iflags: InterruptFlags, mode: Mode) -> None:
        """Emits a 'cpsie_mode' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4043964416 or (iflags << 6)) or (mode << 0)))
        self.pos += 4

    def cpsid_mode(self, iflags: InterruptFlags, mode: Mode) -> None:
        """Emits a 'cpsid_mode' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4044226560 or (iflags << 6)) or (mode << 0)))
        self.pos += 4

    def ldc(self, cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((202375168 or cond) or (write << 21)) or (rn << 16)) or (cpnum << 8)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldm(self, cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, copy_spsr: bool) -> None:
        """Emits a 'ldm' instruction."""
        assert ((copy_spsr == 1) ^ (write == (registers and 32768)))

        struct.pack_into("<I", self.buf, self.pos, ((((((((135266304 or cond) or (rn << 16)) or (addressing_mode << 23)) or (offset_mode << 11)) or (addressing_mode << 23)) or registers) or (copy_spsr << 21)) or (write << 10)))
        self.pos += 4

    def ldr(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((68157440 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrb(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldrb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((72351744 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrbt(self, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) -> None:
        """Emits a 'ldrbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((74448896 or cond) or (rn << 16)) or (rd << 12)) or (offset_mode << 23)))
        self.pos += 4

    def ldrd(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldrd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((208 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrex(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrex' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((26218399 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def ldrh(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldrh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((1048752 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrsb(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldrsb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((1048784 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrsh(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'ldrsh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((1048816 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ldrt(self, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) -> None:
        """Emits a 'ldrt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((70254592 or cond) or (rn << 16)) or (rd << 12)) or (offset_mode << 23)))
        self.pos += 4

    def cdp(self, cond: Condition, cpnum: Coprocessor) -> None:
        """Emits a 'cdp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((234881024 or cond) or (cpnum << 8)))
        self.pos += 4

    def mcr(self, cond: Condition, rd: Reg, cpnum: Coprocessor) -> None:
        """Emits a 'mcr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((234881040 or cond) or (rd << 12)) or (cpnum << 8)))
        self.pos += 4

    def mrc(self, cond: Condition, rd: Reg, cpnum: Coprocessor) -> None:
        """Emits a 'mrc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((235929616 or cond) or (rd << 12)) or (cpnum << 8)))
        self.pos += 4

    def mcrr(self, cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) -> None:
        """Emits a 'mcrr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((205520896 or cond) or (rn << 16)) or (rd << 12)) or (cpnum << 8)))
        self.pos += 4

    def mla(self, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) -> None:
        """Emits a 'mla' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((2097296 or cond) or (update_cprs << 20)) or (rn << 12)) or (rd << 16)) or (update_condition << 20)))
        self.pos += 4

    def mov(self, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) -> None:
        """Emits a 'mov' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((27262976 or cond) or (update_cprs << 20)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def mrrc(self, cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) -> None:
        """Emits a 'mrrc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((206569472 or cond) or (rn << 16)) or (rd << 12)) or (cpnum << 8)))
        self.pos += 4

    def mrs(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'mrs' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((17760256 or cond) or (rd << 12)))
        self.pos += 4

    def mul(self, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) -> None:
        """Emits a 'mul' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((144 or cond) or (update_cprs << 20)) or (rd << 16)) or (update_condition << 20)))
        self.pos += 4

    def mvn(self, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) -> None:
        """Emits a 'mvn' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((31457280 or cond) or (update_cprs << 20)) or (rd << 12)) or (update_condition << 20)))
        self.pos += 4

    def msr_imm(self, cond: Condition, fieldmask: FieldMask) -> None:
        """Emits a 'msr_imm' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((52490240 or cond) or (fieldmask << 16)))
        self.pos += 4

    def msr_reg(self, cond: Condition, fieldmask: FieldMask) -> None:
        """Emits a 'msr_reg' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18935808 or cond) or (fieldmask << 16)))
        self.pos += 4

    def pkhbt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'pkhbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109051920 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def pkhtb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'pkhtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109051984 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def pld(self, rn: Reg, offset_mode: OffsetMode) -> None:
        """Emits a 'pld' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4115722240 or (rn << 16)) or (offset_mode << 23)))
        self.pos += 4

    def qadd(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777296 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764304 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764432 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764336 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qdadd(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qdadd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((20971600 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qdsub(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qdsub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((23068752 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qsub(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874448 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764400 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764528 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def qsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764368 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def rev(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'rev' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((113184560 or cond) or (rd << 12)))
        self.pos += 4

    def rev16(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'rev16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((113184688 or cond) or (rd << 12)))
        self.pos += 4

    def revsh(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'revsh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((117378992 or cond) or (rd << 12)))
        self.pos += 4

    def rfe(self, write: bool, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'rfe' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((4161800704 or (write << 21)) or (rn << 16)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def sadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715728 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def sadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715856 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def saddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'saddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715760 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def sel(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sel' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109055920 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def setendbe(self) -> None:
        """Emits a 'setendbe' instruction."""
        struct.pack_into("<I", self.buf, self.pos, 4043375104)
        self.pos += 4

    def setendle(self) -> None:
        """Emits a 'setendle' instruction."""
        struct.pack_into("<I", self.buf, self.pos, 4043374592)
        self.pos += 4

    def shadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812880 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def shadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103813008 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def shaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812912 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def shsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812976 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def shsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103813104 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def shsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812944 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def smlabb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlabb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777344 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlabt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlabt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777376 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlatb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlatb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777408 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlatt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlatt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777440 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlad(self, cond: Condition, exchange: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlad' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((117440528 or cond) or (exchange << 5)) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlal(self, cond: Condition, update_cprs: bool, update_condition: bool) -> None:
        """Emits a 'smlal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((14680208 or cond) or (update_cprs << 20)) or (update_condition << 20)))
        self.pos += 4

    def smlalbb(self, cond: Condition) -> None:
        """Emits a 'smlalbb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971648 or cond))
        self.pos += 4

    def smlalbt(self, cond: Condition) -> None:
        """Emits a 'smlalbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971680 or cond))
        self.pos += 4

    def smlaltb(self, cond: Condition) -> None:
        """Emits a 'smlaltb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971712 or cond))
        self.pos += 4

    def smlaltt(self, cond: Condition) -> None:
        """Emits a 'smlaltt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971744 or cond))
        self.pos += 4

    def smlald(self, cond: Condition, exchange: bool) -> None:
        """Emits a 'smlald' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((121634832 or cond) or (exchange << 5)))
        self.pos += 4

    def smlawb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlawb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874496 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlawt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlawt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874560 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlsd(self, cond: Condition, exchange: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlsd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((117440592 or cond) or (exchange << 5)) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smlsld(self, cond: Condition, exchange: bool) -> None:
        """Emits a 'smlsld' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((121634896 or cond) or (exchange << 5)))
        self.pos += 4

    def smmla(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smmla' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((122683408 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smmls(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smmls' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((122683600 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def smmul(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smmul' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((122744848 or cond) or (rd << 16)))
        self.pos += 4

    def smuad(self, cond: Condition, exchange: bool, rd: Reg) -> None:
        """Emits a 'smuad' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117501968 or cond) or (exchange << 5)) or (rd << 16)))
        self.pos += 4

    def smulbb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulbb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068800 or cond) or (rd << 16)))
        self.pos += 4

    def smulbt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068832 or cond) or (rd << 16)))
        self.pos += 4

    def smultb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smultb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068864 or cond) or (rd << 16)))
        self.pos += 4

    def smultt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smultt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068896 or cond) or (rd << 16)))
        self.pos += 4

    def smull(self, cond: Condition, update_cprs: bool, update_condition: bool) -> None:
        """Emits a 'smull' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((12583056 or cond) or (update_cprs << 20)) or (update_condition << 20)))
        self.pos += 4

    def smulwb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulwb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18874528 or cond) or (rd << 16)))
        self.pos += 4

    def smulwt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulwt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18874592 or cond) or (rd << 16)))
        self.pos += 4

    def smusd(self, cond: Condition, exchange: bool, rd: Reg) -> None:
        """Emits a 'smusd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117502032 or cond) or (exchange << 5)) or (rd << 16)))
        self.pos += 4

    def srs(self, write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'srs' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((4165797120 or (write << 21)) or (mode << 0)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def ssat(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'ssat' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((105906192 or cond) or (rd << 12)))
        self.pos += 4

    def ssat16(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'ssat16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((111152944 or cond) or (rd << 12)))
        self.pos += 4

    def ssub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715824 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def ssub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715952 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def ssubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715792 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def stc(self, cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'stc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((201326592 or cond) or (write << 21)) or (rn << 16)) or (cpnum << 8)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def stm(self, cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, user_mode: bool) -> None:
        """Emits a 'stm' instruction."""
        assert ((user_mode == 0) or (write == 0))

        struct.pack_into("<I", self.buf, self.pos, ((((((((134217728 or cond) or (rn << 16)) or (addressing_mode << 23)) or (offset_mode << 11)) or (addressing_mode << 23)) or registers) or (user_mode << 21)) or (write << 10)))
        self.pos += 4

    def str(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'str' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((67108864 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def strb(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'strb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((71303168 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def strbt(self, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) -> None:
        """Emits a 'strbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((73400320 or cond) or (rn << 16)) or (rd << 12)) or (offset_mode << 23)))
        self.pos += 4

    def strd(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'strd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((240 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def strex(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'strex' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((25169808 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def strh(self, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) -> None:
        """Emits a 'strh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((((176 or cond) or (write << 21)) or (rn << 16)) or (rd << 12)) or (addressing_mode << 23)) or (offset_mode << 11)))
        self.pos += 4

    def strt(self, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) -> None:
        """Emits a 'strt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((69206016 or cond) or (rn << 16)) or (rd << 12)) or (offset_mode << 23)))
        self.pos += 4

    def swi(self, cond: Condition) -> None:
        """Emits a 'swi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (251658240 or cond))
        self.pos += 4

    def swp(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'swp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777360 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def swpb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'swpb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((20971664 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def sxtab(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtab' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((111149168 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def sxtab16(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtab16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((109052016 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def sxtah(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtah' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((112197744 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def sxtb(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((112132208 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def sxtb16(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtb16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((110035056 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def sxth(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxth' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((113180784 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def teq(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'teq' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((19922944 or cond) or (rn << 16)))
        self.pos += 4

    def tst(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'tst' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((17825792 or cond) or (rn << 16)))
        self.pos += 4

    def uadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910032 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910160 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910064 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007184 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007312 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007216 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007280 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007408 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uhsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007248 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def umaal(self, cond: Condition) -> None:
        """Emits an 'umaal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4194448 or cond))
        self.pos += 4

    def umlal(self, cond: Condition, update_cprs: bool, update_condition: bool) -> None:
        """Emits an 'umlal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((10485904 or cond) or (update_cprs << 20)) or (update_condition << 20)))
        self.pos += 4

    def umull(self, cond: Condition, update_cprs: bool, update_condition: bool) -> None:
        """Emits an 'umull' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((8388752 or cond) or (update_cprs << 20)) or (update_condition << 20)))
        self.pos += 4

    def uqadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958608 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uqadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958736 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uqaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958640 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uqsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958704 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uqsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958832 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uqsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958672 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def usad8(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usad8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((125890576 or cond) or (rd << 16)))
        self.pos += 4

    def usada8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usada8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((125829136 or cond) or (rn << 12)) or (rd << 16)))
        self.pos += 4

    def usat(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usat' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((115343376 or cond) or (rd << 12)))
        self.pos += 4

    def usat16(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usat16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((115347248 or cond) or (rd << 12)))
        self.pos += 4

    def usub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910128 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def usub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910256 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def usubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910096 or cond) or (rn << 16)) or (rd << 12)))
        self.pos += 4

    def uxtab(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtab' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((115343472 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def uxtab16(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtab16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((113246320 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def uxtah(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtah' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((116392048 or cond) or (rn << 16)) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def uxtb(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((116326512 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def uxtb16(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtb16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((114229360 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

    def uxth(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxth' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117375088 or cond) or (rd << 12)) or (rotate << 10)))
        self.pos += 4

