import struct
from enum import Enum, Flag

Reg = int

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


class ArmAssembler:
    """Assembler that targets the arm architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

    def adc(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits an 'adc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((10485760 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def add(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits an 'add' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((8388608 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def and_(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits an 'and' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((0 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def eor(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits an 'eor' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((2097152 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def orr(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits an 'orr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((25165824 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def rsb(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'rsb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((6291456 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def rsc(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'rsc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((14680064 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def sbc(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'sbc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((12582912 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def sub(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'sub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((4194304 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def bkpt(self) -> None:
        """Emits a 'bkpt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, 3776970864)
        self.pos += 4

    def b(self, cond: Condition) -> None:
        """Emits a 'b' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (167772160 | cond))
        self.pos += 4

    def bic(self, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'bic' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((29360128 | cond) | (i << 25)) | (s << 20)) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def blx(self, cond: Condition) -> None:
        """Emits a 'blx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922736 | cond))
        self.pos += 4

    def bx(self, cond: Condition) -> None:
        """Emits a 'bx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922704 | cond))
        self.pos += 4

    def bxj(self, cond: Condition) -> None:
        """Emits a 'bxj' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (19922720 | cond))
        self.pos += 4

    def blxun(self) -> None:
        """Emits a 'blxun' instruction."""
        struct.pack_into("<I", self.buf, self.pos, 4194304000)
        self.pos += 4

    def cdp(self, cond: Condition) -> None:
        """Emits a 'cdp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (234881024 | cond))
        self.pos += 4

    def clz(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'clz' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((24055568 | cond) | (rd << 12)))
        self.pos += 4

    def cmn(self, cond: Condition, i: bool, rn: Reg) -> None:
        """Emits a 'cmn' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((24117248 | cond) | (i << 25)) | (rn << 16)))
        self.pos += 4

    def cmp(self, cond: Condition, i: bool, rn: Reg) -> None:
        """Emits a 'cmp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((22020096 | cond) | (i << 25)) | (rn << 16)))
        self.pos += 4

    def cpy(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'cpy' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((27262976 | cond) | (rd << 12)))
        self.pos += 4

    def cps(self, mode: Mode) -> None:
        """Emits a 'cps' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4043440128 | (mode << 0)))
        self.pos += 4

    def cpsie(self, iflags: InterruptFlags) -> None:
        """Emits a 'cpsie' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4043833344 | (iflags << 9)))
        self.pos += 4

    def cpsid(self, iflags: InterruptFlags) -> None:
        """Emits a 'cpsid' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4044095488 | (iflags << 9)))
        self.pos += 4

    def cpsie_mode(self, iflags: InterruptFlags, mode: Mode) -> None:
        """Emits a 'cpsie_mode' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4043964416 | (iflags << 9)) | (mode << 3)))
        self.pos += 4

    def cpsid_mode(self, iflags: InterruptFlags, mode: Mode) -> None:
        """Emits a 'cpsid_mode' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4044226560 | (iflags << 9)) | (mode << 3)))
        self.pos += 4

    def ldc(self, cond: Condition, write: bool, rn: Reg) -> None:
        """Emits a 'ldc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((205520896 | cond) | (write << 23)) | (rn << 18)))
        self.pos += 4

    def ldm1(self, cond: Condition, write: bool, rn: Reg) -> None:
        """Emits a 'ldm1' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((138412032 | cond) | (write << 23)) | (rn << 18)))
        self.pos += 4

    def ldm2(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'ldm2' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((155189248 | cond) | (rn << 18)))
        self.pos += 4

    def ldm3(self, cond: Condition, write: bool, rn: Reg) -> None:
        """Emits a 'ldm3' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((155320320 | cond) | (write << 23)) | (rn << 18)))
        self.pos += 4

    def ldr(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((71303168 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrb(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((88080384 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrbt(self, cond: Condition, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((81788928 | cond) | (i << 25)) | (rn << 17)) | (rd << 13)))
        self.pos += 4

    def ldrd(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((13312 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrex(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrex' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((26218399 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def ldrh(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((4205568 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrsb(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrsb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((4207616 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrsh(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrsh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((4209664 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def ldrt(self, cond: Condition, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'ldrt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((73400320 | cond) | (i << 25)) | (rn << 17)) | (rd << 13)))
        self.pos += 4

    def mcr(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'mcr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((234897408 | cond) | (rd << 15)))
        self.pos += 4

    def mcrr(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'mcrr' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((205520896 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def mla(self, cond: Condition, s: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'mla' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((2097296 | cond) | (s << 20)) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def mov(self, cond: Condition, i: bool, s: bool, rd: Reg) -> None:
        """Emits a 'mov' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((27262976 | cond) | (i << 25)) | (s << 20)) | (rd << 12)))
        self.pos += 4

    def mrc(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'mrc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((243286016 | cond) | (rd << 15)))
        self.pos += 4

    def mrrc(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'mrrc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((206569472 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def mrs(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'mrs' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((17760256 | cond) | (rd << 12)))
        self.pos += 4

    def mul(self, cond: Condition, s: bool, rd: Reg) -> None:
        """Emits a 'mul' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((144 | cond) | (s << 20)) | (rd << 16)))
        self.pos += 4

    def mvn(self, cond: Condition, i: bool, s: bool, rd: Reg) -> None:
        """Emits a 'mvn' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((31457280 | cond) | (i << 25)) | (s << 20)) | (rd << 12)))
        self.pos += 4

    def msr_imm(self, cond: Condition, fieldmask: FieldMask) -> None:
        """Emits a 'msr_imm' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((52490240 | cond) | (fieldmask << 16)))
        self.pos += 4

    def msr_reg(self, cond: Condition, fieldmask: FieldMask) -> None:
        """Emits a 'msr_reg' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18935808 | cond) | (fieldmask << 16)))
        self.pos += 4

    def pkhbt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'pkhbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109051920 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def pkhtb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'pkhtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109051984 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def pld(self, i: bool, rn: Reg) -> None:
        """Emits a 'pld' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4121026560 | (i << 25)) | (rn << 17)))
        self.pos += 4

    def qadd(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777296 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764304 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764432 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764336 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qdadd(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qdadd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((20971600 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qdsub(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qdsub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((23068752 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qsub(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874448 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764400 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764528 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def qsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'qsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((102764368 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def rev(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'rev' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((113184560 | cond) | (rd << 12)))
        self.pos += 4

    def rev16(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'rev16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((113184688 | cond) | (rd << 12)))
        self.pos += 4

    def revsh(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'revsh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((117378992 | cond) | (rd << 12)))
        self.pos += 4

    def rfe(self, write: bool, rn: Reg) -> None:
        """Emits a 'rfe' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4164954112 | (write << 23)) | (rn << 18)))
        self.pos += 4

    def sadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715728 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def sadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715856 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def saddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'saddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715760 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def sel(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'sel' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((109055920 | cond) | (rn << 16)) | (rd << 12)))
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
        struct.pack_into("<I", self.buf, self.pos, (((103812880 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def shadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103813008 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def shaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812912 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def shsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812976 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def shsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103813104 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def shsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'shsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((103812944 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def smlabb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlabb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777344 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlabt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlabt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777376 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlatb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlatb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777408 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlatt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlatt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777440 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlad(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlad' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117440544 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlal(self, cond: Condition, s: bool) -> None:
        """Emits a 'smlal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((14680208 | cond) | (s << 20)))
        self.pos += 4

    def smlalbb(self, cond: Condition) -> None:
        """Emits a 'smlalbb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971648 | cond))
        self.pos += 4

    def smlalbt(self, cond: Condition) -> None:
        """Emits a 'smlalbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971680 | cond))
        self.pos += 4

    def smlaltb(self, cond: Condition) -> None:
        """Emits a 'smlaltb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971712 | cond))
        self.pos += 4

    def smlaltt(self, cond: Condition) -> None:
        """Emits a 'smlaltt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (20971744 | cond))
        self.pos += 4

    def smlald(self, cond: Condition) -> None:
        """Emits a 'smlald' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (121634848 | cond))
        self.pos += 4

    def smlawb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlawb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874496 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlawt(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlawt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((18874560 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlsd(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smlsd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117440608 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smlsld(self, cond: Condition) -> None:
        """Emits a 'smlsld' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (121634912 | cond))
        self.pos += 4

    def smmla(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smmla' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((122683408 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smmls(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'smmls' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((122683600 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def smmul(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smmul' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((122744848 | cond) | (rd << 16)))
        self.pos += 4

    def smuad(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smuad' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((117501984 | cond) | (rd << 16)))
        self.pos += 4

    def smulbb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulbb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068800 | cond) | (rd << 16)))
        self.pos += 4

    def smulbt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068832 | cond) | (rd << 16)))
        self.pos += 4

    def smultb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smultb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068864 | cond) | (rd << 16)))
        self.pos += 4

    def smultt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smultt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((23068896 | cond) | (rd << 16)))
        self.pos += 4

    def smull(self, cond: Condition, s: bool) -> None:
        """Emits a 'smull' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((6291528 | cond) | (s << 19)))
        self.pos += 4

    def smulwb(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulwb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18874528 | cond) | (rd << 16)))
        self.pos += 4

    def smulwt(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smulwt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((18874592 | cond) | (rd << 16)))
        self.pos += 4

    def smusd(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'smusd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((117502048 | cond) | (rd << 16)))
        self.pos += 4

    def srs(self, write: bool, mode: Mode) -> None:
        """Emits a 'srs' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((4180939776 | (write << 23)) | (mode << 1)))
        self.pos += 4

    def ssat(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'ssat' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((105922560 | cond) | (rd << 16)))
        self.pos += 4

    def ssat16(self, cond: Condition, rd: Reg) -> None:
        """Emits a 'ssat16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((111211264 | cond) | (rd << 16)))
        self.pos += 4

    def ssub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715824 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def ssub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715952 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def ssubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'ssubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((101715792 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def stc(self, cond: Condition, write: bool, rn: Reg) -> None:
        """Emits a 'stc' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((201326592 | cond) | (write << 23)) | (rn << 18)))
        self.pos += 4

    def stm1(self, cond: Condition, write: bool, rn: Reg) -> None:
        """Emits a 'stm1' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((134217728 | cond) | (write << 23)) | (rn << 18)))
        self.pos += 4

    def stm2(self, cond: Condition, rn: Reg) -> None:
        """Emits a 'stm2' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((150994944 | cond) | (rn << 18)))
        self.pos += 4

    def str(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'str' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((67108864 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def strb(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'strb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((83886080 | cond) | (write << 23)) | (i << 25)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def strbt(self, cond: Condition, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'strbt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((79691776 | cond) | (i << 25)) | (rn << 17)) | (rd << 13)))
        self.pos += 4

    def strd(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'strd' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((15360 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def strex(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'strex' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((25173792 | cond) | (rn << 17)) | (rd << 13)))
        self.pos += 4

    def strh(self, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'strh' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((((11264 | cond) | (write << 23)) | (i << 24)) | (rn << 18)) | (rd << 14)))
        self.pos += 4

    def strt(self, cond: Condition, i: bool, rn: Reg, rd: Reg) -> None:
        """Emits a 'strt' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((71303168 | cond) | (i << 25)) | (rn << 17)) | (rd << 13)))
        self.pos += 4

    def swi(self, cond: Condition) -> None:
        """Emits a 'swi' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (251658240 | cond))
        self.pos += 4

    def swp(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'swp' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((16777360 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def swpb(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits a 'swpb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((20971664 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def sxtab(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtab' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def sxtab16(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtab16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def sxtah(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtah' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def sxtb(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((112132208 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def sxtb16(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxtb16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((110035056 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def sxth(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits a 'sxth' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((113180784 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def teq(self, cond: Condition, i: bool, rn: Reg) -> None:
        """Emits a 'teq' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((19922944 | cond) | (i << 25)) | (rn << 16)))
        self.pos += 4

    def tst(self, cond: Condition, i: bool, rn: Reg) -> None:
        """Emits a 'tst' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((17825792 | cond) | (i << 25)) | (rn << 16)))
        self.pos += 4

    def uadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910032 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910160 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910064 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007184 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007312 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007216 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007280 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007408 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uhsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uhsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((108007248 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def umaal(self, cond: Condition) -> None:
        """Emits an 'umaal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (4194448 | cond))
        self.pos += 4

    def umlal(self, cond: Condition, s: bool) -> None:
        """Emits an 'umlal' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((10485904 | cond) | (s << 20)))
        self.pos += 4

    def umull(self, cond: Condition, s: bool) -> None:
        """Emits an 'umull' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((8388752 | cond) | (s << 20)))
        self.pos += 4

    def uqadd16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqadd16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958608 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uqadd8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqadd8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958736 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uqaddsubx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqaddsubx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958640 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uqsub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958704 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uqsub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958832 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uqsubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'uqsubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((106958672 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def usad8(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usad8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((125890576 | cond) | (rd << 16)))
        self.pos += 4

    def usada8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usada8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((125829136 | cond) | (rn << 12)) | (rd << 16)))
        self.pos += 4

    def usat(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usat' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((115376128 | cond) | (rd << 17)))
        self.pos += 4

    def usat16(self, cond: Condition, rd: Reg) -> None:
        """Emits an 'usat16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((115405568 | cond) | (rd << 16)))
        self.pos += 4

    def usub16(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usub16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910128 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def usub8(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usub8' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910256 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def usubaddx(self, cond: Condition, rn: Reg, rd: Reg) -> None:
        """Emits an 'usubaddx' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((105910096 | cond) | (rn << 16)) | (rd << 12)))
        self.pos += 4

    def uxtab(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtab' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def uxtab16(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtab16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def uxtah(self, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtah' instruction."""
        struct.pack_into("<I", self.buf, self.pos, ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def uxtb(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtb' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((116326512 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def uxtb16(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxtb16' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((114229360 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

    def uxth(self, cond: Condition, rd: Reg, rotate: Rotation) -> None:
        """Emits an 'uxth' instruction."""
        struct.pack_into("<I", self.buf, self.pos, (((117375088 | cond) | (rd << 12)) | (rotate << 10)))
        self.pos += 4

