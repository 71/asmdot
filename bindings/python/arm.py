import ctypes
from . import voidptr, voidptrptr
from enum import Enum, Flag

Reg = ctypes.c_uint8

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

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

class Mode(int, Enum):
    """Processor mode."""
    USR = 16
    FIQ = 17
    IRQ = 18
    SVC = 19
    ABT = 23
    UND = 27
    SYS = 31

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

class Shift(int, Enum):
    """Kind of a shift."""
    LSL = 0
    LSR = 1
    ASR = 2
    ROR = 3
    RRX = 3

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

class Rotation(int, Enum):
    """Kind of a right rotation."""
    NOP = 0
    ROR8 = 1
    ROR16 = 2
    ROR24 = 3

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

class FieldMask(int, Flag):
    """Field mask bits."""
    C = 1
    X = 2
    S = 4
    F = 8

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

class InterruptFlags(int, Flag):
    """Interrupt flags."""
    F = 1
    I = 2
    A = 4

    @classmethod
    def from_param(cls, data): return data if isinstance(data, cls) else cls(data)

def load_arm(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the arm architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.adc.restype = None
    asm.adc.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.adc.__doc__ = "Emits an 'adc' instruction."

    asm.add.restype = None
    asm.add.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.add.__doc__ = "Emits an 'add' instruction."

    asm["and"].restype = None
    asm["and"].argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm["and"].__doc__ = "Emits an 'and' instruction."

    asm.eor.restype = None
    asm.eor.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.eor.__doc__ = "Emits an 'eor' instruction."

    asm.orr.restype = None
    asm.orr.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.orr.__doc__ = "Emits an 'orr' instruction."

    asm.rsb.restype = None
    asm.rsb.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.rsb.__doc__ = "Emits a 'rsb' instruction."

    asm.rsc.restype = None
    asm.rsc.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.rsc.__doc__ = "Emits a 'rsc' instruction."

    asm.sbc.restype = None
    asm.sbc.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.sbc.__doc__ = "Emits a 'sbc' instruction."

    asm.sub.restype = None
    asm.sub.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.sub.__doc__ = "Emits a 'sub' instruction."

    asm.bkpt.restype = None
    asm.bkpt.argtypes = [ voidptrptr ]
    asm.bkpt.__doc__ = "Emits a 'bkpt' instruction."

    asm.b.restype = None
    asm.b.argtypes = [ voidptrptr, Condition ]
    asm.b.__doc__ = "Emits a 'b' instruction."

    asm.bic.restype = None
    asm.bic.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.bic.__doc__ = "Emits a 'bic' instruction."

    asm.blx.restype = None
    asm.blx.argtypes = [ voidptrptr, Condition ]
    asm.blx.__doc__ = "Emits a 'blx' instruction."

    asm.bx.restype = None
    asm.bx.argtypes = [ voidptrptr, Condition ]
    asm.bx.__doc__ = "Emits a 'bx' instruction."

    asm.bxj.restype = None
    asm.bxj.argtypes = [ voidptrptr, Condition ]
    asm.bxj.__doc__ = "Emits a 'bxj' instruction."

    asm.blxun.restype = None
    asm.blxun.argtypes = [ voidptrptr ]
    asm.blxun.__doc__ = "Emits a 'blxun' instruction."

    asm.cdp.restype = None
    asm.cdp.argtypes = [ voidptrptr, Condition ]
    asm.cdp.__doc__ = "Emits a 'cdp' instruction."

    asm.clz.restype = None
    asm.clz.argtypes = [ voidptrptr, Condition, Reg ]
    asm.clz.__doc__ = "Emits a 'clz' instruction."

    asm.cmn.restype = None
    asm.cmn.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.cmn.__doc__ = "Emits a 'cmn' instruction."

    asm.cmp.restype = None
    asm.cmp.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.cmp.__doc__ = "Emits a 'cmp' instruction."

    asm.cpy.restype = None
    asm.cpy.argtypes = [ voidptrptr, Condition, Reg ]
    asm.cpy.__doc__ = "Emits a 'cpy' instruction."

    asm.cps.restype = None
    asm.cps.argtypes = [ voidptrptr, Mode ]
    asm.cps.__doc__ = "Emits a 'cps' instruction."

    asm.cpsie.restype = None
    asm.cpsie.argtypes = [ voidptrptr, InterruptFlags ]
    asm.cpsie.__doc__ = "Emits a 'cpsie' instruction."

    asm.cpsid.restype = None
    asm.cpsid.argtypes = [ voidptrptr, InterruptFlags ]
    asm.cpsid.__doc__ = "Emits a 'cpsid' instruction."

    asm.cpsie_mode.restype = None
    asm.cpsie_mode.argtypes = [ voidptrptr, InterruptFlags, Mode ]
    asm.cpsie_mode.__doc__ = "Emits a 'cpsie_mode' instruction."

    asm.cpsid_mode.restype = None
    asm.cpsid_mode.argtypes = [ voidptrptr, InterruptFlags, Mode ]
    asm.cpsid_mode.__doc__ = "Emits a 'cpsid_mode' instruction."

    asm.ldc.restype = None
    asm.ldc.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.ldc.__doc__ = "Emits a 'ldc' instruction."

    asm.ldm1.restype = None
    asm.ldm1.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.ldm1.__doc__ = "Emits a 'ldm1' instruction."

    asm.ldm2.restype = None
    asm.ldm2.argtypes = [ voidptrptr, Condition, Reg ]
    asm.ldm2.__doc__ = "Emits a 'ldm2' instruction."

    asm.ldm3.restype = None
    asm.ldm3.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.ldm3.__doc__ = "Emits a 'ldm3' instruction."

    asm.ldr.restype = None
    asm.ldr.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldr.__doc__ = "Emits a 'ldr' instruction."

    asm.ldrb.restype = None
    asm.ldrb.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldrb.__doc__ = "Emits a 'ldrb' instruction."

    asm.ldrbt.restype = None
    asm.ldrbt.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg, Reg ]
    asm.ldrbt.__doc__ = "Emits a 'ldrbt' instruction."

    asm.ldrd.restype = None
    asm.ldrd.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldrd.__doc__ = "Emits a 'ldrd' instruction."

    asm.ldrex.restype = None
    asm.ldrex.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.ldrex.__doc__ = "Emits a 'ldrex' instruction."

    asm.ldrh.restype = None
    asm.ldrh.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldrh.__doc__ = "Emits a 'ldrh' instruction."

    asm.ldrsb.restype = None
    asm.ldrsb.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldrsb.__doc__ = "Emits a 'ldrsb' instruction."

    asm.ldrsh.restype = None
    asm.ldrsh.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.ldrsh.__doc__ = "Emits a 'ldrsh' instruction."

    asm.ldrt.restype = None
    asm.ldrt.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg, Reg ]
    asm.ldrt.__doc__ = "Emits a 'ldrt' instruction."

    asm.mcr.restype = None
    asm.mcr.argtypes = [ voidptrptr, Condition, Reg ]
    asm.mcr.__doc__ = "Emits a 'mcr' instruction."

    asm.mcrr.restype = None
    asm.mcrr.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.mcrr.__doc__ = "Emits a 'mcrr' instruction."

    asm.mla.restype = None
    asm.mla.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg, Reg ]
    asm.mla.__doc__ = "Emits a 'mla' instruction."

    asm.mov.restype = None
    asm.mov.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg ]
    asm.mov.__doc__ = "Emits a 'mov' instruction."

    asm.mrc.restype = None
    asm.mrc.argtypes = [ voidptrptr, Condition, Reg ]
    asm.mrc.__doc__ = "Emits a 'mrc' instruction."

    asm.mrrc.restype = None
    asm.mrrc.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.mrrc.__doc__ = "Emits a 'mrrc' instruction."

    asm.mrs.restype = None
    asm.mrs.argtypes = [ voidptrptr, Condition, Reg ]
    asm.mrs.__doc__ = "Emits a 'mrs' instruction."

    asm.mul.restype = None
    asm.mul.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.mul.__doc__ = "Emits a 'mul' instruction."

    asm.mvn.restype = None
    asm.mvn.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg ]
    asm.mvn.__doc__ = "Emits a 'mvn' instruction."

    asm.msr_imm.restype = None
    asm.msr_imm.argtypes = [ voidptrptr, Condition, FieldMask ]
    asm.msr_imm.__doc__ = "Emits a 'msr_imm' instruction."

    asm.msr_reg.restype = None
    asm.msr_reg.argtypes = [ voidptrptr, Condition, FieldMask ]
    asm.msr_reg.__doc__ = "Emits a 'msr_reg' instruction."

    asm.pkhbt.restype = None
    asm.pkhbt.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.pkhbt.__doc__ = "Emits a 'pkhbt' instruction."

    asm.pkhtb.restype = None
    asm.pkhtb.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.pkhtb.__doc__ = "Emits a 'pkhtb' instruction."

    asm.pld.restype = None
    asm.pld.argtypes = [ voidptrptr, ctypes.c_bool, Reg ]
    asm.pld.__doc__ = "Emits a 'pld' instruction."

    asm.qadd.restype = None
    asm.qadd.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qadd.__doc__ = "Emits a 'qadd' instruction."

    asm.qadd16.restype = None
    asm.qadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qadd16.__doc__ = "Emits a 'qadd16' instruction."

    asm.qadd8.restype = None
    asm.qadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qadd8.__doc__ = "Emits a 'qadd8' instruction."

    asm.qaddsubx.restype = None
    asm.qaddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qaddsubx.__doc__ = "Emits a 'qaddsubx' instruction."

    asm.qdadd.restype = None
    asm.qdadd.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qdadd.__doc__ = "Emits a 'qdadd' instruction."

    asm.qdsub.restype = None
    asm.qdsub.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qdsub.__doc__ = "Emits a 'qdsub' instruction."

    asm.qsub.restype = None
    asm.qsub.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qsub.__doc__ = "Emits a 'qsub' instruction."

    asm.qsub16.restype = None
    asm.qsub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qsub16.__doc__ = "Emits a 'qsub16' instruction."

    asm.qsub8.restype = None
    asm.qsub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qsub8.__doc__ = "Emits a 'qsub8' instruction."

    asm.qsubaddx.restype = None
    asm.qsubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.qsubaddx.__doc__ = "Emits a 'qsubaddx' instruction."

    asm.rev.restype = None
    asm.rev.argtypes = [ voidptrptr, Condition, Reg ]
    asm.rev.__doc__ = "Emits a 'rev' instruction."

    asm.rev16.restype = None
    asm.rev16.argtypes = [ voidptrptr, Condition, Reg ]
    asm.rev16.__doc__ = "Emits a 'rev16' instruction."

    asm.revsh.restype = None
    asm.revsh.argtypes = [ voidptrptr, Condition, Reg ]
    asm.revsh.__doc__ = "Emits a 'revsh' instruction."

    asm.rfe.restype = None
    asm.rfe.argtypes = [ voidptrptr, ctypes.c_bool, Reg ]
    asm.rfe.__doc__ = "Emits a 'rfe' instruction."

    asm.sadd16.restype = None
    asm.sadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.sadd16.__doc__ = "Emits a 'sadd16' instruction."

    asm.sadd8.restype = None
    asm.sadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.sadd8.__doc__ = "Emits a 'sadd8' instruction."

    asm.saddsubx.restype = None
    asm.saddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.saddsubx.__doc__ = "Emits a 'saddsubx' instruction."

    asm.sel.restype = None
    asm.sel.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.sel.__doc__ = "Emits a 'sel' instruction."

    asm.setendbe.restype = None
    asm.setendbe.argtypes = [ voidptrptr ]
    asm.setendbe.__doc__ = "Emits a 'setendbe' instruction."

    asm.setendle.restype = None
    asm.setendle.argtypes = [ voidptrptr ]
    asm.setendle.__doc__ = "Emits a 'setendle' instruction."

    asm.shadd16.restype = None
    asm.shadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shadd16.__doc__ = "Emits a 'shadd16' instruction."

    asm.shadd8.restype = None
    asm.shadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shadd8.__doc__ = "Emits a 'shadd8' instruction."

    asm.shaddsubx.restype = None
    asm.shaddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shaddsubx.__doc__ = "Emits a 'shaddsubx' instruction."

    asm.shsub16.restype = None
    asm.shsub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shsub16.__doc__ = "Emits a 'shsub16' instruction."

    asm.shsub8.restype = None
    asm.shsub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shsub8.__doc__ = "Emits a 'shsub8' instruction."

    asm.shsubaddx.restype = None
    asm.shsubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.shsubaddx.__doc__ = "Emits a 'shsubaddx' instruction."

    asm.smlabb.restype = None
    asm.smlabb.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlabb.__doc__ = "Emits a 'smlabb' instruction."

    asm.smlabt.restype = None
    asm.smlabt.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlabt.__doc__ = "Emits a 'smlabt' instruction."

    asm.smlatb.restype = None
    asm.smlatb.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlatb.__doc__ = "Emits a 'smlatb' instruction."

    asm.smlatt.restype = None
    asm.smlatt.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlatt.__doc__ = "Emits a 'smlatt' instruction."

    asm.smlad.restype = None
    asm.smlad.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlad.__doc__ = "Emits a 'smlad' instruction."

    asm.smlal.restype = None
    asm.smlal.argtypes = [ voidptrptr, Condition, ctypes.c_bool ]
    asm.smlal.__doc__ = "Emits a 'smlal' instruction."

    asm.smlalbb.restype = None
    asm.smlalbb.argtypes = [ voidptrptr, Condition ]
    asm.smlalbb.__doc__ = "Emits a 'smlalbb' instruction."

    asm.smlalbt.restype = None
    asm.smlalbt.argtypes = [ voidptrptr, Condition ]
    asm.smlalbt.__doc__ = "Emits a 'smlalbt' instruction."

    asm.smlaltb.restype = None
    asm.smlaltb.argtypes = [ voidptrptr, Condition ]
    asm.smlaltb.__doc__ = "Emits a 'smlaltb' instruction."

    asm.smlaltt.restype = None
    asm.smlaltt.argtypes = [ voidptrptr, Condition ]
    asm.smlaltt.__doc__ = "Emits a 'smlaltt' instruction."

    asm.smlald.restype = None
    asm.smlald.argtypes = [ voidptrptr, Condition ]
    asm.smlald.__doc__ = "Emits a 'smlald' instruction."

    asm.smlawb.restype = None
    asm.smlawb.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlawb.__doc__ = "Emits a 'smlawb' instruction."

    asm.smlawt.restype = None
    asm.smlawt.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlawt.__doc__ = "Emits a 'smlawt' instruction."

    asm.smlsd.restype = None
    asm.smlsd.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smlsd.__doc__ = "Emits a 'smlsd' instruction."

    asm.smlsld.restype = None
    asm.smlsld.argtypes = [ voidptrptr, Condition ]
    asm.smlsld.__doc__ = "Emits a 'smlsld' instruction."

    asm.smmla.restype = None
    asm.smmla.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smmla.__doc__ = "Emits a 'smmla' instruction."

    asm.smmls.restype = None
    asm.smmls.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.smmls.__doc__ = "Emits a 'smmls' instruction."

    asm.smmul.restype = None
    asm.smmul.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smmul.__doc__ = "Emits a 'smmul' instruction."

    asm.smuad.restype = None
    asm.smuad.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smuad.__doc__ = "Emits a 'smuad' instruction."

    asm.smulbb.restype = None
    asm.smulbb.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smulbb.__doc__ = "Emits a 'smulbb' instruction."

    asm.smulbt.restype = None
    asm.smulbt.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smulbt.__doc__ = "Emits a 'smulbt' instruction."

    asm.smultb.restype = None
    asm.smultb.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smultb.__doc__ = "Emits a 'smultb' instruction."

    asm.smultt.restype = None
    asm.smultt.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smultt.__doc__ = "Emits a 'smultt' instruction."

    asm.smull.restype = None
    asm.smull.argtypes = [ voidptrptr, Condition, ctypes.c_bool ]
    asm.smull.__doc__ = "Emits a 'smull' instruction."

    asm.smulwb.restype = None
    asm.smulwb.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smulwb.__doc__ = "Emits a 'smulwb' instruction."

    asm.smulwt.restype = None
    asm.smulwt.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smulwt.__doc__ = "Emits a 'smulwt' instruction."

    asm.smusd.restype = None
    asm.smusd.argtypes = [ voidptrptr, Condition, Reg ]
    asm.smusd.__doc__ = "Emits a 'smusd' instruction."

    asm.srs.restype = None
    asm.srs.argtypes = [ voidptrptr, ctypes.c_bool, Mode ]
    asm.srs.__doc__ = "Emits a 'srs' instruction."

    asm.ssat.restype = None
    asm.ssat.argtypes = [ voidptrptr, Condition, Reg ]
    asm.ssat.__doc__ = "Emits a 'ssat' instruction."

    asm.ssat16.restype = None
    asm.ssat16.argtypes = [ voidptrptr, Condition, Reg ]
    asm.ssat16.__doc__ = "Emits a 'ssat16' instruction."

    asm.ssub16.restype = None
    asm.ssub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.ssub16.__doc__ = "Emits a 'ssub16' instruction."

    asm.ssub8.restype = None
    asm.ssub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.ssub8.__doc__ = "Emits a 'ssub8' instruction."

    asm.ssubaddx.restype = None
    asm.ssubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.ssubaddx.__doc__ = "Emits a 'ssubaddx' instruction."

    asm.stc.restype = None
    asm.stc.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.stc.__doc__ = "Emits a 'stc' instruction."

    asm.stm1.restype = None
    asm.stm1.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.stm1.__doc__ = "Emits a 'stm1' instruction."

    asm.stm2.restype = None
    asm.stm2.argtypes = [ voidptrptr, Condition, Reg ]
    asm.stm2.__doc__ = "Emits a 'stm2' instruction."

    asm.str.restype = None
    asm.str.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.str.__doc__ = "Emits a 'str' instruction."

    asm.strb.restype = None
    asm.strb.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.strb.__doc__ = "Emits a 'strb' instruction."

    asm.strbt.restype = None
    asm.strbt.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg, Reg ]
    asm.strbt.__doc__ = "Emits a 'strbt' instruction."

    asm.strd.restype = None
    asm.strd.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.strd.__doc__ = "Emits a 'strd' instruction."

    asm.strex.restype = None
    asm.strex.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.strex.__doc__ = "Emits a 'strex' instruction."

    asm.strh.restype = None
    asm.strh.argtypes = [ voidptrptr, Condition, ctypes.c_bool, ctypes.c_bool, Reg, Reg ]
    asm.strh.__doc__ = "Emits a 'strh' instruction."

    asm.strt.restype = None
    asm.strt.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg, Reg ]
    asm.strt.__doc__ = "Emits a 'strt' instruction."

    asm.swi.restype = None
    asm.swi.argtypes = [ voidptrptr, Condition ]
    asm.swi.__doc__ = "Emits a 'swi' instruction."

    asm.swp.restype = None
    asm.swp.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.swp.__doc__ = "Emits a 'swp' instruction."

    asm.swpb.restype = None
    asm.swpb.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.swpb.__doc__ = "Emits a 'swpb' instruction."

    asm.sxtab.restype = None
    asm.sxtab.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.sxtab.__doc__ = "Emits a 'sxtab' instruction."

    asm.sxtab16.restype = None
    asm.sxtab16.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.sxtab16.__doc__ = "Emits a 'sxtab16' instruction."

    asm.sxtah.restype = None
    asm.sxtah.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.sxtah.__doc__ = "Emits a 'sxtah' instruction."

    asm.sxtb.restype = None
    asm.sxtb.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.sxtb.__doc__ = "Emits a 'sxtb' instruction."

    asm.sxtb16.restype = None
    asm.sxtb16.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.sxtb16.__doc__ = "Emits a 'sxtb16' instruction."

    asm.sxth.restype = None
    asm.sxth.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.sxth.__doc__ = "Emits a 'sxth' instruction."

    asm.teq.restype = None
    asm.teq.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.teq.__doc__ = "Emits a 'teq' instruction."

    asm.tst.restype = None
    asm.tst.argtypes = [ voidptrptr, Condition, ctypes.c_bool, Reg ]
    asm.tst.__doc__ = "Emits a 'tst' instruction."

    asm.uadd16.restype = None
    asm.uadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uadd16.__doc__ = "Emits an 'uadd16' instruction."

    asm.uadd8.restype = None
    asm.uadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uadd8.__doc__ = "Emits an 'uadd8' instruction."

    asm.uaddsubx.restype = None
    asm.uaddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uaddsubx.__doc__ = "Emits an 'uaddsubx' instruction."

    asm.uhadd16.restype = None
    asm.uhadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhadd16.__doc__ = "Emits an 'uhadd16' instruction."

    asm.uhadd8.restype = None
    asm.uhadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhadd8.__doc__ = "Emits an 'uhadd8' instruction."

    asm.uhaddsubx.restype = None
    asm.uhaddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhaddsubx.__doc__ = "Emits an 'uhaddsubx' instruction."

    asm.uhsub16.restype = None
    asm.uhsub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhsub16.__doc__ = "Emits an 'uhsub16' instruction."

    asm.uhsub8.restype = None
    asm.uhsub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhsub8.__doc__ = "Emits an 'uhsub8' instruction."

    asm.uhsubaddx.restype = None
    asm.uhsubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uhsubaddx.__doc__ = "Emits an 'uhsubaddx' instruction."

    asm.umaal.restype = None
    asm.umaal.argtypes = [ voidptrptr, Condition ]
    asm.umaal.__doc__ = "Emits an 'umaal' instruction."

    asm.umlal.restype = None
    asm.umlal.argtypes = [ voidptrptr, Condition, ctypes.c_bool ]
    asm.umlal.__doc__ = "Emits an 'umlal' instruction."

    asm.umull.restype = None
    asm.umull.argtypes = [ voidptrptr, Condition, ctypes.c_bool ]
    asm.umull.__doc__ = "Emits an 'umull' instruction."

    asm.uqadd16.restype = None
    asm.uqadd16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqadd16.__doc__ = "Emits an 'uqadd16' instruction."

    asm.uqadd8.restype = None
    asm.uqadd8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqadd8.__doc__ = "Emits an 'uqadd8' instruction."

    asm.uqaddsubx.restype = None
    asm.uqaddsubx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqaddsubx.__doc__ = "Emits an 'uqaddsubx' instruction."

    asm.uqsub16.restype = None
    asm.uqsub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqsub16.__doc__ = "Emits an 'uqsub16' instruction."

    asm.uqsub8.restype = None
    asm.uqsub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqsub8.__doc__ = "Emits an 'uqsub8' instruction."

    asm.uqsubaddx.restype = None
    asm.uqsubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.uqsubaddx.__doc__ = "Emits an 'uqsubaddx' instruction."

    asm.usad8.restype = None
    asm.usad8.argtypes = [ voidptrptr, Condition, Reg ]
    asm.usad8.__doc__ = "Emits an 'usad8' instruction."

    asm.usada8.restype = None
    asm.usada8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.usada8.__doc__ = "Emits an 'usada8' instruction."

    asm.usat.restype = None
    asm.usat.argtypes = [ voidptrptr, Condition, Reg ]
    asm.usat.__doc__ = "Emits an 'usat' instruction."

    asm.usat16.restype = None
    asm.usat16.argtypes = [ voidptrptr, Condition, Reg ]
    asm.usat16.__doc__ = "Emits an 'usat16' instruction."

    asm.usub16.restype = None
    asm.usub16.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.usub16.__doc__ = "Emits an 'usub16' instruction."

    asm.usub8.restype = None
    asm.usub8.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.usub8.__doc__ = "Emits an 'usub8' instruction."

    asm.usubaddx.restype = None
    asm.usubaddx.argtypes = [ voidptrptr, Condition, Reg, Reg ]
    asm.usubaddx.__doc__ = "Emits an 'usubaddx' instruction."

    asm.uxtab.restype = None
    asm.uxtab.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.uxtab.__doc__ = "Emits an 'uxtab' instruction."

    asm.uxtab16.restype = None
    asm.uxtab16.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.uxtab16.__doc__ = "Emits an 'uxtab16' instruction."

    asm.uxtah.restype = None
    asm.uxtah.argtypes = [ voidptrptr, Condition, Reg, Reg, Rotation ]
    asm.uxtah.__doc__ = "Emits an 'uxtah' instruction."

    asm.uxtb.restype = None
    asm.uxtb.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.uxtb.__doc__ = "Emits an 'uxtb' instruction."

    asm.uxtb16.restype = None
    asm.uxtb16.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.uxtb16.__doc__ = "Emits an 'uxtb16' instruction."

    asm.uxth.restype = None
    asm.uxth.argtypes = [ voidptrptr, Condition, Reg, Rotation ]
    asm.uxth.__doc__ = "Emits an 'uxth' instruction."

    return asm
