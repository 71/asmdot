import ctypes
from . import voidptr, voidptrptr

def load_arm(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the arm architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.adc.restype = ctypes.c_byte
    asm.adc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.add.restype = ctypes.c_byte
    asm.add.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm["and"].restype = ctypes.c_byte
    asm["and"].argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.eor.restype = ctypes.c_byte
    asm.eor.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.orr.restype = ctypes.c_byte
    asm.orr.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.rsb.restype = ctypes.c_byte
    asm.rsb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.rsc.restype = ctypes.c_byte
    asm.rsc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sbc.restype = ctypes.c_byte
    asm.sbc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sub.restype = ctypes.c_byte
    asm.sub.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.bkpt.restype = ctypes.c_byte
    asm.bkpt.argtypes = [ voidptrptr ]

    asm.b.restype = ctypes.c_byte
    asm.b.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.bic.restype = ctypes.c_byte
    asm.bic.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.blx.restype = ctypes.c_byte
    asm.blx.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.bx.restype = ctypes.c_byte
    asm.bx.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.bxj.restype = ctypes.c_byte
    asm.bxj.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.blxun.restype = ctypes.c_byte
    asm.blxun.argtypes = [ voidptrptr ]

    asm.cdp.restype = ctypes.c_byte
    asm.cdp.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.clz.restype = ctypes.c_byte
    asm.clz.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.cmn.restype = ctypes.c_byte
    asm.cmn.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.cmp.restype = ctypes.c_byte
    asm.cmp.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.cpy.restype = ctypes.c_byte
    asm.cpy.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.cps.restype = ctypes.c_byte
    asm.cps.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.cpsie.restype = ctypes.c_byte
    asm.cpsie.argtypes = [ voidptrptr ]

    asm.cpsid.restype = ctypes.c_byte
    asm.cpsid.argtypes = [ voidptrptr ]

    asm.cpsie_mode.restype = ctypes.c_byte
    asm.cpsie_mode.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.cpsid_mode.restype = ctypes.c_byte
    asm.cpsid_mode.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.ldc.restype = ctypes.c_byte
    asm.ldc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldm1.restype = ctypes.c_byte
    asm.ldm1.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldm2.restype = ctypes.c_byte
    asm.ldm2.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldm3.restype = ctypes.c_byte
    asm.ldm3.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldr.restype = ctypes.c_byte
    asm.ldr.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrb.restype = ctypes.c_byte
    asm.ldrb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrbt.restype = ctypes.c_byte
    asm.ldrbt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrd.restype = ctypes.c_byte
    asm.ldrd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrex.restype = ctypes.c_byte
    asm.ldrex.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrh.restype = ctypes.c_byte
    asm.ldrh.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrsb.restype = ctypes.c_byte
    asm.ldrsb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrsh.restype = ctypes.c_byte
    asm.ldrsh.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ldrt.restype = ctypes.c_byte
    asm.ldrt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mcr.restype = ctypes.c_byte
    asm.mcr.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mcrr.restype = ctypes.c_byte
    asm.mcrr.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mla.restype = ctypes.c_byte
    asm.mla.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mov.restype = ctypes.c_byte
    asm.mov.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mrc.restype = ctypes.c_byte
    asm.mrc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mrrc.restype = ctypes.c_byte
    asm.mrrc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mrs.restype = ctypes.c_byte
    asm.mrs.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mul.restype = ctypes.c_byte
    asm.mul.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.mvn.restype = ctypes.c_byte
    asm.mvn.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.msr_imm.restype = ctypes.c_byte
    asm.msr_imm.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.msr_reg.restype = ctypes.c_byte
    asm.msr_reg.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.pkhbt.restype = ctypes.c_byte
    asm.pkhbt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.pkhtb.restype = ctypes.c_byte
    asm.pkhtb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.pld.restype = ctypes.c_byte
    asm.pld.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qadd.restype = ctypes.c_byte
    asm.qadd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qadd16.restype = ctypes.c_byte
    asm.qadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qadd8.restype = ctypes.c_byte
    asm.qadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qaddsubx.restype = ctypes.c_byte
    asm.qaddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qdadd.restype = ctypes.c_byte
    asm.qdadd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qdsub.restype = ctypes.c_byte
    asm.qdsub.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qsub.restype = ctypes.c_byte
    asm.qsub.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qsub16.restype = ctypes.c_byte
    asm.qsub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qsub8.restype = ctypes.c_byte
    asm.qsub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.qsubaddx.restype = ctypes.c_byte
    asm.qsubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.rev.restype = ctypes.c_byte
    asm.rev.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.rev16.restype = ctypes.c_byte
    asm.rev16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.revsh.restype = ctypes.c_byte
    asm.revsh.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.rfe.restype = ctypes.c_byte
    asm.rfe.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sadd16.restype = ctypes.c_byte
    asm.sadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sadd8.restype = ctypes.c_byte
    asm.sadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.saddsubx.restype = ctypes.c_byte
    asm.saddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sel.restype = ctypes.c_byte
    asm.sel.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.setendbe.restype = ctypes.c_byte
    asm.setendbe.argtypes = [ voidptrptr ]

    asm.setendle.restype = ctypes.c_byte
    asm.setendle.argtypes = [ voidptrptr ]

    asm.shadd16.restype = ctypes.c_byte
    asm.shadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.shadd8.restype = ctypes.c_byte
    asm.shadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.shaddsubx.restype = ctypes.c_byte
    asm.shaddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.shsub16.restype = ctypes.c_byte
    asm.shsub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.shsub8.restype = ctypes.c_byte
    asm.shsub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.shsubaddx.restype = ctypes.c_byte
    asm.shsubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlabb.restype = ctypes.c_byte
    asm.smlabb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlabt.restype = ctypes.c_byte
    asm.smlabt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlatb.restype = ctypes.c_byte
    asm.smlatb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlatt.restype = ctypes.c_byte
    asm.smlatt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlad.restype = ctypes.c_byte
    asm.smlad.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlal.restype = ctypes.c_byte
    asm.smlal.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlalbb.restype = ctypes.c_byte
    asm.smlalbb.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smlalbt.restype = ctypes.c_byte
    asm.smlalbt.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smlaltb.restype = ctypes.c_byte
    asm.smlaltb.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smlaltt.restype = ctypes.c_byte
    asm.smlaltt.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smlald.restype = ctypes.c_byte
    asm.smlald.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smlawb.restype = ctypes.c_byte
    asm.smlawb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlawt.restype = ctypes.c_byte
    asm.smlawt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlsd.restype = ctypes.c_byte
    asm.smlsd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smlsld.restype = ctypes.c_byte
    asm.smlsld.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.smmla.restype = ctypes.c_byte
    asm.smmla.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smmls.restype = ctypes.c_byte
    asm.smmls.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smmul.restype = ctypes.c_byte
    asm.smmul.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smuad.restype = ctypes.c_byte
    asm.smuad.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smulbb.restype = ctypes.c_byte
    asm.smulbb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smulbt.restype = ctypes.c_byte
    asm.smulbt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smultb.restype = ctypes.c_byte
    asm.smultb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smultt.restype = ctypes.c_byte
    asm.smultt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smull.restype = ctypes.c_byte
    asm.smull.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smulwb.restype = ctypes.c_byte
    asm.smulwb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smulwt.restype = ctypes.c_byte
    asm.smulwt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.smusd.restype = ctypes.c_byte
    asm.smusd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.srs.restype = ctypes.c_byte
    asm.srs.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ssat.restype = ctypes.c_byte
    asm.ssat.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ssat16.restype = ctypes.c_byte
    asm.ssat16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ssub16.restype = ctypes.c_byte
    asm.ssub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ssub8.restype = ctypes.c_byte
    asm.ssub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.ssubaddx.restype = ctypes.c_byte
    asm.ssubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.stc.restype = ctypes.c_byte
    asm.stc.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.stm1.restype = ctypes.c_byte
    asm.stm1.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.stm2.restype = ctypes.c_byte
    asm.stm2.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.str.restype = ctypes.c_byte
    asm.str.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strb.restype = ctypes.c_byte
    asm.strb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strbt.restype = ctypes.c_byte
    asm.strbt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strd.restype = ctypes.c_byte
    asm.strd.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strex.restype = ctypes.c_byte
    asm.strex.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strh.restype = ctypes.c_byte
    asm.strh.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.strt.restype = ctypes.c_byte
    asm.strt.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.swi.restype = ctypes.c_byte
    asm.swi.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.swp.restype = ctypes.c_byte
    asm.swp.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.swpb.restype = ctypes.c_byte
    asm.swpb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxtab.restype = ctypes.c_byte
    asm.sxtab.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxtab16.restype = ctypes.c_byte
    asm.sxtab16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxtah.restype = ctypes.c_byte
    asm.sxtah.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxtb.restype = ctypes.c_byte
    asm.sxtb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxtb16.restype = ctypes.c_byte
    asm.sxtb16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.sxth.restype = ctypes.c_byte
    asm.sxth.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.teq.restype = ctypes.c_byte
    asm.teq.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.tst.restype = ctypes.c_byte
    asm.tst.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uadd16.restype = ctypes.c_byte
    asm.uadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uadd8.restype = ctypes.c_byte
    asm.uadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uaddsubx.restype = ctypes.c_byte
    asm.uaddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhadd16.restype = ctypes.c_byte
    asm.uhadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhadd8.restype = ctypes.c_byte
    asm.uhadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhaddsubx.restype = ctypes.c_byte
    asm.uhaddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhsub16.restype = ctypes.c_byte
    asm.uhsub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhsub8.restype = ctypes.c_byte
    asm.uhsub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uhsubaddx.restype = ctypes.c_byte
    asm.uhsubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.umaal.restype = ctypes.c_byte
    asm.umaal.argtypes = [ ctypes.c_ubyte, voidptrptr ]

    asm.umlal.restype = ctypes.c_byte
    asm.umlal.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.umull.restype = ctypes.c_byte
    asm.umull.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqadd16.restype = ctypes.c_byte
    asm.uqadd16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqadd8.restype = ctypes.c_byte
    asm.uqadd8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqaddsubx.restype = ctypes.c_byte
    asm.uqaddsubx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqsub16.restype = ctypes.c_byte
    asm.uqsub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqsub8.restype = ctypes.c_byte
    asm.uqsub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uqsubaddx.restype = ctypes.c_byte
    asm.uqsubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usad8.restype = ctypes.c_byte
    asm.usad8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usada8.restype = ctypes.c_byte
    asm.usada8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usat.restype = ctypes.c_byte
    asm.usat.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usat16.restype = ctypes.c_byte
    asm.usat16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usub16.restype = ctypes.c_byte
    asm.usub16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usub8.restype = ctypes.c_byte
    asm.usub8.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.usubaddx.restype = ctypes.c_byte
    asm.usubaddx.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxtab.restype = ctypes.c_byte
    asm.uxtab.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxtab16.restype = ctypes.c_byte
    asm.uxtab16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxtah.restype = ctypes.c_byte
    asm.uxtah.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxtb.restype = ctypes.c_byte
    asm.uxtb.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxtb16.restype = ctypes.c_byte
    asm.uxtb16.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    asm.uxth.restype = ctypes.c_byte
    asm.uxth.argtypes = [ ctypes.c_ubyte, ctypes.c_ubyte, voidptrptr ]

    return asm