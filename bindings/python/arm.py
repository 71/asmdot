import ctypes
from . import voidptr, voidptrptr

def load_arm(lib: str = "asmdot"):
    """Loads the ASM. library using the provided path, and returns a wrapper around the arm architecture."""
    asm = ctypes.cdll.LoadLibrary(lib)

    asm.adc.restype = None
    asm.adc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.add.restype = None
    asm.add.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm["and"].restype = None
    asm["and"].argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.eor.restype = None
    asm.eor.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.orr.restype = None
    asm.orr.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.rsb.restype = None
    asm.rsb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.rsc.restype = None
    asm.rsc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sbc.restype = None
    asm.sbc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sub.restype = None
    asm.sub.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.bkpt.restype = None
    asm.bkpt.argtypes = [ voidptrptr ]

    asm.b.restype = None
    asm.b.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.bic.restype = None
    asm.bic.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.blx.restype = None
    asm.blx.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.bx.restype = None
    asm.bx.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.bxj.restype = None
    asm.bxj.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.blxun.restype = None
    asm.blxun.argtypes = [ voidptrptr ]

    asm.cdp.restype = None
    asm.cdp.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.clz.restype = None
    asm.clz.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.cmn.restype = None
    asm.cmn.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.cmp.restype = None
    asm.cmp.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.cpy.restype = None
    asm.cpy.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.cps.restype = None
    asm.cps.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.cpsie.restype = None
    asm.cpsie.argtypes = [ voidptrptr ]

    asm.cpsid.restype = None
    asm.cpsid.argtypes = [ voidptrptr ]

    asm.cpsie_mode.restype = None
    asm.cpsie_mode.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.cpsid_mode.restype = None
    asm.cpsid_mode.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.ldc.restype = None
    asm.ldc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldm1.restype = None
    asm.ldm1.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldm2.restype = None
    asm.ldm2.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldm3.restype = None
    asm.ldm3.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldr.restype = None
    asm.ldr.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrb.restype = None
    asm.ldrb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrbt.restype = None
    asm.ldrbt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrd.restype = None
    asm.ldrd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrex.restype = None
    asm.ldrex.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrh.restype = None
    asm.ldrh.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrsb.restype = None
    asm.ldrsb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrsh.restype = None
    asm.ldrsh.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ldrt.restype = None
    asm.ldrt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mcr.restype = None
    asm.mcr.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mcrr.restype = None
    asm.mcrr.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mla.restype = None
    asm.mla.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mov.restype = None
    asm.mov.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mrc.restype = None
    asm.mrc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mrrc.restype = None
    asm.mrrc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mrs.restype = None
    asm.mrs.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mul.restype = None
    asm.mul.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.mvn.restype = None
    asm.mvn.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.msr_imm.restype = None
    asm.msr_imm.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.msr_reg.restype = None
    asm.msr_reg.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.pkhbt.restype = None
    asm.pkhbt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.pkhtb.restype = None
    asm.pkhtb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.pld.restype = None
    asm.pld.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qadd.restype = None
    asm.qadd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qadd16.restype = None
    asm.qadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qadd8.restype = None
    asm.qadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qaddsubx.restype = None
    asm.qaddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qdadd.restype = None
    asm.qdadd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qdsub.restype = None
    asm.qdsub.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qsub.restype = None
    asm.qsub.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qsub16.restype = None
    asm.qsub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qsub8.restype = None
    asm.qsub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.qsubaddx.restype = None
    asm.qsubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.rev.restype = None
    asm.rev.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.rev16.restype = None
    asm.rev16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.revsh.restype = None
    asm.revsh.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.rfe.restype = None
    asm.rfe.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sadd16.restype = None
    asm.sadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sadd8.restype = None
    asm.sadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.saddsubx.restype = None
    asm.saddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sel.restype = None
    asm.sel.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.setendbe.restype = None
    asm.setendbe.argtypes = [ voidptrptr ]

    asm.setendle.restype = None
    asm.setendle.argtypes = [ voidptrptr ]

    asm.shadd16.restype = None
    asm.shadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.shadd8.restype = None
    asm.shadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.shaddsubx.restype = None
    asm.shaddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.shsub16.restype = None
    asm.shsub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.shsub8.restype = None
    asm.shsub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.shsubaddx.restype = None
    asm.shsubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlabb.restype = None
    asm.smlabb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlabt.restype = None
    asm.smlabt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlatb.restype = None
    asm.smlatb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlatt.restype = None
    asm.smlatt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlad.restype = None
    asm.smlad.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlal.restype = None
    asm.smlal.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlalbb.restype = None
    asm.smlalbb.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smlalbt.restype = None
    asm.smlalbt.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smlaltb.restype = None
    asm.smlaltb.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smlaltt.restype = None
    asm.smlaltt.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smlald.restype = None
    asm.smlald.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smlawb.restype = None
    asm.smlawb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlawt.restype = None
    asm.smlawt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlsd.restype = None
    asm.smlsd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smlsld.restype = None
    asm.smlsld.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.smmla.restype = None
    asm.smmla.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smmls.restype = None
    asm.smmls.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smmul.restype = None
    asm.smmul.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smuad.restype = None
    asm.smuad.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smulbb.restype = None
    asm.smulbb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smulbt.restype = None
    asm.smulbt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smultb.restype = None
    asm.smultb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smultt.restype = None
    asm.smultt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smull.restype = None
    asm.smull.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smulwb.restype = None
    asm.smulwb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smulwt.restype = None
    asm.smulwt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.smusd.restype = None
    asm.smusd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.srs.restype = None
    asm.srs.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ssat.restype = None
    asm.ssat.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ssat16.restype = None
    asm.ssat16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ssub16.restype = None
    asm.ssub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ssub8.restype = None
    asm.ssub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.ssubaddx.restype = None
    asm.ssubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.stc.restype = None
    asm.stc.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.stm1.restype = None
    asm.stm1.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.stm2.restype = None
    asm.stm2.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.str.restype = None
    asm.str.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strb.restype = None
    asm.strb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strbt.restype = None
    asm.strbt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strd.restype = None
    asm.strd.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strex.restype = None
    asm.strex.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strh.restype = None
    asm.strh.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.strt.restype = None
    asm.strt.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.swi.restype = None
    asm.swi.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.swp.restype = None
    asm.swp.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.swpb.restype = None
    asm.swpb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxtab.restype = None
    asm.sxtab.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxtab16.restype = None
    asm.sxtab16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxtah.restype = None
    asm.sxtah.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxtb.restype = None
    asm.sxtb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxtb16.restype = None
    asm.sxtb16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.sxth.restype = None
    asm.sxth.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.teq.restype = None
    asm.teq.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.tst.restype = None
    asm.tst.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uadd16.restype = None
    asm.uadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uadd8.restype = None
    asm.uadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uaddsubx.restype = None
    asm.uaddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhadd16.restype = None
    asm.uhadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhadd8.restype = None
    asm.uhadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhaddsubx.restype = None
    asm.uhaddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhsub16.restype = None
    asm.uhsub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhsub8.restype = None
    asm.uhsub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uhsubaddx.restype = None
    asm.uhsubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.umaal.restype = None
    asm.umaal.argtypes = [ voidptrptr, ctypes.c_ubyte ]

    asm.umlal.restype = None
    asm.umlal.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.umull.restype = None
    asm.umull.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqadd16.restype = None
    asm.uqadd16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqadd8.restype = None
    asm.uqadd8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqaddsubx.restype = None
    asm.uqaddsubx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqsub16.restype = None
    asm.uqsub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqsub8.restype = None
    asm.uqsub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uqsubaddx.restype = None
    asm.uqsubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usad8.restype = None
    asm.usad8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usada8.restype = None
    asm.usada8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usat.restype = None
    asm.usat.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usat16.restype = None
    asm.usat16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usub16.restype = None
    asm.usub16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usub8.restype = None
    asm.usub8.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.usubaddx.restype = None
    asm.usubaddx.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxtab.restype = None
    asm.uxtab.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxtab16.restype = None
    asm.uxtab16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxtah.restype = None
    asm.uxtah.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxtb.restype = None
    asm.uxtb.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxtb16.restype = None
    asm.uxtb16.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    asm.uxth.restype = None
    asm.uxth.argtypes = [ voidptrptr, ctypes.c_ubyte, ctypes.c_ubyte ]

    return asm