using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class Arm
    {
        public const string LIBNAME = "asmdot";
          public static int adc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int add(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int and(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int eor(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int orr(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int rsb(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int rsc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sbc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sub(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int bkpt(IntPtr buffer)
 {
}
          public static int b(Condition cond, IntPtr buffer)
 {
}
          public static int bic(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int blx(Condition cond, IntPtr buffer)
 {
}
          public static int bx(Condition cond, IntPtr buffer)
 {
}
          public static int bxj(Condition cond, IntPtr buffer)
 {
}
          public static int blxun(IntPtr buffer)
 {
}
          public static int cdp(Condition cond, IntPtr buffer)
 {
}
          public static int clz(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int cmn(Condition cond, bool i, reg rn, IntPtr buffer)
 {
}
          public static int cmp(Condition cond, bool i, reg rn, IntPtr buffer)
 {
}
          public static int cpy(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int cps(Mode mode, IntPtr buffer)
 {
}
          public static int cpsie(IntPtr buffer)
 {
}
          public static int cpsid(IntPtr buffer)
 {
}
          public static int cpsie_mode(Mode mode, IntPtr buffer)
 {
}
          public static int cpsid_mode(Mode mode, IntPtr buffer)
 {
}
          public static int ldc(Condition cond, bool write, reg rn, IntPtr buffer)
 {
}
          public static int ldm1(Condition cond, bool write, reg rn, IntPtr buffer)
 {
}
          public static int ldm2(Condition cond, reg rn, IntPtr buffer)
 {
}
          public static int ldm3(Condition cond, bool write, reg rn, IntPtr buffer)
 {
}
          public static int ldr(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrbt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrd(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrex(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrsb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrsh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ldrt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int mcr(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int mcrr(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int mla(Condition cond, bool s, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int mov(Condition cond, bool i, bool s, reg rd, IntPtr buffer)
 {
}
          public static int mrc(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int mrrc(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int mrs(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int mul(Condition cond, bool s, reg rd, IntPtr buffer)
 {
}
          public static int mvn(Condition cond, bool i, bool s, reg rd, IntPtr buffer)
 {
}
          public static int msr_imm(Condition cond, IntPtr buffer)
 {
}
          public static int msr_reg(Condition cond, IntPtr buffer)
 {
}
          public static int pkhbt(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int pkhtb(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int pld(bool i, reg rn, IntPtr buffer)
 {
}
          public static int qadd(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qdadd(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qdsub(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qsub(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int qsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int rev(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int rev16(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int revsh(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int rfe(bool write, reg rn, IntPtr buffer)
 {
}
          public static int sadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int saddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sel(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int setendbe(IntPtr buffer)
 {
}
          public static int setendle(IntPtr buffer)
 {
}
          public static int shadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int shadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int shaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int shsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int shsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int shsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlabb(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlabt(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlatb(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlatt(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlad(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlal(Condition cond, bool s, IntPtr buffer)
 {
}
          public static int smlalbb(Condition cond, IntPtr buffer)
 {
}
          public static int smlalbt(Condition cond, IntPtr buffer)
 {
}
          public static int smlaltb(Condition cond, IntPtr buffer)
 {
}
          public static int smlaltt(Condition cond, IntPtr buffer)
 {
}
          public static int smlald(Condition cond, IntPtr buffer)
 {
}
          public static int smlawb(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlawt(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlsd(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smlsld(Condition cond, IntPtr buffer)
 {
}
          public static int smmla(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smmls(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int smmul(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smuad(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smulbb(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smulbt(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smultb(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smultt(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smull(Condition cond, bool s, IntPtr buffer)
 {
}
          public static int smulwb(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smulwt(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int smusd(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int srs(bool write, Mode mode, IntPtr buffer)
 {
}
          public static int ssat(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int ssat16(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int ssub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ssub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int ssubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int stc(Condition cond, bool write, reg rn, IntPtr buffer)
 {
}
          public static int stm1(Condition cond, bool write, reg rn, IntPtr buffer)
 {
}
          public static int stm2(Condition cond, reg rn, IntPtr buffer)
 {
}
          public static int str(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strbt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strd(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strex(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int strt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int swi(Condition cond, IntPtr buffer)
 {
}
          public static int swp(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int swpb(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sxtab(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sxtab16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sxtah(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int sxtb(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int sxtb16(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int sxth(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int teq(Condition cond, bool i, reg rn, IntPtr buffer)
 {
}
          public static int tst(Condition cond, bool i, reg rn, IntPtr buffer)
 {
}
          public static int uadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uhsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int umaal(Condition cond, IntPtr buffer)
 {
}
          public static int umlal(Condition cond, bool s, IntPtr buffer)
 {
}
          public static int umull(Condition cond, bool s, IntPtr buffer)
 {
}
          public static int uqadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uqadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uqaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uqsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uqsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uqsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int usad8(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int usada8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int usat(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int usat16(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int usub16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int usub8(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int usubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uxtab(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uxtab16(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uxtah(Condition cond, reg rn, reg rd, IntPtr buffer)
 {
}
          public static int uxtb(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int uxtb16(Condition cond, reg rd, IntPtr buffer)
 {
}
          public static int uxth(Condition cond, reg rd, IntPtr buffer)
 {
}

    }
}
