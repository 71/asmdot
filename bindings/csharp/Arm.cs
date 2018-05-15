using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class Arm
    {
        public const string LIBNAME = "asmdot";
          [DllImport(LIBNAME, EntryPoint = "adc", CallingConvention = CallingConvention.Cdecl)]
          public static int adc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "add", CallingConvention = CallingConvention.Cdecl)]
          public static int add(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "and", CallingConvention = CallingConvention.Cdecl)]
          public static int and(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "eor", CallingConvention = CallingConvention.Cdecl)]
          public static int eor(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "orr", CallingConvention = CallingConvention.Cdecl)]
          public static int orr(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "rsb", CallingConvention = CallingConvention.Cdecl)]
          public static int rsb(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "rsc", CallingConvention = CallingConvention.Cdecl)]
          public static int rsc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sbc", CallingConvention = CallingConvention.Cdecl)]
          public static int sbc(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sub", CallingConvention = CallingConvention.Cdecl)]
          public static int sub(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "bkpt", CallingConvention = CallingConvention.Cdecl)]
          public static int bkpt(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "b", CallingConvention = CallingConvention.Cdecl)]
          public static int b(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "bic", CallingConvention = CallingConvention.Cdecl)]
          public static int bic(Condition cond, bool i, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "blx", CallingConvention = CallingConvention.Cdecl)]
          public static int blx(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "bx", CallingConvention = CallingConvention.Cdecl)]
          public static int bx(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "bxj", CallingConvention = CallingConvention.Cdecl)]
          public static int bxj(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "blxun", CallingConvention = CallingConvention.Cdecl)]
          public static int blxun(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cdp", CallingConvention = CallingConvention.Cdecl)]
          public static int cdp(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "clz", CallingConvention = CallingConvention.Cdecl)]
          public static int clz(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cmn", CallingConvention = CallingConvention.Cdecl)]
          public static int cmn(Condition cond, bool i, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cmp", CallingConvention = CallingConvention.Cdecl)]
          public static int cmp(Condition cond, bool i, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cpy", CallingConvention = CallingConvention.Cdecl)]
          public static int cpy(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cps", CallingConvention = CallingConvention.Cdecl)]
          public static int cps(Mode mode, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cpsie", CallingConvention = CallingConvention.Cdecl)]
          public static int cpsie(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cpsid", CallingConvention = CallingConvention.Cdecl)]
          public static int cpsid(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cpsie_mode", CallingConvention = CallingConvention.Cdecl)]
          public static int cpsie_mode(Mode mode, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "cpsid_mode", CallingConvention = CallingConvention.Cdecl)]
          public static int cpsid_mode(Mode mode, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldc", CallingConvention = CallingConvention.Cdecl)]
          public static int ldc(Condition cond, bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldm1", CallingConvention = CallingConvention.Cdecl)]
          public static int ldm1(Condition cond, bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldm2", CallingConvention = CallingConvention.Cdecl)]
          public static int ldm2(Condition cond, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldm3", CallingConvention = CallingConvention.Cdecl)]
          public static int ldm3(Condition cond, bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldr", CallingConvention = CallingConvention.Cdecl)]
          public static int ldr(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrb", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrbt", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrbt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrd", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrd(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrex", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrex(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrh", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrsb", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrsb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrsh", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrsh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ldrt", CallingConvention = CallingConvention.Cdecl)]
          public static int ldrt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mcr", CallingConvention = CallingConvention.Cdecl)]
          public static int mcr(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mcrr", CallingConvention = CallingConvention.Cdecl)]
          public static int mcrr(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mla", CallingConvention = CallingConvention.Cdecl)]
          public static int mla(Condition cond, bool s, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mov", CallingConvention = CallingConvention.Cdecl)]
          public static int mov(Condition cond, bool i, bool s, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mrc", CallingConvention = CallingConvention.Cdecl)]
          public static int mrc(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mrrc", CallingConvention = CallingConvention.Cdecl)]
          public static int mrrc(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mrs", CallingConvention = CallingConvention.Cdecl)]
          public static int mrs(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mul", CallingConvention = CallingConvention.Cdecl)]
          public static int mul(Condition cond, bool s, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "mvn", CallingConvention = CallingConvention.Cdecl)]
          public static int mvn(Condition cond, bool i, bool s, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "msr_imm", CallingConvention = CallingConvention.Cdecl)]
          public static int msr_imm(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "msr_reg", CallingConvention = CallingConvention.Cdecl)]
          public static int msr_reg(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pkhbt", CallingConvention = CallingConvention.Cdecl)]
          public static int pkhbt(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pkhtb", CallingConvention = CallingConvention.Cdecl)]
          public static int pkhtb(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "pld", CallingConvention = CallingConvention.Cdecl)]
          public static int pld(bool i, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qadd", CallingConvention = CallingConvention.Cdecl)]
          public static int qadd(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int qadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int qadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qaddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int qaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qdadd", CallingConvention = CallingConvention.Cdecl)]
          public static int qdadd(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qdsub", CallingConvention = CallingConvention.Cdecl)]
          public static int qdsub(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qsub", CallingConvention = CallingConvention.Cdecl)]
          public static int qsub(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qsub16", CallingConvention = CallingConvention.Cdecl)]
          public static int qsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qsub8", CallingConvention = CallingConvention.Cdecl)]
          public static int qsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "qsubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int qsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "rev", CallingConvention = CallingConvention.Cdecl)]
          public static int rev(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "rev16", CallingConvention = CallingConvention.Cdecl)]
          public static int rev16(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "revsh", CallingConvention = CallingConvention.Cdecl)]
          public static int revsh(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "rfe", CallingConvention = CallingConvention.Cdecl)]
          public static int rfe(bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int sadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int sadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "saddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int saddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sel", CallingConvention = CallingConvention.Cdecl)]
          public static int sel(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "setendbe", CallingConvention = CallingConvention.Cdecl)]
          public static int setendbe(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "setendle", CallingConvention = CallingConvention.Cdecl)]
          public static int setendle(IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int shadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int shadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shaddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int shaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shsub16", CallingConvention = CallingConvention.Cdecl)]
          public static int shsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shsub8", CallingConvention = CallingConvention.Cdecl)]
          public static int shsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "shsubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int shsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlabb", CallingConvention = CallingConvention.Cdecl)]
          public static int smlabb(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlabt", CallingConvention = CallingConvention.Cdecl)]
          public static int smlabt(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlatb", CallingConvention = CallingConvention.Cdecl)]
          public static int smlatb(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlatt", CallingConvention = CallingConvention.Cdecl)]
          public static int smlatt(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlad", CallingConvention = CallingConvention.Cdecl)]
          public static int smlad(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlal", CallingConvention = CallingConvention.Cdecl)]
          public static int smlal(Condition cond, bool s, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlalbb", CallingConvention = CallingConvention.Cdecl)]
          public static int smlalbb(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlalbt", CallingConvention = CallingConvention.Cdecl)]
          public static int smlalbt(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlaltb", CallingConvention = CallingConvention.Cdecl)]
          public static int smlaltb(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlaltt", CallingConvention = CallingConvention.Cdecl)]
          public static int smlaltt(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlald", CallingConvention = CallingConvention.Cdecl)]
          public static int smlald(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlawb", CallingConvention = CallingConvention.Cdecl)]
          public static int smlawb(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlawt", CallingConvention = CallingConvention.Cdecl)]
          public static int smlawt(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlsd", CallingConvention = CallingConvention.Cdecl)]
          public static int smlsd(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smlsld", CallingConvention = CallingConvention.Cdecl)]
          public static int smlsld(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smmla", CallingConvention = CallingConvention.Cdecl)]
          public static int smmla(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smmls", CallingConvention = CallingConvention.Cdecl)]
          public static int smmls(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smmul", CallingConvention = CallingConvention.Cdecl)]
          public static int smmul(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smuad", CallingConvention = CallingConvention.Cdecl)]
          public static int smuad(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smulbb", CallingConvention = CallingConvention.Cdecl)]
          public static int smulbb(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smulbt", CallingConvention = CallingConvention.Cdecl)]
          public static int smulbt(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smultb", CallingConvention = CallingConvention.Cdecl)]
          public static int smultb(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smultt", CallingConvention = CallingConvention.Cdecl)]
          public static int smultt(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smull", CallingConvention = CallingConvention.Cdecl)]
          public static int smull(Condition cond, bool s, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smulwb", CallingConvention = CallingConvention.Cdecl)]
          public static int smulwb(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smulwt", CallingConvention = CallingConvention.Cdecl)]
          public static int smulwt(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "smusd", CallingConvention = CallingConvention.Cdecl)]
          public static int smusd(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "srs", CallingConvention = CallingConvention.Cdecl)]
          public static int srs(bool write, Mode mode, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ssat", CallingConvention = CallingConvention.Cdecl)]
          public static int ssat(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ssat16", CallingConvention = CallingConvention.Cdecl)]
          public static int ssat16(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ssub16", CallingConvention = CallingConvention.Cdecl)]
          public static int ssub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ssub8", CallingConvention = CallingConvention.Cdecl)]
          public static int ssub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "ssubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int ssubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "stc", CallingConvention = CallingConvention.Cdecl)]
          public static int stc(Condition cond, bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "stm1", CallingConvention = CallingConvention.Cdecl)]
          public static int stm1(Condition cond, bool write, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "stm2", CallingConvention = CallingConvention.Cdecl)]
          public static int stm2(Condition cond, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "str", CallingConvention = CallingConvention.Cdecl)]
          public static int str(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strb", CallingConvention = CallingConvention.Cdecl)]
          public static int strb(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strbt", CallingConvention = CallingConvention.Cdecl)]
          public static int strbt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strd", CallingConvention = CallingConvention.Cdecl)]
          public static int strd(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strex", CallingConvention = CallingConvention.Cdecl)]
          public static int strex(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strh", CallingConvention = CallingConvention.Cdecl)]
          public static int strh(Condition cond, bool write, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "strt", CallingConvention = CallingConvention.Cdecl)]
          public static int strt(Condition cond, bool i, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "swi", CallingConvention = CallingConvention.Cdecl)]
          public static int swi(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "swp", CallingConvention = CallingConvention.Cdecl)]
          public static int swp(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "swpb", CallingConvention = CallingConvention.Cdecl)]
          public static int swpb(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxtab", CallingConvention = CallingConvention.Cdecl)]
          public static int sxtab(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxtab16", CallingConvention = CallingConvention.Cdecl)]
          public static int sxtab16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxtah", CallingConvention = CallingConvention.Cdecl)]
          public static int sxtah(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxtb", CallingConvention = CallingConvention.Cdecl)]
          public static int sxtb(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxtb16", CallingConvention = CallingConvention.Cdecl)]
          public static int sxtb16(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "sxth", CallingConvention = CallingConvention.Cdecl)]
          public static int sxth(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "teq", CallingConvention = CallingConvention.Cdecl)]
          public static int teq(Condition cond, bool i, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "tst", CallingConvention = CallingConvention.Cdecl)]
          public static int tst(Condition cond, bool i, reg rn, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int uadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int uadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uaddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int uaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int uhadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int uhadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhaddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int uhaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhsub16", CallingConvention = CallingConvention.Cdecl)]
          public static int uhsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhsub8", CallingConvention = CallingConvention.Cdecl)]
          public static int uhsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uhsubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int uhsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "umaal", CallingConvention = CallingConvention.Cdecl)]
          public static int umaal(Condition cond, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "umlal", CallingConvention = CallingConvention.Cdecl)]
          public static int umlal(Condition cond, bool s, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "umull", CallingConvention = CallingConvention.Cdecl)]
          public static int umull(Condition cond, bool s, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqadd16", CallingConvention = CallingConvention.Cdecl)]
          public static int uqadd16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqadd8", CallingConvention = CallingConvention.Cdecl)]
          public static int uqadd8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqaddsubx", CallingConvention = CallingConvention.Cdecl)]
          public static int uqaddsubx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqsub16", CallingConvention = CallingConvention.Cdecl)]
          public static int uqsub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqsub8", CallingConvention = CallingConvention.Cdecl)]
          public static int uqsub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uqsubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int uqsubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usad8", CallingConvention = CallingConvention.Cdecl)]
          public static int usad8(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usada8", CallingConvention = CallingConvention.Cdecl)]
          public static int usada8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usat", CallingConvention = CallingConvention.Cdecl)]
          public static int usat(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usat16", CallingConvention = CallingConvention.Cdecl)]
          public static int usat16(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usub16", CallingConvention = CallingConvention.Cdecl)]
          public static int usub16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usub8", CallingConvention = CallingConvention.Cdecl)]
          public static int usub8(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "usubaddx", CallingConvention = CallingConvention.Cdecl)]
          public static int usubaddx(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxtab", CallingConvention = CallingConvention.Cdecl)]
          public static int uxtab(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxtab16", CallingConvention = CallingConvention.Cdecl)]
          public static int uxtab16(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxtah", CallingConvention = CallingConvention.Cdecl)]
          public static int uxtah(Condition cond, reg rn, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxtb", CallingConvention = CallingConvention.Cdecl)]
          public static int uxtb(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxtb16", CallingConvention = CallingConvention.Cdecl)]
          public static int uxtb16(Condition cond, reg rd, IntPtr buffer)
;
          [DllImport(LIBNAME, EntryPoint = "uxth", CallingConvention = CallingConvention.Cdecl)]
          public static int uxth(Condition cond, reg rd, IntPtr buffer)
;

    }
}
