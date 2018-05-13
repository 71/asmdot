using System;
using System.Runtime.InteropServices;

namespace AsmSq
{
    public static class Arm
    {
        [DllImport("asmsq", EntryPoint = "adc", CallingConvention = CallingConvention.Cdecl)]
        public static int adc(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "add", CallingConvention = CallingConvention.Cdecl)]
        public static int add(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "and", CallingConvention = CallingConvention.Cdecl)]
        public static int and(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "eor", CallingConvention = CallingConvention.Cdecl)]
        public static int eor(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "orr", CallingConvention = CallingConvention.Cdecl)]
        public static int orr(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "rsb", CallingConvention = CallingConvention.Cdecl)]
        public static int rsb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "rsc", CallingConvention = CallingConvention.Cdecl)]
        public static int rsc(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sbc", CallingConvention = CallingConvention.Cdecl)]
        public static int sbc(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sub", CallingConvention = CallingConvention.Cdecl)]
        public static int sub(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "bkpt", CallingConvention = CallingConvention.Cdecl)]
        public static int bkpt(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "b", CallingConvention = CallingConvention.Cdecl)]
        public static int b(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "bic", CallingConvention = CallingConvention.Cdecl)]
        public static int bic(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "blx", CallingConvention = CallingConvention.Cdecl)]
        public static int blx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "bx", CallingConvention = CallingConvention.Cdecl)]
        public static int bx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "bxj", CallingConvention = CallingConvention.Cdecl)]
        public static int bxj(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "blxun", CallingConvention = CallingConvention.Cdecl)]
        public static int blxun(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cdp", CallingConvention = CallingConvention.Cdecl)]
        public static int cdp(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "clz", CallingConvention = CallingConvention.Cdecl)]
        public static int clz(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cmn", CallingConvention = CallingConvention.Cdecl)]
        public static int cmn(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cmp", CallingConvention = CallingConvention.Cdecl)]
        public static int cmp(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cpy", CallingConvention = CallingConvention.Cdecl)]
        public static int cpy(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cps", CallingConvention = CallingConvention.Cdecl)]
        public static int cps(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cpsie", CallingConvention = CallingConvention.Cdecl)]
        public static int cpsie(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cpsid", CallingConvention = CallingConvention.Cdecl)]
        public static int cpsid(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cpsie_mode", CallingConvention = CallingConvention.Cdecl)]
        public static int cpsie(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "cpsid_mode", CallingConvention = CallingConvention.Cdecl)]
        public static int cpsid(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldc", CallingConvention = CallingConvention.Cdecl)]
        public static int ldc(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldm1", CallingConvention = CallingConvention.Cdecl)]
        public static int ldm1(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldm2", CallingConvention = CallingConvention.Cdecl)]
        public static int ldm2(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldm3", CallingConvention = CallingConvention.Cdecl)]
        public static int ldm3(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldr", CallingConvention = CallingConvention.Cdecl)]
        public static int ldr(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrb", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrb(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrbt", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrbt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrd", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrd(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrex", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrex(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrh", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrh(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrsb", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrsb(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrsh", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrsh(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ldrt", CallingConvention = CallingConvention.Cdecl)]
        public static int ldrt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mcr", CallingConvention = CallingConvention.Cdecl)]
        public static int mcr(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mcrr", CallingConvention = CallingConvention.Cdecl)]
        public static int mcrr(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mla", CallingConvention = CallingConvention.Cdecl)]
        public static int mla(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mov", CallingConvention = CallingConvention.Cdecl)]
        public static int mov(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mrc", CallingConvention = CallingConvention.Cdecl)]
        public static int mrc(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mrrc", CallingConvention = CallingConvention.Cdecl)]
        public static int mrrc(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mrs", CallingConvention = CallingConvention.Cdecl)]
        public static int mrs(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mul", CallingConvention = CallingConvention.Cdecl)]
        public static int mul(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "mvn", CallingConvention = CallingConvention.Cdecl)]
        public static int mvn(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "msr_imm", CallingConvention = CallingConvention.Cdecl)]
        public static int msr(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "msr_reg", CallingConvention = CallingConvention.Cdecl)]
        public static int msr(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pkhbt", CallingConvention = CallingConvention.Cdecl)]
        public static int pkhbt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pkhtb", CallingConvention = CallingConvention.Cdecl)]
        public static int pkhtb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "pld", CallingConvention = CallingConvention.Cdecl)]
        public static int pld(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qadd", CallingConvention = CallingConvention.Cdecl)]
        public static int qadd(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int qadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int qadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qaddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int qaddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qdadd", CallingConvention = CallingConvention.Cdecl)]
        public static int qdadd(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qdsub", CallingConvention = CallingConvention.Cdecl)]
        public static int qdsub(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qsub", CallingConvention = CallingConvention.Cdecl)]
        public static int qsub(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qsub16", CallingConvention = CallingConvention.Cdecl)]
        public static int qsub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qsub8", CallingConvention = CallingConvention.Cdecl)]
        public static int qsub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "qsubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int qsubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "rev", CallingConvention = CallingConvention.Cdecl)]
        public static int rev(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "rev16", CallingConvention = CallingConvention.Cdecl)]
        public static int rev16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "revsh", CallingConvention = CallingConvention.Cdecl)]
        public static int revsh(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "rfe", CallingConvention = CallingConvention.Cdecl)]
        public static int rfe(bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int sadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int sadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "saddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int saddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sel", CallingConvention = CallingConvention.Cdecl)]
        public static int sel(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "setendbe", CallingConvention = CallingConvention.Cdecl)]
        public static int setendbe(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "setendle", CallingConvention = CallingConvention.Cdecl)]
        public static int setendle(ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int shadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int shadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shaddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int shaddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shsub16", CallingConvention = CallingConvention.Cdecl)]
        public static int shsub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shsub8", CallingConvention = CallingConvention.Cdecl)]
        public static int shsub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "shsubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int shsubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlabb", CallingConvention = CallingConvention.Cdecl)]
        public static int smlabb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlabt", CallingConvention = CallingConvention.Cdecl)]
        public static int smlabt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlatb", CallingConvention = CallingConvention.Cdecl)]
        public static int smlatb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlatt", CallingConvention = CallingConvention.Cdecl)]
        public static int smlatt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlad", CallingConvention = CallingConvention.Cdecl)]
        public static int smlad(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlal", CallingConvention = CallingConvention.Cdecl)]
        public static int smlal(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlalbb", CallingConvention = CallingConvention.Cdecl)]
        public static int smlalbb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlalbt", CallingConvention = CallingConvention.Cdecl)]
        public static int smlalbt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlaltb", CallingConvention = CallingConvention.Cdecl)]
        public static int smlaltb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlaltt", CallingConvention = CallingConvention.Cdecl)]
        public static int smlaltt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlald", CallingConvention = CallingConvention.Cdecl)]
        public static int smlald(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlawb", CallingConvention = CallingConvention.Cdecl)]
        public static int smlawb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlawt", CallingConvention = CallingConvention.Cdecl)]
        public static int smlawt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlsd", CallingConvention = CallingConvention.Cdecl)]
        public static int smlsd(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smlsld", CallingConvention = CallingConvention.Cdecl)]
        public static int smlsld(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smmla", CallingConvention = CallingConvention.Cdecl)]
        public static int smmla(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smmls", CallingConvention = CallingConvention.Cdecl)]
        public static int smmls(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smmul", CallingConvention = CallingConvention.Cdecl)]
        public static int smmul(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smuad", CallingConvention = CallingConvention.Cdecl)]
        public static int smuad(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smulbb", CallingConvention = CallingConvention.Cdecl)]
        public static int smulbb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smulbt", CallingConvention = CallingConvention.Cdecl)]
        public static int smulbt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smultb", CallingConvention = CallingConvention.Cdecl)]
        public static int smultb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smultt", CallingConvention = CallingConvention.Cdecl)]
        public static int smultt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smull", CallingConvention = CallingConvention.Cdecl)]
        public static int smull(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smulwb", CallingConvention = CallingConvention.Cdecl)]
        public static int smulwb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smulwt", CallingConvention = CallingConvention.Cdecl)]
        public static int smulwt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "smusd", CallingConvention = CallingConvention.Cdecl)]
        public static int smusd(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "srs", CallingConvention = CallingConvention.Cdecl)]
        public static int srs(bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ssat", CallingConvention = CallingConvention.Cdecl)]
        public static int ssat(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ssat16", CallingConvention = CallingConvention.Cdecl)]
        public static int ssat16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ssub16", CallingConvention = CallingConvention.Cdecl)]
        public static int ssub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ssub8", CallingConvention = CallingConvention.Cdecl)]
        public static int ssub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "ssubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int ssubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "stc", CallingConvention = CallingConvention.Cdecl)]
        public static int stc(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "stm1", CallingConvention = CallingConvention.Cdecl)]
        public static int stm1(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "stm2", CallingConvention = CallingConvention.Cdecl)]
        public static int stm2(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "str", CallingConvention = CallingConvention.Cdecl)]
        public static int str(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strb", CallingConvention = CallingConvention.Cdecl)]
        public static int strb(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strbt", CallingConvention = CallingConvention.Cdecl)]
        public static int strbt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strd", CallingConvention = CallingConvention.Cdecl)]
        public static int strd(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strex", CallingConvention = CallingConvention.Cdecl)]
        public static int strex(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strh", CallingConvention = CallingConvention.Cdecl)]
        public static int strh(Condition cond, bool write, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "strt", CallingConvention = CallingConvention.Cdecl)]
        public static int strt(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "swi", CallingConvention = CallingConvention.Cdecl)]
        public static int swi(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "swp", CallingConvention = CallingConvention.Cdecl)]
        public static int swp(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "swpb", CallingConvention = CallingConvention.Cdecl)]
        public static int swpb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxtab", CallingConvention = CallingConvention.Cdecl)]
        public static int sxtab(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxtab16", CallingConvention = CallingConvention.Cdecl)]
        public static int sxtab16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxtah", CallingConvention = CallingConvention.Cdecl)]
        public static int sxtah(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxtb", CallingConvention = CallingConvention.Cdecl)]
        public static int sxtb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxtb16", CallingConvention = CallingConvention.Cdecl)]
        public static int sxtb16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "sxth", CallingConvention = CallingConvention.Cdecl)]
        public static int sxth(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "teq", CallingConvention = CallingConvention.Cdecl)]
        public static int teq(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "tst", CallingConvention = CallingConvention.Cdecl)]
        public static int tst(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int uadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int uadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uaddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int uaddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int uhadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int uhadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhaddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int uhaddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhsub16", CallingConvention = CallingConvention.Cdecl)]
        public static int uhsub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhsub8", CallingConvention = CallingConvention.Cdecl)]
        public static int uhsub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uhsubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int uhsubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "umaal", CallingConvention = CallingConvention.Cdecl)]
        public static int umaal(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "umlal", CallingConvention = CallingConvention.Cdecl)]
        public static int umlal(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "umull", CallingConvention = CallingConvention.Cdecl)]
        public static int umull(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqadd16", CallingConvention = CallingConvention.Cdecl)]
        public static int uqadd16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqadd8", CallingConvention = CallingConvention.Cdecl)]
        public static int uqadd8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqaddsubx", CallingConvention = CallingConvention.Cdecl)]
        public static int uqaddsubx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqsub16", CallingConvention = CallingConvention.Cdecl)]
        public static int uqsub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqsub8", CallingConvention = CallingConvention.Cdecl)]
        public static int uqsub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uqsubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int uqsubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usad8", CallingConvention = CallingConvention.Cdecl)]
        public static int usad8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usada8", CallingConvention = CallingConvention.Cdecl)]
        public static int usada8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usat", CallingConvention = CallingConvention.Cdecl)]
        public static int usat(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usat16", CallingConvention = CallingConvention.Cdecl)]
        public static int usat16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usub16", CallingConvention = CallingConvention.Cdecl)]
        public static int usub16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usub8", CallingConvention = CallingConvention.Cdecl)]
        public static int usub8(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "usubaddx", CallingConvention = CallingConvention.Cdecl)]
        public static int usubaddx(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxtab", CallingConvention = CallingConvention.Cdecl)]
        public static int uxtab(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxtab16", CallingConvention = CallingConvention.Cdecl)]
        public static int uxtab16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxtah", CallingConvention = CallingConvention.Cdecl)]
        public static int uxtah(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxtb", CallingConvention = CallingConvention.Cdecl)]
        public static int uxtb(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxtb16", CallingConvention = CallingConvention.Cdecl)]
        public static int uxtb16(Condition cond, ref IntPtr buf);
        [DllImport("asmsq", EntryPoint = "uxth", CallingConvention = CallingConvention.Cdecl)]
        public static int uxth(Condition cond, ref IntPtr buf);

    }
}
