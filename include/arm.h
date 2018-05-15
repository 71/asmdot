// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define reg byte

typedef enum {
    ///
    /// Equal.
    EQ = 0b0000,
    ///
    /// Not equal.
    NE = 0b0001,
    ///
    /// Carry set.
    CS = 0b0010,
    ///
    /// Unsigned higher or same.
    HS = 0b0010,
    ///
    /// Carry clear.
    CC = 0b0011,
    ///
    /// Unsigned lower.
    LO = 0b0011,
    ///
    /// Minus / negative.
    MI = 0b0100,
    ///
    /// Plus / positive or zero.
    PL = 0b0101,
    ///
    /// Overflow.
    VS = 0b0110,
    ///
    /// No overflow.
    VC = 0b0111,
    ///
    /// Unsigned higher.
    HI = 0b1000,
    ///
    /// Unsigned lower or same.
    LS = 0b1001,
    ///
    /// Signed greater than or equal.
    GE = 0b1010,
    ///
    /// Signed less than.
    LT = 0b1011,
    ///
    /// Signed greater than.
    GT = 0b1100,
    ///
    /// Signed less than or equal.
    LE = 0b1101,
    ///
    /// Always (unconditional).
    AL = 0b1110,
    ///
    /// Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).
    UN = 0b1111
} condition;

typedef enum {
    /// User mode.
    USR = 0b10000,
    /// FIQ (high-speed data transfer) mode.
    FIQ = 0b10001,
    /// IRQ (general-purpose interrupt handling) mode.
    IRQ = 0b10010,
    /// Supervisor mode.
    SVC = 0b10011,
    /// Abort mode.
    ABT = 0b10111,
    /// Undefined mode.
    UND = 0b11011,
    /// System (privileged) mode.
    SYS = 0b11111
} Mode;

int adc(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int add(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int and(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int eor(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int orr(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int rsb(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int rsc(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int sbc(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int sub(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int bkpt(void* buf);
int b(condition cond, void* buf);
int bic(condition cond, bool i, bool s, reg rn, reg rd, void* buf);
int blx(condition cond, void* buf);
int bx(condition cond, void* buf);
int bxj(condition cond, void* buf);
int blxun(void* buf);
int cdp(condition cond, void* buf);
int clz(condition cond, reg rd, void* buf);
int cmn(condition cond, bool i, reg rn, void* buf);
int cmp(condition cond, bool i, reg rn, void* buf);
int cpy(condition cond, reg rd, void* buf);
int cps(Mode mode, void* buf);
int cpsie(void* buf);
int cpsid(void* buf);
int cpsie_mode(Mode mode, void* buf);
int cpsid_mode(Mode mode, void* buf);
int ldc(condition cond, bool write, reg rn, void* buf);
int ldm1(condition cond, bool write, reg rn, void* buf);
int ldm2(condition cond, reg rn, void* buf);
int ldm3(condition cond, bool write, reg rn, void* buf);
int ldr(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrb(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrbt(condition cond, bool i, reg rn, reg rd, void* buf);
int ldrd(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrex(condition cond, reg rn, reg rd, void* buf);
int ldrh(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrsb(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrsh(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int ldrt(condition cond, bool i, reg rn, reg rd, void* buf);
int mcr(condition cond, reg rd, void* buf);
int mcrr(condition cond, reg rn, reg rd, void* buf);
int mla(condition cond, bool s, reg rn, reg rd, void* buf);
int mov(condition cond, bool i, bool s, reg rd, void* buf);
int mrc(condition cond, reg rd, void* buf);
int mrrc(condition cond, reg rn, reg rd, void* buf);
int mrs(condition cond, reg rd, void* buf);
int mul(condition cond, bool s, reg rd, void* buf);
int mvn(condition cond, bool i, bool s, reg rd, void* buf);
int msr_imm(condition cond, void* buf);
int msr_reg(condition cond, void* buf);
int pkhbt(condition cond, reg rn, reg rd, void* buf);
int pkhtb(condition cond, reg rn, reg rd, void* buf);
int pld(bool i, reg rn, void* buf);
int qadd(condition cond, reg rn, reg rd, void* buf);
int qadd16(condition cond, reg rn, reg rd, void* buf);
int qadd8(condition cond, reg rn, reg rd, void* buf);
int qaddsubx(condition cond, reg rn, reg rd, void* buf);
int qdadd(condition cond, reg rn, reg rd, void* buf);
int qdsub(condition cond, reg rn, reg rd, void* buf);
int qsub(condition cond, reg rn, reg rd, void* buf);
int qsub16(condition cond, reg rn, reg rd, void* buf);
int qsub8(condition cond, reg rn, reg rd, void* buf);
int qsubaddx(condition cond, reg rn, reg rd, void* buf);
int rev(condition cond, reg rd, void* buf);
int rev16(condition cond, reg rd, void* buf);
int revsh(condition cond, reg rd, void* buf);
int rfe(bool write, reg rn, void* buf);
int sadd16(condition cond, reg rn, reg rd, void* buf);
int sadd8(condition cond, reg rn, reg rd, void* buf);
int saddsubx(condition cond, reg rn, reg rd, void* buf);
int sel(condition cond, reg rn, reg rd, void* buf);
int setendbe(void* buf);
int setendle(void* buf);
int shadd16(condition cond, reg rn, reg rd, void* buf);
int shadd8(condition cond, reg rn, reg rd, void* buf);
int shaddsubx(condition cond, reg rn, reg rd, void* buf);
int shsub16(condition cond, reg rn, reg rd, void* buf);
int shsub8(condition cond, reg rn, reg rd, void* buf);
int shsubaddx(condition cond, reg rn, reg rd, void* buf);
int smlabb(condition cond, reg rn, reg rd, void* buf);
int smlabt(condition cond, reg rn, reg rd, void* buf);
int smlatb(condition cond, reg rn, reg rd, void* buf);
int smlatt(condition cond, reg rn, reg rd, void* buf);
int smlad(condition cond, reg rn, reg rd, void* buf);
int smlal(condition cond, bool s, void* buf);
int smlalbb(condition cond, void* buf);
int smlalbt(condition cond, void* buf);
int smlaltb(condition cond, void* buf);
int smlaltt(condition cond, void* buf);
int smlald(condition cond, void* buf);
int smlawb(condition cond, reg rn, reg rd, void* buf);
int smlawt(condition cond, reg rn, reg rd, void* buf);
int smlsd(condition cond, reg rn, reg rd, void* buf);
int smlsld(condition cond, void* buf);
int smmla(condition cond, reg rn, reg rd, void* buf);
int smmls(condition cond, reg rn, reg rd, void* buf);
int smmul(condition cond, reg rd, void* buf);
int smuad(condition cond, reg rd, void* buf);
int smulbb(condition cond, reg rd, void* buf);
int smulbt(condition cond, reg rd, void* buf);
int smultb(condition cond, reg rd, void* buf);
int smultt(condition cond, reg rd, void* buf);
int smull(condition cond, bool s, void* buf);
int smulwb(condition cond, reg rd, void* buf);
int smulwt(condition cond, reg rd, void* buf);
int smusd(condition cond, reg rd, void* buf);
int srs(bool write, Mode mode, void* buf);
int ssat(condition cond, reg rd, void* buf);
int ssat16(condition cond, reg rd, void* buf);
int ssub16(condition cond, reg rn, reg rd, void* buf);
int ssub8(condition cond, reg rn, reg rd, void* buf);
int ssubaddx(condition cond, reg rn, reg rd, void* buf);
int stc(condition cond, bool write, reg rn, void* buf);
int stm1(condition cond, bool write, reg rn, void* buf);
int stm2(condition cond, reg rn, void* buf);
int str(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int strb(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int strbt(condition cond, bool i, reg rn, reg rd, void* buf);
int strd(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int strex(condition cond, reg rn, reg rd, void* buf);
int strh(condition cond, bool write, bool i, reg rn, reg rd, void* buf);
int strt(condition cond, bool i, reg rn, reg rd, void* buf);
int swi(condition cond, void* buf);
int swp(condition cond, reg rn, reg rd, void* buf);
int swpb(condition cond, reg rn, reg rd, void* buf);
int sxtab(condition cond, reg rn, reg rd, void* buf);
int sxtab16(condition cond, reg rn, reg rd, void* buf);
int sxtah(condition cond, reg rn, reg rd, void* buf);
int sxtb(condition cond, reg rd, void* buf);
int sxtb16(condition cond, reg rd, void* buf);
int sxth(condition cond, reg rd, void* buf);
int teq(condition cond, bool i, reg rn, void* buf);
int tst(condition cond, bool i, reg rn, void* buf);
int uadd16(condition cond, reg rn, reg rd, void* buf);
int uadd8(condition cond, reg rn, reg rd, void* buf);
int uaddsubx(condition cond, reg rn, reg rd, void* buf);
int uhadd16(condition cond, reg rn, reg rd, void* buf);
int uhadd8(condition cond, reg rn, reg rd, void* buf);
int uhaddsubx(condition cond, reg rn, reg rd, void* buf);
int uhsub16(condition cond, reg rn, reg rd, void* buf);
int uhsub8(condition cond, reg rn, reg rd, void* buf);
int uhsubaddx(condition cond, reg rn, reg rd, void* buf);
int umaal(condition cond, void* buf);
int umlal(condition cond, bool s, void* buf);
int umull(condition cond, bool s, void* buf);
int uqadd16(condition cond, reg rn, reg rd, void* buf);
int uqadd8(condition cond, reg rn, reg rd, void* buf);
int uqaddsubx(condition cond, reg rn, reg rd, void* buf);
int uqsub16(condition cond, reg rn, reg rd, void* buf);
int uqsub8(condition cond, reg rn, reg rd, void* buf);
int uqsubaddx(condition cond, reg rn, reg rd, void* buf);
int usad8(condition cond, reg rd, void* buf);
int usada8(condition cond, reg rn, reg rd, void* buf);
int usat(condition cond, reg rd, void* buf);
int usat16(condition cond, reg rd, void* buf);
int usub16(condition cond, reg rn, reg rd, void* buf);
int usub8(condition cond, reg rn, reg rd, void* buf);
int usubaddx(condition cond, reg rn, reg rd, void* buf);
int uxtab(condition cond, reg rn, reg rd, void* buf);
int uxtab16(condition cond, reg rn, reg rd, void* buf);
int uxtah(condition cond, reg rn, reg rd, void* buf);
int uxtb(condition cond, reg rd, void* buf);
int uxtb16(condition cond, reg rd, void* buf);
int uxth(condition cond, reg rd, void* buf);
#define r0 0x0
#define r1 0x1
#define r2 0x2
#define r3 0x3
#define r4 0x4
#define r5 0x5
#define r6 0x6
#define r7 0x7
#define r8 0x8
#define r9 0x9
#define r10 0xa
#define r11 0xb
#define r12 0xc
#define r13 0xd
#define r14 0xe
#define r15 0xf
#define a1 0x0
#define a2 0x1
#define a3 0x2
#define a4 0x3
#define v1 0x4
#define v2 0x5
#define v3 0x6
#define v4 0x7
#define v5 0x8
#define v6 0x9
#define v7 0xa
#define v8 0xb
#define ip 0xc
#define sp 0xd
#define lr 0xe
#define pc 0xf
#define wr 0x7
#define sb 0x9
#define sl 0xa
#define fp 0xb
