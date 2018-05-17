// Automatically generated file.

#include <stdint.h>

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#ifndef uint32
#define uint32 unsigned int
#endif

#ifndef int32
#define int32 int
#endif

#ifndef int8
#define int8 char
#endif

#ifndef uint8
#define uint8 unsigned char
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

void CALLCONV adc(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV add(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV and(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV eor(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV orr(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV rsb(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV rsc(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV sbc(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV sub(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV bkpt(void** buf);
void CALLCONV b(void** buf, condition cond);
void CALLCONV bic(void** buf, condition cond, bool i, bool s, reg rn, reg rd);
void CALLCONV blx(void** buf, condition cond);
void CALLCONV bx(void** buf, condition cond);
void CALLCONV bxj(void** buf, condition cond);
void CALLCONV blxun(void** buf);
void CALLCONV cdp(void** buf, condition cond);
void CALLCONV clz(void** buf, condition cond, reg rd);
void CALLCONV cmn(void** buf, condition cond, bool i, reg rn);
void CALLCONV cmp(void** buf, condition cond, bool i, reg rn);
void CALLCONV cpy(void** buf, condition cond, reg rd);
void CALLCONV cps(void** buf, Mode mode);
void CALLCONV cpsie(void** buf);
void CALLCONV cpsid(void** buf);
void CALLCONV cpsie_mode(void** buf, Mode mode);
void CALLCONV cpsid_mode(void** buf, Mode mode);
void CALLCONV ldc(void** buf, condition cond, bool write, reg rn);
void CALLCONV ldm1(void** buf, condition cond, bool write, reg rn);
void CALLCONV ldm2(void** buf, condition cond, reg rn);
void CALLCONV ldm3(void** buf, condition cond, bool write, reg rn);
void CALLCONV ldr(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrb(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrbt(void** buf, condition cond, bool i, reg rn, reg rd);
void CALLCONV ldrd(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrex(void** buf, condition cond, reg rn, reg rd);
void CALLCONV ldrh(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrsb(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrsh(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV ldrt(void** buf, condition cond, bool i, reg rn, reg rd);
void CALLCONV mcr(void** buf, condition cond, reg rd);
void CALLCONV mcrr(void** buf, condition cond, reg rn, reg rd);
void CALLCONV mla(void** buf, condition cond, bool s, reg rn, reg rd);
void CALLCONV mov(void** buf, condition cond, bool i, bool s, reg rd);
void CALLCONV mrc(void** buf, condition cond, reg rd);
void CALLCONV mrrc(void** buf, condition cond, reg rn, reg rd);
void CALLCONV mrs(void** buf, condition cond, reg rd);
void CALLCONV mul(void** buf, condition cond, bool s, reg rd);
void CALLCONV mvn(void** buf, condition cond, bool i, bool s, reg rd);
void CALLCONV msr_imm(void** buf, condition cond);
void CALLCONV msr_reg(void** buf, condition cond);
void CALLCONV pkhbt(void** buf, condition cond, reg rn, reg rd);
void CALLCONV pkhtb(void** buf, condition cond, reg rn, reg rd);
void CALLCONV pld(void** buf, bool i, reg rn);
void CALLCONV qadd(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qaddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qdadd(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qdsub(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qsub(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qsub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qsub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV qsubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV rev(void** buf, condition cond, reg rd);
void CALLCONV rev16(void** buf, condition cond, reg rd);
void CALLCONV revsh(void** buf, condition cond, reg rd);
void CALLCONV rfe(void** buf, bool write, reg rn);
void CALLCONV sadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV saddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sel(void** buf, condition cond, reg rn, reg rd);
void CALLCONV setendbe(void** buf);
void CALLCONV setendle(void** buf);
void CALLCONV shadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV shadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV shaddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV shsub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV shsub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV shsubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlabb(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlabt(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlatb(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlatt(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlad(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlal(void** buf, condition cond, bool s);
void CALLCONV smlalbb(void** buf, condition cond);
void CALLCONV smlalbt(void** buf, condition cond);
void CALLCONV smlaltb(void** buf, condition cond);
void CALLCONV smlaltt(void** buf, condition cond);
void CALLCONV smlald(void** buf, condition cond);
void CALLCONV smlawb(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlawt(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlsd(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smlsld(void** buf, condition cond);
void CALLCONV smmla(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smmls(void** buf, condition cond, reg rn, reg rd);
void CALLCONV smmul(void** buf, condition cond, reg rd);
void CALLCONV smuad(void** buf, condition cond, reg rd);
void CALLCONV smulbb(void** buf, condition cond, reg rd);
void CALLCONV smulbt(void** buf, condition cond, reg rd);
void CALLCONV smultb(void** buf, condition cond, reg rd);
void CALLCONV smultt(void** buf, condition cond, reg rd);
void CALLCONV smull(void** buf, condition cond, bool s);
void CALLCONV smulwb(void** buf, condition cond, reg rd);
void CALLCONV smulwt(void** buf, condition cond, reg rd);
void CALLCONV smusd(void** buf, condition cond, reg rd);
void CALLCONV srs(void** buf, bool write, Mode mode);
void CALLCONV ssat(void** buf, condition cond, reg rd);
void CALLCONV ssat16(void** buf, condition cond, reg rd);
void CALLCONV ssub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV ssub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV ssubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV stc(void** buf, condition cond, bool write, reg rn);
void CALLCONV stm1(void** buf, condition cond, bool write, reg rn);
void CALLCONV stm2(void** buf, condition cond, reg rn);
void CALLCONV str(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV strb(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV strbt(void** buf, condition cond, bool i, reg rn, reg rd);
void CALLCONV strd(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV strex(void** buf, condition cond, reg rn, reg rd);
void CALLCONV strh(void** buf, condition cond, bool write, bool i, reg rn, reg rd);
void CALLCONV strt(void** buf, condition cond, bool i, reg rn, reg rd);
void CALLCONV swi(void** buf, condition cond);
void CALLCONV swp(void** buf, condition cond, reg rn, reg rd);
void CALLCONV swpb(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sxtab(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sxtab16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sxtah(void** buf, condition cond, reg rn, reg rd);
void CALLCONV sxtb(void** buf, condition cond, reg rd);
void CALLCONV sxtb16(void** buf, condition cond, reg rd);
void CALLCONV sxth(void** buf, condition cond, reg rd);
void CALLCONV teq(void** buf, condition cond, bool i, reg rn);
void CALLCONV tst(void** buf, condition cond, bool i, reg rn);
void CALLCONV uadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uaddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhaddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhsub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhsub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uhsubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV umaal(void** buf, condition cond);
void CALLCONV umlal(void** buf, condition cond, bool s);
void CALLCONV umull(void** buf, condition cond, bool s);
void CALLCONV uqadd16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uqadd8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uqaddsubx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uqsub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uqsub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uqsubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV usad8(void** buf, condition cond, reg rd);
void CALLCONV usada8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV usat(void** buf, condition cond, reg rd);
void CALLCONV usat16(void** buf, condition cond, reg rd);
void CALLCONV usub16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV usub8(void** buf, condition cond, reg rn, reg rd);
void CALLCONV usubaddx(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uxtab(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uxtab16(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uxtah(void** buf, condition cond, reg rn, reg rd);
void CALLCONV uxtb(void** buf, condition cond, reg rd);
void CALLCONV uxtb16(void** buf, condition cond, reg rd);
void CALLCONV uxth(void** buf, condition cond, reg rd);

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
