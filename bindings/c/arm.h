// Automatically generated file.

#include <stdint.h>

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

int CALLCONV adc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV add(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV and(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV eor(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV orr(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV rsb(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV rsc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV sbc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV sub(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV bkpt(void** buf);
int CALLCONV b(condition cond, void** buf);
int CALLCONV bic(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
int CALLCONV blx(condition cond, void** buf);
int CALLCONV bx(condition cond, void** buf);
int CALLCONV bxj(condition cond, void** buf);
int CALLCONV blxun(void** buf);
int CALLCONV cdp(condition cond, void** buf);
int CALLCONV clz(condition cond, reg rd, void** buf);
int CALLCONV cmn(condition cond, bool i, reg rn, void** buf);
int CALLCONV cmp(condition cond, bool i, reg rn, void** buf);
int CALLCONV cpy(condition cond, reg rd, void** buf);
int CALLCONV cps(Mode mode, void** buf);
int CALLCONV cpsie(void** buf);
int CALLCONV cpsid(void** buf);
int CALLCONV cpsie_mode(Mode mode, void** buf);
int CALLCONV cpsid_mode(Mode mode, void** buf);
int CALLCONV ldc(condition cond, bool write, reg rn, void** buf);
int CALLCONV ldm1(condition cond, bool write, reg rn, void** buf);
int CALLCONV ldm2(condition cond, reg rn, void** buf);
int CALLCONV ldm3(condition cond, bool write, reg rn, void** buf);
int CALLCONV ldr(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrbt(condition cond, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrd(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrex(condition cond, reg rn, reg rd, void** buf);
int CALLCONV ldrh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrsb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrsh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV ldrt(condition cond, bool i, reg rn, reg rd, void** buf);
int CALLCONV mcr(condition cond, reg rd, void** buf);
int CALLCONV mcrr(condition cond, reg rn, reg rd, void** buf);
int CALLCONV mla(condition cond, bool s, reg rn, reg rd, void** buf);
int CALLCONV mov(condition cond, bool i, bool s, reg rd, void** buf);
int CALLCONV mrc(condition cond, reg rd, void** buf);
int CALLCONV mrrc(condition cond, reg rn, reg rd, void** buf);
int CALLCONV mrs(condition cond, reg rd, void** buf);
int CALLCONV mul(condition cond, bool s, reg rd, void** buf);
int CALLCONV mvn(condition cond, bool i, bool s, reg rd, void** buf);
int CALLCONV msr_imm(condition cond, void** buf);
int CALLCONV msr_reg(condition cond, void** buf);
int CALLCONV pkhbt(condition cond, reg rn, reg rd, void** buf);
int CALLCONV pkhtb(condition cond, reg rn, reg rd, void** buf);
int CALLCONV pld(bool i, reg rn, void** buf);
int CALLCONV qadd(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qaddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qdadd(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qdsub(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qsub(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qsub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qsub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV qsubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV rev(condition cond, reg rd, void** buf);
int CALLCONV rev16(condition cond, reg rd, void** buf);
int CALLCONV revsh(condition cond, reg rd, void** buf);
int CALLCONV rfe(bool write, reg rn, void** buf);
int CALLCONV sadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV saddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sel(condition cond, reg rn, reg rd, void** buf);
int CALLCONV setendbe(void** buf);
int CALLCONV setendle(void** buf);
int CALLCONV shadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV shadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV shaddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV shsub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV shsub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV shsubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlabb(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlabt(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlatb(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlatt(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlad(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlal(condition cond, bool s, void** buf);
int CALLCONV smlalbb(condition cond, void** buf);
int CALLCONV smlalbt(condition cond, void** buf);
int CALLCONV smlaltb(condition cond, void** buf);
int CALLCONV smlaltt(condition cond, void** buf);
int CALLCONV smlald(condition cond, void** buf);
int CALLCONV smlawb(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlawt(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlsd(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smlsld(condition cond, void** buf);
int CALLCONV smmla(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smmls(condition cond, reg rn, reg rd, void** buf);
int CALLCONV smmul(condition cond, reg rd, void** buf);
int CALLCONV smuad(condition cond, reg rd, void** buf);
int CALLCONV smulbb(condition cond, reg rd, void** buf);
int CALLCONV smulbt(condition cond, reg rd, void** buf);
int CALLCONV smultb(condition cond, reg rd, void** buf);
int CALLCONV smultt(condition cond, reg rd, void** buf);
int CALLCONV smull(condition cond, bool s, void** buf);
int CALLCONV smulwb(condition cond, reg rd, void** buf);
int CALLCONV smulwt(condition cond, reg rd, void** buf);
int CALLCONV smusd(condition cond, reg rd, void** buf);
int CALLCONV srs(bool write, Mode mode, void** buf);
int CALLCONV ssat(condition cond, reg rd, void** buf);
int CALLCONV ssat16(condition cond, reg rd, void** buf);
int CALLCONV ssub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV ssub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV ssubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV stc(condition cond, bool write, reg rn, void** buf);
int CALLCONV stm1(condition cond, bool write, reg rn, void** buf);
int CALLCONV stm2(condition cond, reg rn, void** buf);
int CALLCONV str(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV strb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV strbt(condition cond, bool i, reg rn, reg rd, void** buf);
int CALLCONV strd(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV strex(condition cond, reg rn, reg rd, void** buf);
int CALLCONV strh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
int CALLCONV strt(condition cond, bool i, reg rn, reg rd, void** buf);
int CALLCONV swi(condition cond, void** buf);
int CALLCONV swp(condition cond, reg rn, reg rd, void** buf);
int CALLCONV swpb(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sxtab(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sxtab16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sxtah(condition cond, reg rn, reg rd, void** buf);
int CALLCONV sxtb(condition cond, reg rd, void** buf);
int CALLCONV sxtb16(condition cond, reg rd, void** buf);
int CALLCONV sxth(condition cond, reg rd, void** buf);
int CALLCONV teq(condition cond, bool i, reg rn, void** buf);
int CALLCONV tst(condition cond, bool i, reg rn, void** buf);
int CALLCONV uadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uaddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhaddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhsub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhsub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uhsubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV umaal(condition cond, void** buf);
int CALLCONV umlal(condition cond, bool s, void** buf);
int CALLCONV umull(condition cond, bool s, void** buf);
int CALLCONV uqadd16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uqadd8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uqaddsubx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uqsub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uqsub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uqsubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV usad8(condition cond, reg rd, void** buf);
int CALLCONV usada8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV usat(condition cond, reg rd, void** buf);
int CALLCONV usat16(condition cond, reg rd, void** buf);
int CALLCONV usub16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV usub8(condition cond, reg rn, reg rd, void** buf);
int CALLCONV usubaddx(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uxtab(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uxtab16(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uxtah(condition cond, reg rn, reg rd, void** buf);
int CALLCONV uxtb(condition cond, reg rd, void** buf);
int CALLCONV uxtb16(condition cond, reg rd, void** buf);
int CALLCONV uxth(condition cond, reg rd, void** buf);

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
