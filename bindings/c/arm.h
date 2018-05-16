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

byte CALLCONV adc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV add(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV and(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV eor(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV orr(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV rsb(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV rsc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV sbc(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV sub(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV bkpt(void** buf);
byte CALLCONV b(condition cond, void** buf);
byte CALLCONV bic(condition cond, bool i, bool s, reg rn, reg rd, void** buf);
byte CALLCONV blx(condition cond, void** buf);
byte CALLCONV bx(condition cond, void** buf);
byte CALLCONV bxj(condition cond, void** buf);
byte CALLCONV blxun(void** buf);
byte CALLCONV cdp(condition cond, void** buf);
byte CALLCONV clz(condition cond, reg rd, void** buf);
byte CALLCONV cmn(condition cond, bool i, reg rn, void** buf);
byte CALLCONV cmp(condition cond, bool i, reg rn, void** buf);
byte CALLCONV cpy(condition cond, reg rd, void** buf);
byte CALLCONV cps(Mode mode, void** buf);
byte CALLCONV cpsie(void** buf);
byte CALLCONV cpsid(void** buf);
byte CALLCONV cpsie_mode(Mode mode, void** buf);
byte CALLCONV cpsid_mode(Mode mode, void** buf);
byte CALLCONV ldc(condition cond, bool write, reg rn, void** buf);
byte CALLCONV ldm1(condition cond, bool write, reg rn, void** buf);
byte CALLCONV ldm2(condition cond, reg rn, void** buf);
byte CALLCONV ldm3(condition cond, bool write, reg rn, void** buf);
byte CALLCONV ldr(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrbt(condition cond, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrd(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrex(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV ldrh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrsb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrsh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV ldrt(condition cond, bool i, reg rn, reg rd, void** buf);
byte CALLCONV mcr(condition cond, reg rd, void** buf);
byte CALLCONV mcrr(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV mla(condition cond, bool s, reg rn, reg rd, void** buf);
byte CALLCONV mov(condition cond, bool i, bool s, reg rd, void** buf);
byte CALLCONV mrc(condition cond, reg rd, void** buf);
byte CALLCONV mrrc(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV mrs(condition cond, reg rd, void** buf);
byte CALLCONV mul(condition cond, bool s, reg rd, void** buf);
byte CALLCONV mvn(condition cond, bool i, bool s, reg rd, void** buf);
byte CALLCONV msr_imm(condition cond, void** buf);
byte CALLCONV msr_reg(condition cond, void** buf);
byte CALLCONV pkhbt(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV pkhtb(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV pld(bool i, reg rn, void** buf);
byte CALLCONV qadd(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qaddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qdadd(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qdsub(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qsub(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qsub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qsub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV qsubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV rev(condition cond, reg rd, void** buf);
byte CALLCONV rev16(condition cond, reg rd, void** buf);
byte CALLCONV revsh(condition cond, reg rd, void** buf);
byte CALLCONV rfe(bool write, reg rn, void** buf);
byte CALLCONV sadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV saddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sel(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV setendbe(void** buf);
byte CALLCONV setendle(void** buf);
byte CALLCONV shadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV shadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV shaddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV shsub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV shsub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV shsubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlabb(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlabt(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlatb(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlatt(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlad(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlal(condition cond, bool s, void** buf);
byte CALLCONV smlalbb(condition cond, void** buf);
byte CALLCONV smlalbt(condition cond, void** buf);
byte CALLCONV smlaltb(condition cond, void** buf);
byte CALLCONV smlaltt(condition cond, void** buf);
byte CALLCONV smlald(condition cond, void** buf);
byte CALLCONV smlawb(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlawt(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlsd(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smlsld(condition cond, void** buf);
byte CALLCONV smmla(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smmls(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV smmul(condition cond, reg rd, void** buf);
byte CALLCONV smuad(condition cond, reg rd, void** buf);
byte CALLCONV smulbb(condition cond, reg rd, void** buf);
byte CALLCONV smulbt(condition cond, reg rd, void** buf);
byte CALLCONV smultb(condition cond, reg rd, void** buf);
byte CALLCONV smultt(condition cond, reg rd, void** buf);
byte CALLCONV smull(condition cond, bool s, void** buf);
byte CALLCONV smulwb(condition cond, reg rd, void** buf);
byte CALLCONV smulwt(condition cond, reg rd, void** buf);
byte CALLCONV smusd(condition cond, reg rd, void** buf);
byte CALLCONV srs(bool write, Mode mode, void** buf);
byte CALLCONV ssat(condition cond, reg rd, void** buf);
byte CALLCONV ssat16(condition cond, reg rd, void** buf);
byte CALLCONV ssub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV ssub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV ssubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV stc(condition cond, bool write, reg rn, void** buf);
byte CALLCONV stm1(condition cond, bool write, reg rn, void** buf);
byte CALLCONV stm2(condition cond, reg rn, void** buf);
byte CALLCONV str(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV strb(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV strbt(condition cond, bool i, reg rn, reg rd, void** buf);
byte CALLCONV strd(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV strex(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV strh(condition cond, bool write, bool i, reg rn, reg rd, void** buf);
byte CALLCONV strt(condition cond, bool i, reg rn, reg rd, void** buf);
byte CALLCONV swi(condition cond, void** buf);
byte CALLCONV swp(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV swpb(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sxtab(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sxtab16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sxtah(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV sxtb(condition cond, reg rd, void** buf);
byte CALLCONV sxtb16(condition cond, reg rd, void** buf);
byte CALLCONV sxth(condition cond, reg rd, void** buf);
byte CALLCONV teq(condition cond, bool i, reg rn, void** buf);
byte CALLCONV tst(condition cond, bool i, reg rn, void** buf);
byte CALLCONV uadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uaddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhaddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhsub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhsub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uhsubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV umaal(condition cond, void** buf);
byte CALLCONV umlal(condition cond, bool s, void** buf);
byte CALLCONV umull(condition cond, bool s, void** buf);
byte CALLCONV uqadd16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uqadd8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uqaddsubx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uqsub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uqsub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uqsubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV usad8(condition cond, reg rd, void** buf);
byte CALLCONV usada8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV usat(condition cond, reg rd, void** buf);
byte CALLCONV usat16(condition cond, reg rd, void** buf);
byte CALLCONV usub16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV usub8(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV usubaddx(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uxtab(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uxtab16(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uxtah(condition cond, reg rn, reg rd, void** buf);
byte CALLCONV uxtb(condition cond, reg rd, void** buf);
byte CALLCONV uxtb16(condition cond, reg rd, void** buf);
byte CALLCONV uxth(condition cond, reg rd, void** buf);

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
