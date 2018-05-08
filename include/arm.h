
// Automatically generated file.
// Please see ../asm/arm.py for more informations.

#define byte unsigned char
#define bool _Bool
#define RET(x) return x
#define CALLCONV 


#ifndef uint32_t
#define uint32_t unsigned int
#endif

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

int CALLCONV adc(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x500;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV add(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x100;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV and(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV eor(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x400;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV orr(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x180;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV rsb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x600;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV rsc(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x700;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sbc(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x300;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sub(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x200;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV bkpt(void** buf) {
  uint32_t ins = 0xe000487;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV b(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x50;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV bic(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV blx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcfff480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV bx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8fff480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV bxj(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x4fff480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV blxun(void** buf) {
  uint32_t ins = 0x5f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cdp(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x70;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV clz(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f0f680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cmn(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xe80;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cmp(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa80;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cpy(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x580;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cps(void** buf) {
  uint32_t ins = 0x408f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cpsie(void** buf) {
  uint32_t ins = 0x108f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cpsid(void** buf) {
  uint32_t ins = 0x308f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cpsie_mode(void** buf) {
  uint32_t ins = 0x508f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV cpsid_mode(void** buf) {
  uint32_t ins = 0x708f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldc(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x230;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldm1(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x210;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldm2(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x290;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldm3(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x4290;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldr(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x220;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrb(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x2a0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrbt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x720;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrd(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x2c0000;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrex(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xf9f00980;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrh(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x340200;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrsb(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x2c0200;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrsh(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x3c0200;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ldrt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x620;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mcr(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x20070;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mcrr(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x230;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mla(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000400;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mov(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x580;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mrc(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x20170;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mrrc(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa30;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mrs(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xf080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mul(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000000;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV mvn(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x780;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV msr_imm(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xf4c0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV msr_reg(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xf480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV pkhbt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8000160;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV pkhtb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa000160;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV pld(void** buf) {
  uint32_t ins = 0x785af;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qadd(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qaddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qdadd(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qdsub(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa000680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qsub(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xa000480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qsub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qsub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV qsubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00460;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV rev(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf0fd60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV rev16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xdf0fd60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV revsh(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xdf0ff60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV rfe(/* switch */ bool write, void** buf) {
  uint32_t ins = 0x14021f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV saddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sel(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xdf00160;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV setendbe(void** buf) {
  uint32_t ins = 0x40808f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV setendle(void** buf) {
  uint32_t ins = 0x808f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shaddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shsub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shsub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV shsubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00c60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlabb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x1000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlabt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x5000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlatb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlatt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x7000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlad(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x40000e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlal(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000700;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlalbb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x1000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlalbt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x5000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlaltb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlaltt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x7000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlald(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x40002e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlawb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x1000480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlawt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3000480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlsd(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x60000e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smlsld(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x60002e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smmla(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8000ae0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smmls(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xb000ae0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smmul(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x80f0ae0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smuad(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x40f00e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smulbb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x1000680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smulbt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x5000680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smultb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3000680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smultt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x7000680;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smull(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x12000600;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smulwb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x5000480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smulwt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x7000480;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV smusd(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x60f00e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV srs(/* switch */ bool write, void** buf) {
  uint32_t ins = 0x282c9f;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ssat(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x20a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ssat16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf0560;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ssub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ssub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV ssubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00860;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV stc(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x30;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV stm1(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x10;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV stm2(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x90;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV str(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x20;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strb(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0xa0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strbt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x320;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strd(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x3c0000;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strex(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x4f80180;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strh(/* condition */ condition cond, /* switch */ bool write, void** buf) {
  uint32_t ins = 0x340000;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV strt(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x220;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV swi(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xf0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV swp(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000080;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV swpb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000280;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxtab(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800560;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxtab16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800160;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxtah(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800d60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxtb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380f560;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxtb16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380f160;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV sxth(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380fd60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV teq(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xc80;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV tst(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x880;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uaddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhaddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhsub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhsub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uhsubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00e60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV umaal(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000200;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV umlal(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000500;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV umull(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9000100;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqadd16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x8f00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqadd8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x9f00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqaddsubx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqsub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqsub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uqsubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00660;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usad8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x80f01e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usada8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x80001e0;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usat(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x10760;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usat16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xcf0760;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usub16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xef00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usub8(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xff00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV usubaddx(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0xaf00a60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxtab(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800760;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxtab16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800360;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxtah(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x3800f60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxtb(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380f760;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxtb16(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380f360;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

int CALLCONV uxth(/* condition */ condition cond, void** buf) {
  uint32_t ins = 0x380ff60;
  *(uint32_t*)(*buf) = ins;
  *buf += 4;
  RET(4);
}

