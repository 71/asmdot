// Automatically generated file.

#include <stdint.h>

#define byte unsigned char
#define bool _Bool
#define CALLCONV 



#define reg byte

///
/// Condition for an ARM instruction to be executed.
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
} Condition;

///
/// Processor mode.
typedef enum {
    ///
    /// User mode.
    USR = 0b10000,
    ///
    /// FIQ (high-speed data transfer) mode.
    FIQ = 0b10001,
    ///
    /// IRQ (general-purpose interrupt handling) mode.
    IRQ = 0b10010,
    ///
    /// Supervisor mode.
    SVC = 0b10011,
    ///
    /// Abort mode.
    ABT = 0b10111,
    ///
    /// Undefined mode.
    UND = 0b11011,
    ///
    /// System (privileged) mode.
    SYS = 0b11111
} Mode;

///
/// Kind of a shift.
typedef enum {
    ///
    /// Logical shift left.
    LSL = 0b00,
    ///
    /// Logical shift right.
    LSR = 0b01,
    ///
    /// Arithmetic shift right.
    ASR = 0b10,
    ///
    /// Rotate right.
    ROR = 0b11,
    ///
    /// Shifted right by one bit.
    RRX = 0b11
} Shift;

///
/// Kind of a right rotation.
typedef enum {
    ///
    /// Rotate 8 bits to the right.
    ROR8  = 0b01,
    ///
    /// Rotate 16 bits to the right.
    ROR16 = 0b10,
    ///
    /// Rotate 24 bits to the right.
    ROR24 = 0b11,
    ///
    /// Do not rotate.
    NOP   = 0b00
} Rotation;

///
/// Field mask bits.
typedef enum {
    ///
    /// Control field mask bit.
    C = 0b0001,
    ///
    /// Extension field mask bit.
    X = 0b0010,
    ///
    /// Status field mask bit.
    S = 0b0100,
    ///
    /// Flags field mask bit.
    F = 0b1000
} Field;

///
/// Interrupt flags.
typedef enum {
    ///
    /// Imprecise data abort bit.
    A = 0b100,
    ///
    /// IRQ interrupt bit.
    I = 0b010,
    ///
    /// FIQ interrupt bit.
    F = 0b001
} InterruptFlags;

void CALLCONV adc(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((1280 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV add(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((256 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((0 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV eor(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((1024 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV orr(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((384 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV rsb(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((1536 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV rsc(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((1792 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sbc(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((768 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((512 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV bkpt(void** buf) {
    *(uint32_t*)(*buf) = 234882183;
    *(byte*)buf += 4;
}

void CALLCONV b(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (80 | cond);
    *(byte*)buf += 4;
}

void CALLCONV bic(void** buf, Condition cond, bool i, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((896 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV blx(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (218100864 | cond);
    *(byte*)buf += 4;
}

void CALLCONV bx(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (150992000 | cond);
    *(byte*)buf += 4;
}

void CALLCONV bxj(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (83883136 | cond);
    *(byte*)buf += 4;
}

void CALLCONV blxun(void** buf) {
    *(uint32_t*)(*buf) = 95;
    *(byte*)buf += 4;
}

void CALLCONV cdp(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (112 | cond);
    *(byte*)buf += 4;
}

void CALLCONV clz(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((150009472 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV cmn(void** buf, Condition cond, bool i, Reg rn) {
    *(uint32_t*)(*buf) = (((3712 | cond) | (i << 6)) | (rn << 12));
    *(byte*)buf += 4;
}

void CALLCONV cmp(void** buf, Condition cond, bool i, Reg rn) {
    *(uint32_t*)(*buf) = (((2688 | cond) | (i << 6)) | (rn << 12));
    *(byte*)buf += 4;
}

void CALLCONV cpy(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((1408 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV cps(void** buf, Mode mode) {
    *(uint32_t*)(*buf) = (16527 | (mode << 24));
    *(byte*)buf += 4;
}

void CALLCONV cpsie(void** buf) {
    *(uint32_t*)(*buf) = 4239;
    *(byte*)buf += 4;
}

void CALLCONV cpsid(void** buf) {
    *(uint32_t*)(*buf) = 12431;
    *(byte*)buf += 4;
}

void CALLCONV cpsie_mode(void** buf, Mode mode) {
    *(uint32_t*)(*buf) = (20623 | (mode << 21));
    *(byte*)buf += 4;
}

void CALLCONV cpsid_mode(void** buf, Mode mode) {
    *(uint32_t*)(*buf) = (28815 | (mode << 21));
    *(byte*)buf += 4;
}

void CALLCONV ldc(void** buf, Condition cond, bool write, Reg rn) {
    *(uint32_t*)(*buf) = (((560 | cond) | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV ldm1(void** buf, Condition cond, bool write, Reg rn) {
    *(uint32_t*)(*buf) = (((528 | cond) | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV ldm2(void** buf, Condition cond, Reg rn) {
    *(uint32_t*)(*buf) = ((656 | cond) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV ldm3(void** buf, Condition cond, bool write, Reg rn) {
    *(uint32_t*)(*buf) = (((17040 | cond) | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV ldr(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((544 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrb(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((672 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrbt(void** buf, Condition cond, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = ((((1824 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
}

void CALLCONV ldrd(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((2883584 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrex(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV ldrh(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((3408384 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrsb(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((2884096 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrsh(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((3932672 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV ldrt(void** buf, Condition cond, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = ((((1568 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
}

void CALLCONV mcr(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((131184 | cond) | (rd << 13));
    *(byte*)buf += 4;
}

void CALLCONV mcrr(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((560 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV mla(void** buf, Condition cond, bool s, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = ((((150995968 | cond) | (s << 11)) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV mov(void** buf, Condition cond, bool i, bool s, Reg rd) {
    *(uint32_t*)(*buf) = ((((1408 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV mrc(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((131440 | cond) | (rd << 13));
    *(byte*)buf += 4;
}

void CALLCONV mrrc(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((2608 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV mrs(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((61568 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV mul(void** buf, Condition cond, bool s, Reg rd) {
    *(uint32_t*)(*buf) = (((150994944 | cond) | (s << 11)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV mvn(void** buf, Condition cond, bool i, bool s, Reg rd) {
    *(uint32_t*)(*buf) = ((((1920 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV msr_imm(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (62656 | cond);
    *(byte*)buf += 4;
}

void CALLCONV msr_reg(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (62592 | cond);
    *(byte*)buf += 4;
}

void CALLCONV pkhbt(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV pkhtb(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV pld(void** buf, bool i, Reg rn) {
    *(uint32_t*)(*buf) = ((492975 | (i << 6)) | (rn << 11));
    *(byte*)buf += 4;
}

void CALLCONV qadd(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qdadd(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qdsub(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qsub(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qsub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qsub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV qsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV rev(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((217120096 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV rev16(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((233897312 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV revsh(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((233897824 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV rfe(void** buf, bool write, Reg rn) {
    *(uint32_t*)(*buf) = ((1311263 | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV sadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV saddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sel(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV setendbe(void** buf) {
    *(uint32_t*)(*buf) = 4227215;
    *(byte*)buf += 4;
}

void CALLCONV setendle(void** buf) {
    *(uint32_t*)(*buf) = 32911;
    *(byte*)buf += 4;
}

void CALLCONV shadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV shadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV shaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV shsub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV shsub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV shsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV smlabb(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlabt(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlatb(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlatt(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlad(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlal(void** buf, Condition cond, bool s) {
    *(uint32_t*)(*buf) = ((150996736 | cond) | (s << 11));
    *(byte*)buf += 4;
}

void CALLCONV smlalbb(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (16777856 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smlalbt(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (83886720 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smlaltb(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (50332288 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smlaltt(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (117441152 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smlald(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (67109600 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smlawb(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlawt(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlsd(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smlsld(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (100664032 | cond);
    *(byte*)buf += 4;
}

void CALLCONV smmla(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smmls(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smmul(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((135203552 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smuad(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((68092128 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smulbb(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((16778880 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smulbt(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((83887744 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smultb(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((50333312 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smultt(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((117442176 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smull(void** buf, Condition cond, bool s) {
    *(uint32_t*)(*buf) = ((301991424 | cond) | (s << 12));
    *(byte*)buf += 4;
}

void CALLCONV smulwb(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((83887232 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smulwt(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((117441664 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV smusd(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((101646560 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV srs(void** buf, bool write, Mode mode) {
    *(uint32_t*)(*buf) = ((2632863 | (write << 8)) | (mode << 26));
    *(byte*)buf += 4;
}

void CALLCONV ssat(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((133728 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV ssat16(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((13567328 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV ssub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV ssub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV ssubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV stc(void** buf, Condition cond, bool write, Reg rn) {
    *(uint32_t*)(*buf) = (((48 | cond) | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV stm1(void** buf, Condition cond, bool write, Reg rn) {
    *(uint32_t*)(*buf) = (((16 | cond) | (write << 8)) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV stm2(void** buf, Condition cond, Reg rn) {
    *(uint32_t*)(*buf) = ((144 | cond) | (rn << 10));
    *(byte*)buf += 4;
}

void CALLCONV str(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((32 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV strb(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((160 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV strbt(void** buf, Condition cond, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = ((((800 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
}

void CALLCONV strd(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((3932160 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV strex(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
}

void CALLCONV strh(void** buf, Condition cond, bool write, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((((3407872 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
}

void CALLCONV strt(void** buf, Condition cond, bool i, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = ((((544 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
}

void CALLCONV swi(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (240 | cond);
    *(byte*)buf += 4;
}

void CALLCONV swp(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV swpb(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxtab(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58721632 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxtab16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58720608 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxtah(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58723680 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxtb(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58783072 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxtb16(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58782048 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV sxth(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58785120 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV teq(void** buf, Condition cond, bool i, Reg rn) {
    *(uint32_t*)(*buf) = (((3200 | cond) | (i << 6)) | (rn << 12));
    *(byte*)buf += 4;
}

void CALLCONV tst(void** buf, Condition cond, bool i, Reg rn) {
    *(uint32_t*)(*buf) = (((2176 | cond) | (i << 6)) | (rn << 12));
    *(byte*)buf += 4;
}

void CALLCONV uadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhsub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhsub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uhsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV umaal(void** buf, Condition cond) {
    *(uint32_t*)(*buf) = (150995456 | cond);
    *(byte*)buf += 4;
}

void CALLCONV umlal(void** buf, Condition cond, bool s) {
    *(uint32_t*)(*buf) = ((150996224 | cond) | (s << 11));
    *(byte*)buf += 4;
}

void CALLCONV umull(void** buf, Condition cond, bool s) {
    *(uint32_t*)(*buf) = ((150995200 | cond) | (s << 11));
    *(byte*)buf += 4;
}

void CALLCONV uqadd16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uqadd8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uqaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uqsub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uqsub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uqsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV usad8(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((135201248 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV usada8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV usat(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((67424 | cond) | (rd << 11));
    *(byte*)buf += 4;
}

void CALLCONV usat16(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((13567840 | cond) | (rd << 12));
    *(byte*)buf += 4;
}

void CALLCONV usub16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV usub8(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV usubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxtab(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58722144 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxtab16(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58721120 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxtah(void** buf, Condition cond, Reg rn, Reg rd) {
    *(uint32_t*)(*buf) = (((58724192 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxtb(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58783584 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxtb16(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58782560 | cond) | (rd << 16));
    *(byte*)buf += 4;
}

void CALLCONV uxth(void** buf, Condition cond, Reg rd) {
    *(uint32_t*)(*buf) = ((58785632 | cond) | (rd << 16));
    *(byte*)buf += 4;
}


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
