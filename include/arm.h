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

byte CALLCONV adc(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((1280 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV add(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((256 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV and(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((0 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV eor(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((1024 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV orr(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((384 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV rsb(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((1536 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV rsc(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((1792 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sbc(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((768 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sub(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((512 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV bkpt(void** buf) {
    *(int32_t*)(*buf + 0) = 234882183;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV b(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (80 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV bic(condition cond, bool i, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((896 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV blx(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (218100864 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV bx(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (150992000 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV bxj(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (83883136 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV blxun(void** buf) {
    *(int32_t*)(*buf + 0) = 95;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cdp(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (112 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV clz(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((150009472 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cmn(condition cond, bool i, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((3712 | cond) | (i ? 64 : 0)) | (rn << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cmp(condition cond, bool i, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((2688 | cond) | (i ? 64 : 0)) | (rn << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cpy(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((1408 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cps(Mode mode, void** buf) {
    *(int32_t*)(*buf + 0) = (16527 | (mode << 24));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cpsie(void** buf) {
    *(int32_t*)(*buf + 0) = 4239;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cpsid(void** buf) {
    *(int32_t*)(*buf + 0) = 12431;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cpsie_mode(Mode mode, void** buf) {
    *(int32_t*)(*buf + 0) = (20623 | (mode << 21));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV cpsid_mode(Mode mode, void** buf) {
    *(int32_t*)(*buf + 0) = (28815 | (mode << 21));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldc(condition cond, bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((560 | cond) | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldm1(condition cond, bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((528 | cond) | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldm2(condition cond, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = ((656 | cond) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldm3(condition cond, bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((17040 | cond) | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldr(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((544 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrb(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((672 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrbt(condition cond, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((1824 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrd(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((2883584 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrex(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrh(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((3408384 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrsb(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((2884096 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrsh(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((3932672 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ldrt(condition cond, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((1568 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mcr(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((131184 | cond) | (rd << 13));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mcrr(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((560 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mla(condition cond, bool s, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((150995968 | cond) | (s ? 2048 : 0)) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mov(condition cond, bool i, bool s, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((1408 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mrc(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((131440 | cond) | (rd << 13));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mrrc(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((2608 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mrs(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((61568 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mul(condition cond, bool s, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((150994944 | cond) | (s ? 2048 : 0)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV mvn(condition cond, bool i, bool s, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((1920 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV msr_imm(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (62656 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV msr_reg(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (62592 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV pkhbt(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV pkhtb(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV pld(bool i, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = ((492975 | (i ? 64 : 0)) | (rn << 11));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qadd(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qaddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qdadd(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qdsub(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qsub(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qsub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qsub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV qsubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV rev(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((217120096 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV rev16(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((233897312 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV revsh(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((233897824 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV rfe(bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = ((1311263 | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV saddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sel(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV setendbe(void** buf) {
    *(int32_t*)(*buf + 0) = 4227215;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV setendle(void** buf) {
    *(int32_t*)(*buf + 0) = 32911;
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shaddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shsub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shsub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV shsubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlabb(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlabt(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlatb(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlatt(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlad(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlal(condition cond, bool s, void** buf) {
    *(int32_t*)(*buf + 0) = ((150996736 | cond) | (s ? 2048 : 0));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlalbb(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (16777856 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlalbt(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (83886720 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlaltb(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (50332288 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlaltt(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (117441152 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlald(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (67109600 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlawb(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlawt(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlsd(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smlsld(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (100664032 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smmla(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smmls(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smmul(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((135203552 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smuad(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((68092128 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smulbb(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((16778880 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smulbt(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((83887744 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smultb(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((50333312 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smultt(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((117442176 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smull(condition cond, bool s, void** buf) {
    *(int32_t*)(*buf + 0) = ((301991424 | cond) | (s ? 4096 : 0));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smulwb(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((83887232 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smulwt(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((117441664 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV smusd(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((101646560 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV srs(bool write, Mode mode, void** buf) {
    *(int32_t*)(*buf + 0) = ((2632863 | (write ? 256 : 0)) | (mode << 26));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ssat(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((133728 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ssat16(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((13567328 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ssub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ssub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV ssubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV stc(condition cond, bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((48 | cond) | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV stm1(condition cond, bool write, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((16 | cond) | (write ? 256 : 0)) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV stm2(condition cond, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = ((144 | cond) | (rn << 10));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV str(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((32 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strb(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((160 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strbt(condition cond, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((800 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strd(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((3932160 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strex(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strh(condition cond, bool write, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((((3407872 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV strt(condition cond, bool i, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((((544 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV swi(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (240 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV swp(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV swpb(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxtab(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58721632 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxtab16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58720608 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxtah(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58723680 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxtb(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58783072 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxtb16(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58782048 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV sxth(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58785120 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV teq(condition cond, bool i, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((3200 | cond) | (i ? 64 : 0)) | (rn << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV tst(condition cond, bool i, reg rn, void** buf) {
    *(int32_t*)(*buf + 0) = (((2176 | cond) | (i ? 64 : 0)) | (rn << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uaddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhaddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhsub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhsub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uhsubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV umaal(condition cond, void** buf) {
    *(int32_t*)(*buf + 0) = (150995456 | cond);
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV umlal(condition cond, bool s, void** buf) {
    *(int32_t*)(*buf + 0) = ((150996224 | cond) | (s ? 2048 : 0));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV umull(condition cond, bool s, void** buf) {
    *(int32_t*)(*buf + 0) = ((150995200 | cond) | (s ? 2048 : 0));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqadd16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqadd8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqaddsubx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqsub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqsub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uqsubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usad8(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((135201248 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usada8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usat(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((67424 | cond) | (rd << 11));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usat16(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((13567840 | cond) | (rd << 12));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usub16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usub8(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV usubaddx(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxtab(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58722144 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxtab16(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58721120 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxtah(condition cond, reg rn, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = (((58724192 | cond) | (rn << 12)) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxtb(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58783584 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxtb16(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58782560 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
}

byte CALLCONV uxth(condition cond, reg rd, void** buf) {
    *(int32_t*)(*buf + 0) = ((58785632 | cond) | (rd << 16));
    *(byte*)buf += 4;
    return 4;
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
