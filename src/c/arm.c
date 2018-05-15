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

int adc(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((1280 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int add(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((256 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int and(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((0 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int eor(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((1024 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int orr(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((384 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int rsb(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((1536 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int rsc(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((1792 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int sbc(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((768 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int sub(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((512 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int bkpt(void* buf) {
    *(int32*)(buf + 0) = 234882183;
    return 4;
}

int b(condition cond, void* buf) {
    *(int32*)(buf + 0) = (80 | cond);
    return 4;
}

int bic(condition cond, bool i, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((896 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
    return 4;
}

int blx(condition cond, void* buf) {
    *(int32*)(buf + 0) = (218100864 | cond);
    return 4;
}

int bx(condition cond, void* buf) {
    *(int32*)(buf + 0) = (150992000 | cond);
    return 4;
}

int bxj(condition cond, void* buf) {
    *(int32*)(buf + 0) = (83883136 | cond);
    return 4;
}

int blxun(void* buf) {
    *(int32*)(buf + 0) = 95;
    return 4;
}

int cdp(condition cond, void* buf) {
    *(int32*)(buf + 0) = (112 | cond);
    return 4;
}

int clz(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((150009472 | cond) | (rd << 16));
    return 4;
}

int cmn(condition cond, bool i, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((3712 | cond) | (i ? 64 : 0)) | (rn << 12));
    return 4;
}

int cmp(condition cond, bool i, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((2688 | cond) | (i ? 64 : 0)) | (rn << 12));
    return 4;
}

int cpy(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((1408 | cond) | (rd << 16));
    return 4;
}

int cps(Mode mode, void* buf) {
    *(int32*)(buf + 0) = (16527 | (mode << 24));
    return 4;
}

int cpsie(void* buf) {
    *(int32*)(buf + 0) = 4239;
    return 4;
}

int cpsid(void* buf) {
    *(int32*)(buf + 0) = 12431;
    return 4;
}

int cpsie_mode(Mode mode, void* buf) {
    *(int32*)(buf + 0) = (20623 | (mode << 21));
    return 4;
}

int cpsid_mode(Mode mode, void* buf) {
    *(int32*)(buf + 0) = (28815 | (mode << 21));
    return 4;
}

int ldc(condition cond, bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((560 | cond) | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int ldm1(condition cond, bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((528 | cond) | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int ldm2(condition cond, reg rn, void* buf) {
    *(int32*)(buf + 0) = ((656 | cond) | (rn << 10));
    return 4;
}

int ldm3(condition cond, bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((17040 | cond) | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int ldr(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((544 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrb(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((672 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrbt(condition cond, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((1824 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    return 4;
}

int ldrd(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((2883584 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrex(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int ldrh(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((3408384 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrsb(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((2884096 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrsh(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((3932672 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int ldrt(condition cond, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((1568 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    return 4;
}

int mcr(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((131184 | cond) | (rd << 13));
    return 4;
}

int mcrr(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((560 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int mla(condition cond, bool s, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((150995968 | cond) | (s ? 2048 : 0)) | (rn << 16)) | (rd << 12));
    return 4;
}

int mov(condition cond, bool i, bool s, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((1408 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
    return 4;
}

int mrc(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((131440 | cond) | (rd << 13));
    return 4;
}

int mrrc(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((2608 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int mrs(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((61568 | cond) | (rd << 16));
    return 4;
}

int mul(condition cond, bool s, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((150994944 | cond) | (s ? 2048 : 0)) | (rd << 12));
    return 4;
}

int mvn(condition cond, bool i, bool s, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((1920 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
    return 4;
}

int msr_imm(condition cond, void* buf) {
    *(int32*)(buf + 0) = (62656 | cond);
    return 4;
}

int msr_reg(condition cond, void* buf) {
    *(int32*)(buf + 0) = (62592 | cond);
    return 4;
}

int pkhbt(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int pkhtb(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int pld(bool i, reg rn, void* buf) {
    *(int32*)(buf + 0) = ((492975 | (i ? 64 : 0)) | (rn << 11));
    return 4;
}

int qadd(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qaddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qdadd(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qdsub(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qsub(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qsub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qsub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int qsubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int rev(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((217120096 | cond) | (rd << 16));
    return 4;
}

int rev16(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((233897312 | cond) | (rd << 16));
    return 4;
}

int revsh(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((233897824 | cond) | (rd << 16));
    return 4;
}

int rfe(bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = ((1311263 | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int sadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int saddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sel(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int setendbe(void* buf) {
    *(int32*)(buf + 0) = 4227215;
    return 4;
}

int setendle(void* buf) {
    *(int32*)(buf + 0) = 32911;
    return 4;
}

int shadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int shadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int shaddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int shsub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int shsub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int shsubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int smlabb(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlabt(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlatb(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlatt(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlad(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlal(condition cond, bool s, void* buf) {
    *(int32*)(buf + 0) = ((150996736 | cond) | (s ? 2048 : 0));
    return 4;
}

int smlalbb(condition cond, void* buf) {
    *(int32*)(buf + 0) = (16777856 | cond);
    return 4;
}

int smlalbt(condition cond, void* buf) {
    *(int32*)(buf + 0) = (83886720 | cond);
    return 4;
}

int smlaltb(condition cond, void* buf) {
    *(int32*)(buf + 0) = (50332288 | cond);
    return 4;
}

int smlaltt(condition cond, void* buf) {
    *(int32*)(buf + 0) = (117441152 | cond);
    return 4;
}

int smlald(condition cond, void* buf) {
    *(int32*)(buf + 0) = (67109600 | cond);
    return 4;
}

int smlawb(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlawt(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlsd(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smlsld(condition cond, void* buf) {
    *(int32*)(buf + 0) = (100664032 | cond);
    return 4;
}

int smmla(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smmls(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int smmul(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((135203552 | cond) | (rd << 12));
    return 4;
}

int smuad(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((68092128 | cond) | (rd << 12));
    return 4;
}

int smulbb(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((16778880 | cond) | (rd << 12));
    return 4;
}

int smulbt(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((83887744 | cond) | (rd << 12));
    return 4;
}

int smultb(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((50333312 | cond) | (rd << 12));
    return 4;
}

int smultt(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((117442176 | cond) | (rd << 12));
    return 4;
}

int smull(condition cond, bool s, void* buf) {
    *(int32*)(buf + 0) = ((301991424 | cond) | (s ? 4096 : 0));
    return 4;
}

int smulwb(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((83887232 | cond) | (rd << 12));
    return 4;
}

int smulwt(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((117441664 | cond) | (rd << 12));
    return 4;
}

int smusd(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((101646560 | cond) | (rd << 12));
    return 4;
}

int srs(bool write, Mode mode, void* buf) {
    *(int32*)(buf + 0) = ((2632863 | (write ? 256 : 0)) | (mode << 26));
    return 4;
}

int ssat(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((133728 | cond) | (rd << 12));
    return 4;
}

int ssat16(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((13567328 | cond) | (rd << 12));
    return 4;
}

int ssub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int ssub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int ssubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int stc(condition cond, bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((48 | cond) | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int stm1(condition cond, bool write, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((16 | cond) | (write ? 256 : 0)) | (rn << 10));
    return 4;
}

int stm2(condition cond, reg rn, void* buf) {
    *(int32*)(buf + 0) = ((144 | cond) | (rn << 10));
    return 4;
}

int str(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((32 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int strb(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((160 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int strbt(condition cond, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((800 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    return 4;
}

int strd(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((3932160 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int strex(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
    return 4;
}

int strh(condition cond, bool write, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((((3407872 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
    return 4;
}

int strt(condition cond, bool i, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((((544 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
    return 4;
}

int swi(condition cond, void* buf) {
    *(int32*)(buf + 0) = (240 | cond);
    return 4;
}

int swp(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int swpb(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sxtab(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58721632 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sxtab16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58720608 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sxtah(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58723680 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int sxtb(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58783072 | cond) | (rd << 16));
    return 4;
}

int sxtb16(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58782048 | cond) | (rd << 16));
    return 4;
}

int sxth(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58785120 | cond) | (rd << 16));
    return 4;
}

int teq(condition cond, bool i, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((3200 | cond) | (i ? 64 : 0)) | (rn << 12));
    return 4;
}

int tst(condition cond, bool i, reg rn, void* buf) {
    *(int32*)(buf + 0) = (((2176 | cond) | (i ? 64 : 0)) | (rn << 12));
    return 4;
}

int uadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uaddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhaddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhsub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhsub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uhsubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int umaal(condition cond, void* buf) {
    *(int32*)(buf + 0) = (150995456 | cond);
    return 4;
}

int umlal(condition cond, bool s, void* buf) {
    *(int32*)(buf + 0) = ((150996224 | cond) | (s ? 2048 : 0));
    return 4;
}

int umull(condition cond, bool s, void* buf) {
    *(int32*)(buf + 0) = ((150995200 | cond) | (s ? 2048 : 0));
    return 4;
}

int uqadd16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uqadd8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uqaddsubx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uqsub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uqsub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uqsubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int usad8(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((135201248 | cond) | (rd << 12));
    return 4;
}

int usada8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
    return 4;
}

int usat(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((67424 | cond) | (rd << 11));
    return 4;
}

int usat16(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((13567840 | cond) | (rd << 12));
    return 4;
}

int usub16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int usub8(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int usubaddx(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uxtab(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58722144 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uxtab16(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58721120 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uxtah(condition cond, reg rn, reg rd, void* buf) {
    *(int32*)(buf + 0) = (((58724192 | cond) | (rn << 12)) | (rd << 16));
    return 4;
}

int uxtb(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58783584 | cond) | (rd << 16));
    return 4;
}

int uxtb16(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58782560 | cond) | (rd << 16));
    return 4;
}

int uxth(condition cond, reg rd, void* buf) {
    *(int32*)(buf + 0) = ((58785632 | cond) | (rd << 16));
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
