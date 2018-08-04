// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 

inline uint16_t asm_swap16(uint16_t value) 
{
    return (value << 8) | (value >> 8);
}

inline uint32_t asm_swap32(uint32_t value)
{
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
    return (value << 16) | (value >> 16);
}

inline uint64_t asm_swap64(uint64_t value)
{
    value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
    value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
    return (value << 32) | (value >> 32);
}

#define Reg uint8_t
#define Reg_R0 0
#define Reg_R1 1
#define Reg_R2 2
#define Reg_R3 3
#define Reg_R4 4
#define Reg_R5 5
#define Reg_R6 6
#define Reg_R7 7
#define Reg_R8 8
#define Reg_R9 9
#define Reg_R10 10
#define Reg_R11 11
#define Reg_R12 12
#define Reg_R13 13
#define Reg_R14 14
#define Reg_R15 15
#define Reg_A1 0
#define Reg_A2 1
#define Reg_A3 2
#define Reg_A4 3
#define Reg_V1 4
#define Reg_V2 5
#define Reg_V3 6
#define Reg_V4 7
#define Reg_V5 8
#define Reg_V6 9
#define Reg_V7 10
#define Reg_V8 11
#define Reg_IP 12
#define Reg_SP 13
#define Reg_LR 14
#define Reg_PC 15
#define Reg_WR 7
#define Reg_SB 9
#define Reg_SL 10
#define Reg_FP 11
///
/// A list of ARM registers, where each register corresponds to a single bit.
typedef enum {
    ///
    /// Register #1.
    RLR0 = 0,
    ///
    /// Register #2.
    RLR1 = 1,
    ///
    /// Register #3.
    RLR2 = 2,
    ///
    /// Register #4.
    RLR3 = 3,
    ///
    /// Register #5.
    RLR4 = 4,
    ///
    /// Register #6.
    RLR5 = 5,
    ///
    /// Register #7.
    RLR6 = 6,
    ///
    /// Register #8.
    RLR7 = 7,
    ///
    /// Register #9.
    RLR8 = 8,
    ///
    /// Register #10.
    RLR9 = 9,
    ///
    /// Register #11.
    RLR10 = 10,
    ///
    /// Register #12.
    RLR11 = 11,
    ///
    /// Register #13.
    RLR12 = 12,
    ///
    /// Register #14.
    RLR13 = 13,
    ///
    /// Register #15.
    RLR14 = 14,
    ///
    /// Register #16.
    RLR15 = 15,
    ///
    /// Register A1.
    RLA1 = 0,
    ///
    /// Register A2.
    RLA2 = 1,
    ///
    /// Register A3.
    RLA3 = 2,
    ///
    /// Register A4.
    RLA4 = 3,
    ///
    /// Register V1.
    RLV1 = 4,
    ///
    /// Register V2.
    RLV2 = 5,
    ///
    /// Register V3.
    RLV3 = 6,
    ///
    /// Register V4.
    RLV4 = 7,
    ///
    /// Register V5.
    RLV5 = 8,
    ///
    /// Register V6.
    RLV6 = 9,
    ///
    /// Register V7.
    RLV7 = 10,
    ///
    /// Register V8.
    RLV8 = 11,
    ///
    /// Register IP.
    RLIP = 12,
    ///
    /// Register SP.
    RLSP = 13,
    ///
    /// Register LR.
    RLLR = 14,
    ///
    /// Register PC.
    RLPC = 15,
    ///
    /// Register WR.
    RLWR = 7,
    ///
    /// Register SB.
    RLSB = 9,
    ///
    /// Register SL.
    RLSL = 10,
    ///
    /// Register FP.
    RLFP = 11,
} RegList;

#define Coprocessor uint8_t
#define Coprocessor_CP0 0
#define Coprocessor_CP1 1
#define Coprocessor_CP2 2
#define Coprocessor_CP3 3
#define Coprocessor_CP4 4
#define Coprocessor_CP5 5
#define Coprocessor_CP6 6
#define Coprocessor_CP7 7
#define Coprocessor_CP8 8
#define Coprocessor_CP9 9
#define Coprocessor_CP10 10
#define Coprocessor_CP11 11
#define Coprocessor_CP12 12
#define Coprocessor_CP13 13
#define Coprocessor_CP14 14
#define Coprocessor_CP15 15
///
/// Condition for an ARM instruction to be executed.
typedef enum {
    ///
    /// Equal.
    Equal = 0,
    ///
    /// Not equal.
    NotEqual = 1,
    ///
    /// Unsigned higher or same.
    UnsignedHigherOrEqual = 2,
    ///
    /// Unsigned lower.
    UnsignedLower = 3,
    ///
    /// Minus / negative.
    Negative = 4,
    ///
    /// Plus / positive or zero.
    PositiveOrZero = 5,
    ///
    /// Overflow.
    Overflow = 6,
    ///
    /// No overflow.
    NoOverflow = 7,
    ///
    /// Unsigned higher.
    UnsignedHigher = 8,
    ///
    /// Unsigned lower or same.
    UnsignedLowerOrEqual = 9,
    ///
    /// Signed greater than or equal.
    SignedGreaterOrEqual = 10,
    ///
    /// Signed less than.
    SignedLower = 11,
    ///
    /// Signed greater than.
    SignedGreater = 12,
    ///
    /// Signed less than or equal.
    SignedLowerOrEqual = 13,
    ///
    /// Always (unconditional).
    Always = 14,
    ///
    /// Unpredictable (ARMv4 or lower).
    Unpredictable = 15,
    ///
    /// Carry set.
    CarrySet = 2,
    ///
    /// Carry clear.
    CarryClear = 3,
} Condition;

///
/// Processor mode.
typedef enum {
    ///
    /// User mode.
    USRMode = 16,
    ///
    /// FIQ (high-speed data transfer) mode.
    FIQMode = 17,
    ///
    /// IRQ (general-purpose interrupt handling) mode.
    IRQMode = 18,
    ///
    /// Supervisor mode.
    SVCMode = 19,
    ///
    /// Abort mode.
    ABTMode = 23,
    ///
    /// Undefined mode.
    UNDMode = 27,
    ///
    /// System (privileged) mode.
    SYSMode = 31,
} Mode;

///
/// Kind of a shift.
typedef enum {
    ///
    /// Logical shift left.
    LogicalShiftLeft = 0,
    ///
    /// Logical shift right.
    LogicalShiftRight = 1,
    ///
    /// Arithmetic shift right.
    ArithShiftRight = 2,
    ///
    /// Rotate right.
    RotateRight = 3,
    ///
    /// Shifted right by one bit.
    RRX = 3,
} Shift;

///
/// Kind of a right rotation.
typedef enum {
    ///
    /// Do not rotate.
    NoRotation = 0,
    ///
    /// Rotate 8 bits to the right.
    RotateRight8 = 1,
    ///
    /// Rotate 16 bits to the right.
    RotateRight16 = 2,
    ///
    /// Rotate 24 bits to the right.
    RotateRight24 = 3,
} Rotation;

///
/// Field mask bits.
typedef enum {
    ///
    /// Control field mask bit.
    CFieldMask = 1,
    ///
    /// Extension field mask bit.
    XFieldMask = 2,
    ///
    /// Status field mask bit.
    SFieldMask = 4,
    ///
    /// Flags field mask bit.
    FFieldMask = 8,
} FieldMask;

///
/// Interrupt flags.
typedef enum {
    ///
    /// FIQ interrupt bit.
    InterruptFIQ = 1,
    ///
    /// IRQ interrupt bit.
    InterruptIRQ = 2,
    ///
    /// Imprecise data abort bit.
    ImpreciseDataAbort = 4,
} InterruptFlags;

///
/// Addressing type.
typedef enum {
    ///
    /// Post-indexed addressing.
    PostIndexedIndexing = 0,
    ///
    /// Pre-indexed addressing (or offset addressing if `write` is false).
    PreIndexedIndexing = 1,
    ///
    /// Offset addressing (or pre-indexed addressing if `write` is true).
    OffsetIndexing = 1,
} Addressing;

///
/// Offset adding or subtracting mode.
typedef enum {
    ///
    /// Subtract offset from the base.
    SubtractOffset = 0,
    ///
    /// Add offset to the base.
    AddOffset = 1,
} OffsetMode;


void CALLCONV adc(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV add(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV eor(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV orr(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV rsb(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV rsc(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sbc(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV bkpt(void** buf, uint16_t immed) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)));
#else
    *(uint32_t*)(*buf) = ((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0));
#endif
    *(byte*)buf += 4;
}

void CALLCONV b(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((167772160 | cond));
#else
    *(uint32_t*)(*buf) = (167772160 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV bic(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV blx(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((19922736 | cond));
#else
    *(uint32_t*)(*buf) = (19922736 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV bx(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((19922704 | cond));
#else
    *(uint32_t*)(*buf) = (19922704 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV bxj(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((19922720 | cond));
#else
    *(uint32_t*)(*buf) = (19922720 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV blxun(void** buf) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(4194304000);
#else
    *(uint32_t*)(*buf) = 4194304000;
#endif
    *(byte*)buf += 4;
}

void CALLCONV clz(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((24055568 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((24055568 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cmn(void** buf, Condition cond, Reg rn) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((24117248 | cond) | (rn << 16)));
#else
    *(uint32_t*)(*buf) = ((24117248 | cond) | (rn << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cmp(void** buf, Condition cond, Reg rn) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((22020096 | cond) | (rn << 16)));
#else
    *(uint32_t*)(*buf) = ((22020096 | cond) | (rn << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cpy(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((27262976 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((27262976 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cps(void** buf, Mode mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((4043440128 | (mode << 0)));
#else
    *(uint32_t*)(*buf) = (4043440128 | (mode << 0));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cpsie(void** buf, InterruptFlags iflags) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((4043833344 | (iflags << 6)));
#else
    *(uint32_t*)(*buf) = (4043833344 | (iflags << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cpsid(void** buf, InterruptFlags iflags) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((4044095488 | (iflags << 6)));
#else
    *(uint32_t*)(*buf) = (4044095488 | (iflags << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cpsie_mode(void** buf, InterruptFlags iflags, Mode mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((4043964416 | (iflags << 6)) | (mode << 0)));
#else
    *(uint32_t*)(*buf) = ((4043964416 | (iflags << 6)) | (mode << 0));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cpsid_mode(void** buf, InterruptFlags iflags, Mode mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((4044226560 | (iflags << 6)) | (mode << 0)));
#else
    *(uint32_t*)(*buf) = ((4044226560 | (iflags << 6)) | (mode << 0));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldc(void** buf, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldm(void** buf, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool copy_spsr) {
    assert(((copy_spsr == 1) ^ (write == (registers & 32768))));
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)));
#else
    *(uint32_t*)(*buf) = ((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldr(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrb(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrbt(void** buf, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
#else
    *(uint32_t*)(*buf) = ((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrd(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrex(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((26218399 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((26218399 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrh(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrsb(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrsh(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ldrt(void** buf, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
#else
    *(uint32_t*)(*buf) = ((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
#endif
    *(byte*)buf += 4;
}

void CALLCONV cdp(void** buf, Condition cond, Coprocessor cpnum) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((234881024 | cond) | (cpnum << 8)));
#else
    *(uint32_t*)(*buf) = ((234881024 | cond) | (cpnum << 8));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mcr(void** buf, Condition cond, Reg rd, Coprocessor cpnum) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((234881040 | cond) | (rd << 12)) | (cpnum << 8)));
#else
    *(uint32_t*)(*buf) = (((234881040 | cond) | (rd << 12)) | (cpnum << 8));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mrc(void** buf, Condition cond, Reg rd, Coprocessor cpnum) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((235929616 | cond) | (rd << 12)) | (cpnum << 8)));
#else
    *(uint32_t*)(*buf) = (((235929616 | cond) | (rd << 12)) | (cpnum << 8));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mcrr(void** buf, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)));
#else
    *(uint32_t*)(*buf) = ((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mla(void** buf, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mov(void** buf, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = ((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mrrc(void** buf, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)));
#else
    *(uint32_t*)(*buf) = ((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mrs(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((17760256 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((17760256 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mul(void** buf, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = ((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mvn(void** buf, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = ((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV msr_imm(void** buf, Condition cond, FieldMask fieldmask) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((52490240 | cond) | (fieldmask << 16)));
#else
    *(uint32_t*)(*buf) = ((52490240 | cond) | (fieldmask << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV msr_reg(void** buf, Condition cond, FieldMask fieldmask) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((18935808 | cond) | (fieldmask << 16)));
#else
    *(uint32_t*)(*buf) = ((18935808 | cond) | (fieldmask << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV pkhbt(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((109051920 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((109051920 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV pkhtb(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((109051984 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((109051984 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV pld(void** buf, Reg rn, OffsetMode offset_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((4115722240 | (rn << 16)) | (offset_mode << 23)));
#else
    *(uint32_t*)(*buf) = ((4115722240 | (rn << 16)) | (offset_mode << 23));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qadd(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777296 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((16777296 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764304 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764304 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764432 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764432 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764336 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764336 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qdadd(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((20971600 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((20971600 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qdsub(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((23068752 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((23068752 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qsub(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((18874448 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((18874448 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qsub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764400 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764400 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qsub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764528 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764528 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV qsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((102764368 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((102764368 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV rev(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((113184560 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((113184560 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV rev16(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((113184688 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((113184688 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV revsh(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((117378992 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((117378992 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV rfe(void** buf, bool write, Reg rn, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715728 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715728 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715856 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715856 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV saddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715760 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715760 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sel(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((109055920 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((109055920 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV setendbe(void** buf) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(4043375104);
#else
    *(uint32_t*)(*buf) = 4043375104;
#endif
    *(byte*)buf += 4;
}

void CALLCONV setendle(void** buf) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(4043374592);
#else
    *(uint32_t*)(*buf) = 4043374592;
#endif
    *(byte*)buf += 4;
}

void CALLCONV shadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103812880 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103812880 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV shadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103813008 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103813008 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV shaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103812912 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103812912 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV shsub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103812976 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103812976 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV shsub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103813104 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103813104 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV shsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((103812944 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((103812944 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlabb(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777344 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((16777344 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlabt(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777376 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((16777376 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlatb(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777408 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((16777408 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlatt(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777440 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((16777440 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlad(void** buf, Condition cond, bool exchange, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlal(void** buf, Condition cond, bool update_cprs, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlalbb(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((20971648 | cond));
#else
    *(uint32_t*)(*buf) = (20971648 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlalbt(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((20971680 | cond));
#else
    *(uint32_t*)(*buf) = (20971680 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlaltb(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((20971712 | cond));
#else
    *(uint32_t*)(*buf) = (20971712 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlaltt(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((20971744 | cond));
#else
    *(uint32_t*)(*buf) = (20971744 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlald(void** buf, Condition cond, bool exchange) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((121634832 | cond) | (exchange << 5)));
#else
    *(uint32_t*)(*buf) = ((121634832 | cond) | (exchange << 5));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlawb(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((18874496 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((18874496 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlawt(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((18874560 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((18874560 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlsd(void** buf, Condition cond, bool exchange, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smlsld(void** buf, Condition cond, bool exchange) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((121634896 | cond) | (exchange << 5)));
#else
    *(uint32_t*)(*buf) = ((121634896 | cond) | (exchange << 5));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smmla(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((122683408 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((122683408 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smmls(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((122683600 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((122683600 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smmul(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((122744848 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((122744848 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smuad(void** buf, Condition cond, bool exchange, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((117501968 | cond) | (exchange << 5)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((117501968 | cond) | (exchange << 5)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smulbb(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((23068800 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((23068800 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smulbt(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((23068832 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((23068832 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smultb(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((23068864 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((23068864 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smultt(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((23068896 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((23068896 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smull(void** buf, Condition cond, bool update_cprs, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smulwb(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((18874528 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((18874528 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smulwt(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((18874592 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((18874592 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV smusd(void** buf, Condition cond, bool exchange, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((117502032 | cond) | (exchange << 5)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((117502032 | cond) | (exchange << 5)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV srs(void** buf, bool write, Mode mode, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ssat(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((105906192 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((105906192 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ssat16(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((111152944 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((111152944 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ssub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715824 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715824 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ssub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715952 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715952 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV ssubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((101715792 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((101715792 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV stc(void** buf, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV stm(void** buf, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool user_mode) {
    assert(((user_mode == 0) || (write == 0)));
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10)));
#else
    *(uint32_t*)(*buf) = ((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV str(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strb(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strbt(void** buf, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
#else
    *(uint32_t*)(*buf) = ((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strd(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strex(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((25169808 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((25169808 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strh(void** buf, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
#else
    *(uint32_t*)(*buf) = ((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
#endif
    *(byte*)buf += 4;
}

void CALLCONV strt(void** buf, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
#else
    *(uint32_t*)(*buf) = ((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
#endif
    *(byte*)buf += 4;
}

void CALLCONV swi(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((251658240 | cond));
#else
    *(uint32_t*)(*buf) = (251658240 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV swp(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((16777360 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((16777360 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV swpb(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((20971664 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((20971664 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxtab(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxtab16(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxtah(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxtb(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((112132208 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((112132208 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxtb16(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((110035056 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((110035056 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV sxth(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((113180784 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((113180784 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV teq(void** buf, Condition cond, Reg rn) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((19922944 | cond) | (rn << 16)));
#else
    *(uint32_t*)(*buf) = ((19922944 | cond) | (rn << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV tst(void** buf, Condition cond, Reg rn) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((17825792 | cond) | (rn << 16)));
#else
    *(uint32_t*)(*buf) = ((17825792 | cond) | (rn << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910032 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910032 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910160 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910160 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910064 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910064 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007184 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007184 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007312 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007312 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007216 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007216 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhsub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007280 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007280 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhsub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007408 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007408 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uhsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((108007248 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((108007248 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV umaal(void** buf, Condition cond) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((4194448 | cond));
#else
    *(uint32_t*)(*buf) = (4194448 | cond);
#endif
    *(byte*)buf += 4;
}

void CALLCONV umlal(void** buf, Condition cond, bool update_cprs, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV umull(void** buf, Condition cond, bool update_cprs, bool update_condition) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20)));
#else
    *(uint32_t*)(*buf) = (((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqadd16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958608 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958608 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqadd8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958736 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958736 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqaddsubx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958640 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958640 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqsub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958704 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958704 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqsub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958832 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958832 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uqsubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((106958672 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((106958672 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usad8(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((125890576 | cond) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = ((125890576 | cond) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usada8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((125829136 | cond) | (rn << 12)) | (rd << 16)));
#else
    *(uint32_t*)(*buf) = (((125829136 | cond) | (rn << 12)) | (rd << 16));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usat(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((115343376 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((115343376 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usat16(void** buf, Condition cond, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((115347248 | cond) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = ((115347248 | cond) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usub16(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910128 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910128 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usub8(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910256 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910256 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV usubaddx(void** buf, Condition cond, Reg rn, Reg rd) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((105910096 | cond) | (rn << 16)) | (rd << 12)));
#else
    *(uint32_t*)(*buf) = (((105910096 | cond) | (rn << 16)) | (rd << 12));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxtab(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxtab16(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxtah(void** buf, Condition cond, Reg rn, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxtb(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((116326512 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((116326512 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxtb16(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((114229360 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((114229360 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

void CALLCONV uxth(void** buf, Condition cond, Reg rd, Rotation rotate) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((117375088 | cond) | (rd << 12)) | (rotate << 10)));
#else
    *(uint32_t*)(*buf) = (((117375088 | cond) | (rd << 12)) | (rotate << 10));
#endif
    *(byte*)buf += 4;
}

