// Automatically generated file.

#include <cassert>
#include <ostream>

namespace arm
{
    namespace
    {
        inline uint16_t swap16(uint16_t value) 
        {
            return (value << 8) | (value >> 8);
        }

        inline uint32_t swap32(uint32_t value)
        {
            value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
            return (value << 16) | (value >> 16);
        }

        inline uint64_t swap64(uint64_t value)
        {
            value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
            value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
            return (value << 32) | (value >> 32);
        }
    }

    using Reg = uint8_t;
    static const Reg r0 = 0;
    static const Reg r1 = 1;
    static const Reg r2 = 2;
    static const Reg r3 = 3;
    static const Reg r4 = 4;
    static const Reg r5 = 5;
    static const Reg r6 = 6;
    static const Reg r7 = 7;
    static const Reg r8 = 8;
    static const Reg r9 = 9;
    static const Reg r10 = 10;
    static const Reg r11 = 11;
    static const Reg r12 = 12;
    static const Reg r13 = 13;
    static const Reg r14 = 14;
    static const Reg r15 = 15;
    static const Reg a1 = 0;
    static const Reg a2 = 1;
    static const Reg a3 = 2;
    static const Reg a4 = 3;
    static const Reg v1 = 4;
    static const Reg v2 = 5;
    static const Reg v3 = 6;
    static const Reg v4 = 7;
    static const Reg v5 = 8;
    static const Reg v6 = 9;
    static const Reg v7 = 10;
    static const Reg v8 = 11;
    static const Reg ip = 12;
    static const Reg sp = 13;
    static const Reg lr = 14;
    static const Reg pc = 15;
    static const Reg wr = 7;
    static const Reg sb = 9;
    static const Reg sl = 10;
    static const Reg fp = 11;
    ///
    /// A list of ARM registers, where each register corresponds to a single bit.
    enum class RegList {
        ///
        /// Register #1.
        R0 = 0,
        ///
        /// Register #2.
        R1 = 1,
        ///
        /// Register #3.
        R2 = 2,
        ///
        /// Register #4.
        R3 = 3,
        ///
        /// Register #5.
        R4 = 4,
        ///
        /// Register #6.
        R5 = 5,
        ///
        /// Register #7.
        R6 = 6,
        ///
        /// Register #8.
        R7 = 7,
        ///
        /// Register #9.
        R8 = 8,
        ///
        /// Register #10.
        R9 = 9,
        ///
        /// Register #11.
        R10 = 10,
        ///
        /// Register #12.
        R11 = 11,
        ///
        /// Register #13.
        R12 = 12,
        ///
        /// Register #14.
        R13 = 13,
        ///
        /// Register #15.
        R14 = 14,
        ///
        /// Register #16.
        R15 = 15,
        ///
        /// Register A1.
        A1 = 0,
        ///
        /// Register A2.
        A2 = 1,
        ///
        /// Register A3.
        A3 = 2,
        ///
        /// Register A4.
        A4 = 3,
        ///
        /// Register V1.
        V1 = 4,
        ///
        /// Register V2.
        V2 = 5,
        ///
        /// Register V3.
        V3 = 6,
        ///
        /// Register V4.
        V4 = 7,
        ///
        /// Register V5.
        V5 = 8,
        ///
        /// Register V6.
        V6 = 9,
        ///
        /// Register V7.
        V7 = 10,
        ///
        /// Register V8.
        V8 = 11,
        ///
        /// Register IP.
        IP = 12,
        ///
        /// Register SP.
        SP = 13,
        ///
        /// Register LR.
        LR = 14,
        ///
        /// Register PC.
        PC = 15,
        ///
        /// Register WR.
        WR = 7,
        ///
        /// Register SB.
        SB = 9,
        ///
        /// Register SL.
        SL = 10,
        ///
        /// Register FP.
        FP = 11,
    };

    using Coprocessor = uint8_t;
    static const Coprocessor cp0 = 0;
    static const Coprocessor cp1 = 1;
    static const Coprocessor cp2 = 2;
    static const Coprocessor cp3 = 3;
    static const Coprocessor cp4 = 4;
    static const Coprocessor cp5 = 5;
    static const Coprocessor cp6 = 6;
    static const Coprocessor cp7 = 7;
    static const Coprocessor cp8 = 8;
    static const Coprocessor cp9 = 9;
    static const Coprocessor cp10 = 10;
    static const Coprocessor cp11 = 11;
    static const Coprocessor cp12 = 12;
    static const Coprocessor cp13 = 13;
    static const Coprocessor cp14 = 14;
    static const Coprocessor cp15 = 15;
    ///
    /// Condition for an ARM instruction to be executed.
    enum class Condition {
        ///
        /// Equal.
        EQ = 0,
        ///
        /// Not equal.
        NE = 1,
        ///
        /// Unsigned higher or same.
        HS = 2,
        ///
        /// Unsigned lower.
        LO = 3,
        ///
        /// Minus / negative.
        MI = 4,
        ///
        /// Plus / positive or zero.
        PL = 5,
        ///
        /// Overflow.
        VS = 6,
        ///
        /// No overflow.
        VC = 7,
        ///
        /// Unsigned higher.
        HI = 8,
        ///
        /// Unsigned lower or same.
        LS = 9,
        ///
        /// Signed greater than or equal.
        GE = 10,
        ///
        /// Signed less than.
        LT = 11,
        ///
        /// Signed greater than.
        GT = 12,
        ///
        /// Signed less than or equal.
        LE = 13,
        ///
        /// Always (unconditional).
        AL = 14,
        ///
        /// Unpredictable (ARMv4 or lower).
        UN = 15,
        ///
        /// Carry set.
        CS = 2,
        ///
        /// Carry clear.
        CC = 3,
    };

    ///
    /// Processor mode.
    enum class Mode {
        ///
        /// User mode.
        USR = 16,
        ///
        /// FIQ (high-speed data transfer) mode.
        FIQ = 17,
        ///
        /// IRQ (general-purpose interrupt handling) mode.
        IRQ = 18,
        ///
        /// Supervisor mode.
        SVC = 19,
        ///
        /// Abort mode.
        ABT = 23,
        ///
        /// Undefined mode.
        UND = 27,
        ///
        /// System (privileged) mode.
        SYS = 31,
    };

    ///
    /// Kind of a shift.
    enum class Shift {
        ///
        /// Logical shift left.
        LSL = 0,
        ///
        /// Logical shift right.
        LSR = 1,
        ///
        /// Arithmetic shift right.
        ASR = 2,
        ///
        /// Rotate right.
        ROR = 3,
        ///
        /// Shifted right by one bit.
        RRX = 3,
    };

    ///
    /// Kind of a right rotation.
    enum class Rotation {
        ///
        /// Do not rotate.
        NOP = 0,
        ///
        /// Rotate 8 bits to the right.
        ROR8 = 1,
        ///
        /// Rotate 16 bits to the right.
        ROR16 = 2,
        ///
        /// Rotate 24 bits to the right.
        ROR24 = 3,
    };

    ///
    /// Field mask bits.
    enum class FieldMask {
        ///
        /// Control field mask bit.
        C = 1,
        ///
        /// Extension field mask bit.
        X = 2,
        ///
        /// Status field mask bit.
        S = 4,
        ///
        /// Flags field mask bit.
        F = 8,
    };

    ///
    /// Interrupt flags.
    enum class InterruptFlags {
        ///
        /// FIQ interrupt bit.
        F = 1,
        ///
        /// IRQ interrupt bit.
        I = 2,
        ///
        /// Imprecise data abort bit.
        A = 4,
    };

    ///
    /// Addressing type.
    enum class Addressing {
        ///
        /// Post-indexed addressing.
        PostIndexed = 0,
        ///
        /// Pre-indexed addressing (or offset addressing if `write` is false).
        PreIndexed = 1,
        ///
        /// Offset addressing (or pre-indexed addressing if `write` is true).
        Offset = 1,
    };

    ///
    /// Offset adding or subtracting mode.
    enum class OffsetMode {
        ///
        /// Subtract offset from the base.
        Subtract = 0,
        ///
        /// Add offset to the base.
        Add = 1,
    };


    std::ostream& adc(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& eor(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& orr(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& rsb(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& rsc(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& sbc(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& bkpt(std::ostream& os, uint16_t immed) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0))));
        #else
        os << std::bitset<32>(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)));
        #endif

        return os;
    }

    std::ostream& b(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((167772160 | cond)));
        #else
        os << std::bitset<32>((167772160 | cond));
        #endif

        return os;
    }

    std::ostream& bic(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& blx(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((19922736 | cond)));
        #else
        os << std::bitset<32>((19922736 | cond));
        #endif

        return os;
    }

    std::ostream& bx(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((19922704 | cond)));
        #else
        os << std::bitset<32>((19922704 | cond));
        #endif

        return os;
    }

    std::ostream& bxj(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((19922720 | cond)));
        #else
        os << std::bitset<32>((19922720 | cond));
        #endif

        return os;
    }

    std::ostream& blxun(std::ostream& os) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(4194304000));
        #else
        os << std::bitset<32>(4194304000);
        #endif

        return os;
    }

    std::ostream& clz(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((24055568 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((24055568 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& cmn(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((24117248 | cond) | (rn << 16))));
        #else
        os << std::bitset<32>(((24117248 | cond) | (rn << 16)));
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((22020096 | cond) | (rn << 16))));
        #else
        os << std::bitset<32>(((22020096 | cond) | (rn << 16)));
        #endif

        return os;
    }

    std::ostream& cpy(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((27262976 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((27262976 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& cps(std::ostream& os, Mode mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((4043440128 | (mode << 0))));
        #else
        os << std::bitset<32>((4043440128 | (mode << 0)));
        #endif

        return os;
    }

    std::ostream& cpsie(std::ostream& os, InterruptFlags iflags) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((4043833344 | (iflags << 6))));
        #else
        os << std::bitset<32>((4043833344 | (iflags << 6)));
        #endif

        return os;
    }

    std::ostream& cpsid(std::ostream& os, InterruptFlags iflags) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((4044095488 | (iflags << 6))));
        #else
        os << std::bitset<32>((4044095488 | (iflags << 6)));
        #endif

        return os;
    }

    std::ostream& cpsie_mode(std::ostream& os, InterruptFlags iflags, Mode mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((4043964416 | (iflags << 6)) | (mode << 0))));
        #else
        os << std::bitset<32>(((4043964416 | (iflags << 6)) | (mode << 0)));
        #endif

        return os;
    }

    std::ostream& cpsid_mode(std::ostream& os, InterruptFlags iflags, Mode mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((4044226560 | (iflags << 6)) | (mode << 0))));
        #else
        os << std::bitset<32>(((4044226560 | (iflags << 6)) | (mode << 0)));
        #endif

        return os;
    }

    std::ostream& ldc(std::ostream& os, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldm(std::ostream& os, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool copy_spsr) {
        assert(((copy_spsr == 1) ^ (write == (registers & 32768))));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10))));
        #else
        os << std::bitset<32>(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)));
        #endif

        return os;
    }

    std::ostream& ldr(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrbt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23))));
        #else
        os << std::bitset<32>(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
        #endif

        return os;
    }

    std::ostream& ldrd(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrex(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((26218399 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((26218399 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& ldrh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrsb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrsh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ldrt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23))));
        #else
        os << std::bitset<32>(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
        #endif

        return os;
    }

    std::ostream& cdp(std::ostream& os, Condition cond, Coprocessor cpnum) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((234881024 | cond) | (cpnum << 8))));
        #else
        os << std::bitset<32>(((234881024 | cond) | (cpnum << 8)));
        #endif

        return os;
    }

    std::ostream& mcr(std::ostream& os, Condition cond, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((234881040 | cond) | (rd << 12)) | (cpnum << 8))));
        #else
        os << std::bitset<32>((((234881040 | cond) | (rd << 12)) | (cpnum << 8)));
        #endif

        return os;
    }

    std::ostream& mrc(std::ostream& os, Condition cond, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((235929616 | cond) | (rd << 12)) | (cpnum << 8))));
        #else
        os << std::bitset<32>((((235929616 | cond) | (rd << 12)) | (cpnum << 8)));
        #endif

        return os;
    }

    std::ostream& mcrr(std::ostream& os, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8))));
        #else
        os << std::bitset<32>(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)));
        #endif

        return os;
    }

    std::ostream& mla(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& mov(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& mrrc(std::ostream& os, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8))));
        #else
        os << std::bitset<32>(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)));
        #endif

        return os;
    }

    std::ostream& mrs(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((17760256 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((17760256 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& mul(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20))));
        #else
        os << std::bitset<32>(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& mvn(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20))));
        #else
        os << std::bitset<32>(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& msr_imm(std::ostream& os, Condition cond, FieldMask fieldmask) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((52490240 | cond) | (fieldmask << 16))));
        #else
        os << std::bitset<32>(((52490240 | cond) | (fieldmask << 16)));
        #endif

        return os;
    }

    std::ostream& msr_reg(std::ostream& os, Condition cond, FieldMask fieldmask) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((18935808 | cond) | (fieldmask << 16))));
        #else
        os << std::bitset<32>(((18935808 | cond) | (fieldmask << 16)));
        #endif

        return os;
    }

    std::ostream& pkhbt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((109051920 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((109051920 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& pkhtb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((109051984 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((109051984 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& pld(std::ostream& os, Reg rn, OffsetMode offset_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((4115722240 | (rn << 16)) | (offset_mode << 23))));
        #else
        os << std::bitset<32>(((4115722240 | (rn << 16)) | (offset_mode << 23)));
        #endif

        return os;
    }

    std::ostream& qadd(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777296 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((16777296 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764304 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764304 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764432 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764432 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764336 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764336 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qdadd(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((20971600 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((20971600 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qdsub(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((23068752 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((23068752 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qsub(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((18874448 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((18874448 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764400 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764400 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764528 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764528 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& qsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((102764368 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((102764368 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& rev(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((113184560 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((113184560 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& rev16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((113184688 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((113184688 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& revsh(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((117378992 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((117378992 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& rfe(std::ostream& os, bool write, Reg rn, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& sadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715728 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715728 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& sadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715856 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715856 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& saddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715760 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715760 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& sel(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((109055920 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((109055920 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& setendbe(std::ostream& os) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(4043375104));
        #else
        os << std::bitset<32>(4043375104);
        #endif

        return os;
    }

    std::ostream& setendle(std::ostream& os) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(4043374592));
        #else
        os << std::bitset<32>(4043374592);
        #endif

        return os;
    }

    std::ostream& shadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103812880 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103812880 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& shadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103813008 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103813008 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& shaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103812912 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103812912 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& shsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103812976 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103812976 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& shsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103813104 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103813104 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& shsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((103812944 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((103812944 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& smlabb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777344 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((16777344 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlabt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777376 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((16777376 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlatb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777408 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((16777408 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlatt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777440 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((16777440 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlad(std::ostream& os, Condition cond, bool exchange, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlal(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& smlalbb(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((20971648 | cond)));
        #else
        os << std::bitset<32>((20971648 | cond));
        #endif

        return os;
    }

    std::ostream& smlalbt(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((20971680 | cond)));
        #else
        os << std::bitset<32>((20971680 | cond));
        #endif

        return os;
    }

    std::ostream& smlaltb(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((20971712 | cond)));
        #else
        os << std::bitset<32>((20971712 | cond));
        #endif

        return os;
    }

    std::ostream& smlaltt(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((20971744 | cond)));
        #else
        os << std::bitset<32>((20971744 | cond));
        #endif

        return os;
    }

    std::ostream& smlald(std::ostream& os, Condition cond, bool exchange) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((121634832 | cond) | (exchange << 5))));
        #else
        os << std::bitset<32>(((121634832 | cond) | (exchange << 5)));
        #endif

        return os;
    }

    std::ostream& smlawb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((18874496 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((18874496 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlawt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((18874560 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((18874560 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlsd(std::ostream& os, Condition cond, bool exchange, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smlsld(std::ostream& os, Condition cond, bool exchange) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((121634896 | cond) | (exchange << 5))));
        #else
        os << std::bitset<32>(((121634896 | cond) | (exchange << 5)));
        #endif

        return os;
    }

    std::ostream& smmla(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((122683408 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((122683408 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smmls(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((122683600 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((122683600 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smmul(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((122744848 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((122744848 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smuad(std::ostream& os, Condition cond, bool exchange, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((117501968 | cond) | (exchange << 5)) | (rd << 16))));
        #else
        os << std::bitset<32>((((117501968 | cond) | (exchange << 5)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smulbb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((23068800 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((23068800 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smulbt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((23068832 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((23068832 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smultb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((23068864 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((23068864 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smultt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((23068896 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((23068896 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smull(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& smulwb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((18874528 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((18874528 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smulwt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((18874592 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((18874592 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& smusd(std::ostream& os, Condition cond, bool exchange, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((117502032 | cond) | (exchange << 5)) | (rd << 16))));
        #else
        os << std::bitset<32>((((117502032 | cond) | (exchange << 5)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& srs(std::ostream& os, bool write, Mode mode, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& ssat(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((105906192 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((105906192 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& ssat16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((111152944 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((111152944 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& ssub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715824 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715824 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& ssub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715952 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715952 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& ssubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((101715792 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((101715792 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& stc(std::ostream& os, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& stm(std::ostream& os, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool user_mode) {
        assert(((user_mode == 0) || (write == 0)));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10))));
        #else
        os << std::bitset<32>(((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10)));
        #endif

        return os;
    }

    std::ostream& str(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& strb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& strbt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23))));
        #else
        os << std::bitset<32>(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
        #endif

        return os;
    }

    std::ostream& strd(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& strex(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((25169808 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((25169808 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& strh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11))));
        #else
        os << std::bitset<32>(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)));
        #endif

        return os;
    }

    std::ostream& strt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23))));
        #else
        os << std::bitset<32>(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)));
        #endif

        return os;
    }

    std::ostream& swi(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((251658240 | cond)));
        #else
        os << std::bitset<32>((251658240 | cond));
        #endif

        return os;
    }

    std::ostream& swp(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((16777360 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((16777360 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& swpb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((20971664 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((20971664 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& sxtab(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& sxtab16(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& sxtah(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& sxtb(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((112132208 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((112132208 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& sxtb16(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((110035056 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((110035056 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& sxth(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((113180784 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((113180784 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& teq(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((19922944 | cond) | (rn << 16))));
        #else
        os << std::bitset<32>(((19922944 | cond) | (rn << 16)));
        #endif

        return os;
    }

    std::ostream& tst(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((17825792 | cond) | (rn << 16))));
        #else
        os << std::bitset<32>(((17825792 | cond) | (rn << 16)));
        #endif

        return os;
    }

    std::ostream& uadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910032 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910032 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910160 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910160 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910064 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910064 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007184 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007184 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007312 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007312 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007216 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007216 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007280 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007280 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007408 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007408 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uhsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((108007248 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((108007248 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& umaal(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((4194448 | cond)));
        #else
        os << std::bitset<32>((4194448 | cond));
        #endif

        return os;
    }

    std::ostream& umlal(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& umull(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20))));
        #else
        os << std::bitset<32>((((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20)));
        #endif

        return os;
    }

    std::ostream& uqadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958608 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958608 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uqadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958736 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958736 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uqaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958640 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958640 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uqsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958704 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958704 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uqsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958832 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958832 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uqsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((106958672 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((106958672 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& usad8(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((125890576 | cond) | (rd << 16))));
        #else
        os << std::bitset<32>(((125890576 | cond) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& usada8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((125829136 | cond) | (rn << 12)) | (rd << 16))));
        #else
        os << std::bitset<32>((((125829136 | cond) | (rn << 12)) | (rd << 16)));
        #endif

        return os;
    }

    std::ostream& usat(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((115343376 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((115343376 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& usat16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((115347248 | cond) | (rd << 12))));
        #else
        os << std::bitset<32>(((115347248 | cond) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& usub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910128 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910128 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& usub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910256 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910256 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& usubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((105910096 | cond) | (rn << 16)) | (rd << 12))));
        #else
        os << std::bitset<32>((((105910096 | cond) | (rn << 16)) | (rd << 12)));
        #endif

        return os;
    }

    std::ostream& uxtab(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& uxtab16(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& uxtah(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& uxtb(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((116326512 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((116326512 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& uxtb16(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((114229360 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((114229360 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

    std::ostream& uxth(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((117375088 | cond) | (rd << 12)) | (rotate << 10))));
        #else
        os << std::bitset<32>((((117375088 | cond) | (rd << 12)) | (rotate << 10)));
        #endif

        return os;
    }

