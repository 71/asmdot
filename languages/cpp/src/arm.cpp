// Automatically generated file.

#include <cassert>
#include <cstdint>
#include <ostream>

namespace arm
{
    namespace
    {
        template<typename T>
        inline uint8_t get_prefix(T& r)
        {
            if (r.value < 8)
                return r.value;
            
            r.value -= 8;
            return 1;
        }

        template<typename T>
        inline void write_binary(std::ostream& os, T value, std::streamsize size)
        {
            os.write(reinterpret_cast<const char*>(&value), size);
        }

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

    ///
    /// An ARM register.
    struct Reg {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg, given its underlying value.
        Reg(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg R0;
        static const Reg R1;
        static const Reg R2;
        static const Reg R3;
        static const Reg R4;
        static const Reg R5;
        static const Reg R6;
        static const Reg R7;
        static const Reg R8;
        static const Reg R9;
        static const Reg R10;
        static const Reg R11;
        static const Reg R12;
        static const Reg R13;
        static const Reg R14;
        static const Reg R15;
        static const Reg A1;
        static const Reg A2;
        static const Reg A3;
        static const Reg A4;
        static const Reg V1;
        static const Reg V2;
        static const Reg V3;
        static const Reg V4;
        static const Reg V5;
        static const Reg V6;
        static const Reg V7;
        static const Reg V8;
        static const Reg IP;
        static const Reg SP;
        static const Reg LR;
        static const Reg PC;
        static const Reg WR;
        static const Reg SB;
        static const Reg SL;
        static const Reg FP;
    };

    const Reg Reg::R0 = 0;
    const Reg Reg::R1 = 1;
    const Reg Reg::R2 = 2;
    const Reg Reg::R3 = 3;
    const Reg Reg::R4 = 4;
    const Reg Reg::R5 = 5;
    const Reg Reg::R6 = 6;
    const Reg Reg::R7 = 7;
    const Reg Reg::R8 = 8;
    const Reg Reg::R9 = 9;
    const Reg Reg::R10 = 10;
    const Reg Reg::R11 = 11;
    const Reg Reg::R12 = 12;
    const Reg Reg::R13 = 13;
    const Reg Reg::R14 = 14;
    const Reg Reg::R15 = 15;
    const Reg Reg::A1 = 0;
    const Reg Reg::A2 = 1;
    const Reg Reg::A3 = 2;
    const Reg Reg::A4 = 3;
    const Reg Reg::V1 = 4;
    const Reg Reg::V2 = 5;
    const Reg Reg::V3 = 6;
    const Reg Reg::V4 = 7;
    const Reg Reg::V5 = 8;
    const Reg Reg::V6 = 9;
    const Reg Reg::V7 = 10;
    const Reg Reg::V8 = 11;
    const Reg Reg::IP = 12;
    const Reg Reg::SP = 13;
    const Reg Reg::LR = 14;
    const Reg Reg::PC = 15;
    const Reg Reg::WR = 7;
    const Reg Reg::SB = 9;
    const Reg Reg::SL = 10;
    const Reg Reg::FP = 11;

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

    ///
    /// An ARM coprocessor.
    struct Coprocessor {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Coprocessor, given its underlying value.
        Coprocessor(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Coprocessor CP0;
        static const Coprocessor CP1;
        static const Coprocessor CP2;
        static const Coprocessor CP3;
        static const Coprocessor CP4;
        static const Coprocessor CP5;
        static const Coprocessor CP6;
        static const Coprocessor CP7;
        static const Coprocessor CP8;
        static const Coprocessor CP9;
        static const Coprocessor CP10;
        static const Coprocessor CP11;
        static const Coprocessor CP12;
        static const Coprocessor CP13;
        static const Coprocessor CP14;
        static const Coprocessor CP15;
    };

    const Coprocessor Coprocessor::CP0 = 0;
    const Coprocessor Coprocessor::CP1 = 1;
    const Coprocessor Coprocessor::CP2 = 2;
    const Coprocessor Coprocessor::CP3 = 3;
    const Coprocessor Coprocessor::CP4 = 4;
    const Coprocessor Coprocessor::CP5 = 5;
    const Coprocessor Coprocessor::CP6 = 6;
    const Coprocessor Coprocessor::CP7 = 7;
    const Coprocessor Coprocessor::CP8 = 8;
    const Coprocessor Coprocessor::CP9 = 9;
    const Coprocessor Coprocessor::CP10 = 10;
    const Coprocessor Coprocessor::CP11 = 11;
    const Coprocessor Coprocessor::CP12 = 12;
    const Coprocessor Coprocessor::CP13 = 13;
    const Coprocessor Coprocessor::CP14 = 14;
    const Coprocessor Coprocessor::CP15 = 15;

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
        write_binary(os, swap32((((((10485760 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((10485760 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((8388608 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((8388608 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((0 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((0 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& eor(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((2097152 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((2097152 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& orr(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((25165824 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((25165824 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& rsb(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((6291456 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((6291456 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& rsc(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((14680064 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((14680064 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& sbc(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((12582912 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((12582912 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((4194304 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((4194304 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& bkpt(std::ostream& os, uint16_t immed) {
        #if BIGENDIAN
        write_binary(os, swap32(((3776970864 | (((uint32_t)immed & 65520) << 8)) | (((uint32_t)immed & 15) << 0))), 4);
        #else
        write_binary(os, ((3776970864 | (((uint32_t)immed & 65520) << 8)) | (((uint32_t)immed & 15) << 0)), 4);
        #endif

        return os;
    }

    std::ostream& b(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((167772160 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (167772160 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& bic(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((29360128 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((29360128 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& blx(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((19922736 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (19922736 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& bx(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((19922704 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (19922704 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& bxj(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((19922720 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (19922720 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& blxun(std::ostream& os) {
        #if BIGENDIAN
        write_binary(os, swap32(4194304000), 4);
        #else
        write_binary(os, 4194304000, 4);
        #endif

        return os;
    }

    std::ostream& clz(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((24055568 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((24055568 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& cmn(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        write_binary(os, swap32(((24117248 | (uint32_t)cond) | ((uint32_t)rn << 16))), 4);
        #else
        write_binary(os, ((24117248 | (uint32_t)cond) | ((uint32_t)rn << 16)), 4);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        write_binary(os, swap32(((22020096 | (uint32_t)cond) | ((uint32_t)rn << 16))), 4);
        #else
        write_binary(os, ((22020096 | (uint32_t)cond) | ((uint32_t)rn << 16)), 4);
        #endif

        return os;
    }

    std::ostream& cpy(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((27262976 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((27262976 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& cps(std::ostream& os, Mode mode) {
        #if BIGENDIAN
        write_binary(os, swap32((4043440128 | ((uint32_t)mode << 0))), 4);
        #else
        write_binary(os, (4043440128 | ((uint32_t)mode << 0)), 4);
        #endif

        return os;
    }

    std::ostream& cpsie(std::ostream& os, InterruptFlags iflags) {
        #if BIGENDIAN
        write_binary(os, swap32((4043833344 | ((uint32_t)iflags << 6))), 4);
        #else
        write_binary(os, (4043833344 | ((uint32_t)iflags << 6)), 4);
        #endif

        return os;
    }

    std::ostream& cpsid(std::ostream& os, InterruptFlags iflags) {
        #if BIGENDIAN
        write_binary(os, swap32((4044095488 | ((uint32_t)iflags << 6))), 4);
        #else
        write_binary(os, (4044095488 | ((uint32_t)iflags << 6)), 4);
        #endif

        return os;
    }

    std::ostream& cpsie_mode(std::ostream& os, InterruptFlags iflags, Mode mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((4043964416 | ((uint32_t)iflags << 6)) | ((uint32_t)mode << 0))), 4);
        #else
        write_binary(os, ((4043964416 | ((uint32_t)iflags << 6)) | ((uint32_t)mode << 0)), 4);
        #endif

        return os;
    }

    std::ostream& cpsid_mode(std::ostream& os, InterruptFlags iflags, Mode mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((4044226560 | ((uint32_t)iflags << 6)) | ((uint32_t)mode << 0))), 4);
        #else
        write_binary(os, ((4044226560 | ((uint32_t)iflags << 6)) | ((uint32_t)mode << 0)), 4);
        #endif

        return os;
    }

    std::ostream& ldc(std::ostream& os, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((202375168 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)cpnum << 8)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((202375168 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)cpnum << 8)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldm(std::ostream& os, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool copy_spsr) {
        assert((((uint32_t)copy_spsr == 1) ^ ((uint32_t)write == ((uint32_t)registers & 32768))));
        #if BIGENDIAN
        write_binary(os, swap32(((((((((135266304 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)) | ((uint32_t)addressing_mode << 23)) | (uint32_t)registers) | ((uint32_t)copy_spsr << 21)) | ((uint32_t)write << 10))), 4);
        #else
        write_binary(os, ((((((((135266304 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)) | ((uint32_t)addressing_mode << 23)) | (uint32_t)registers) | ((uint32_t)copy_spsr << 21)) | ((uint32_t)write << 10)), 4);
        #endif

        return os;
    }

    std::ostream& ldr(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((68157440 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((68157440 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((72351744 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((72351744 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrbt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((74448896 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23))), 4);
        #else
        write_binary(os, ((((74448896 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23)), 4);
        #endif

        return os;
    }

    std::ostream& ldrd(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((208 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((208 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrex(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((26218399 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((26218399 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& ldrh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((1048752 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((1048752 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrsb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((1048784 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((1048784 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrsh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((1048816 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((1048816 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ldrt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((70254592 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23))), 4);
        #else
        write_binary(os, ((((70254592 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23)), 4);
        #endif

        return os;
    }

    std::ostream& cdp(std::ostream& os, Condition cond, Coprocessor cpnum) {
        #if BIGENDIAN
        write_binary(os, swap32(((234881024 | (uint32_t)cond) | ((uint32_t)cpnum << 8))), 4);
        #else
        write_binary(os, ((234881024 | (uint32_t)cond) | ((uint32_t)cpnum << 8)), 4);
        #endif

        return os;
    }

    std::ostream& mcr(std::ostream& os, Condition cond, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        write_binary(os, swap32((((234881040 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8))), 4);
        #else
        write_binary(os, (((234881040 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8)), 4);
        #endif

        return os;
    }

    std::ostream& mrc(std::ostream& os, Condition cond, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        write_binary(os, swap32((((235929616 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8))), 4);
        #else
        write_binary(os, (((235929616 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8)), 4);
        #endif

        return os;
    }

    std::ostream& mcrr(std::ostream& os, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        write_binary(os, swap32(((((205520896 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8))), 4);
        #else
        write_binary(os, ((((205520896 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8)), 4);
        #endif

        return os;
    }

    std::ostream& mla(std::ostream& os, Condition cond, bool update_cprs, Reg rn, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((((2097296 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((((2097296 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& mov(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32(((((27262976 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, ((((27262976 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& mrrc(std::ostream& os, Condition cond, Reg rn, Reg rd, Coprocessor cpnum) {
        #if BIGENDIAN
        write_binary(os, swap32(((((206569472 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8))), 4);
        #else
        write_binary(os, ((((206569472 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)cpnum << 8)), 4);
        #endif

        return os;
    }

    std::ostream& mrs(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((17760256 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((17760256 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& mul(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32(((((144 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 16)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, ((((144 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 16)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& mvn(std::ostream& os, Condition cond, bool update_cprs, Reg rd, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32(((((31457280 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, ((((31457280 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)rd << 12)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& msr_imm(std::ostream& os, Condition cond, FieldMask fieldmask) {
        #if BIGENDIAN
        write_binary(os, swap32(((52490240 | (uint32_t)cond) | ((uint32_t)fieldmask << 16))), 4);
        #else
        write_binary(os, ((52490240 | (uint32_t)cond) | ((uint32_t)fieldmask << 16)), 4);
        #endif

        return os;
    }

    std::ostream& msr_reg(std::ostream& os, Condition cond, FieldMask fieldmask) {
        #if BIGENDIAN
        write_binary(os, swap32(((18935808 | (uint32_t)cond) | ((uint32_t)fieldmask << 16))), 4);
        #else
        write_binary(os, ((18935808 | (uint32_t)cond) | ((uint32_t)fieldmask << 16)), 4);
        #endif

        return os;
    }

    std::ostream& pkhbt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((109051920 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((109051920 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& pkhtb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((109051984 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((109051984 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& pld(std::ostream& os, Reg rn, OffsetMode offset_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((4115722240 | ((uint32_t)rn << 16)) | ((uint32_t)offset_mode << 23))), 4);
        #else
        write_binary(os, ((4115722240 | ((uint32_t)rn << 16)) | ((uint32_t)offset_mode << 23)), 4);
        #endif

        return os;
    }

    std::ostream& qadd(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777296 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((16777296 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764304 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764304 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764432 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764432 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764336 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764336 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qdadd(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((20971600 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((20971600 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qdsub(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((23068752 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((23068752 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qsub(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((18874448 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((18874448 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764400 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764400 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764528 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764528 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& qsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((102764368 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((102764368 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& rev(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((113184560 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((113184560 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& rev16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((113184688 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((113184688 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& revsh(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((117378992 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((117378992 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& rfe(std::ostream& os, bool write, Reg rn, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((4161800704 | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((4161800704 | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& sadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715728 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715728 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& sadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715856 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715856 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& saddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715760 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715760 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& sel(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((109055920 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((109055920 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& setendbe(std::ostream& os) {
        #if BIGENDIAN
        write_binary(os, swap32(4043375104), 4);
        #else
        write_binary(os, 4043375104, 4);
        #endif

        return os;
    }

    std::ostream& setendle(std::ostream& os) {
        #if BIGENDIAN
        write_binary(os, swap32(4043374592), 4);
        #else
        write_binary(os, 4043374592, 4);
        #endif

        return os;
    }

    std::ostream& shadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103812880 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103812880 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& shadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103813008 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103813008 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& shaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103812912 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103812912 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& shsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103812976 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103812976 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& shsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103813104 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103813104 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& shsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((103812944 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((103812944 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& smlabb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777344 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((16777344 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlabt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777376 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((16777376 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlatb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777408 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((16777408 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlatt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777440 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((16777440 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlad(std::ostream& os, Condition cond, bool exchange, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((((117440528 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((((117440528 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlal(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((14680208 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((14680208 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& smlalbb(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((20971648 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (20971648 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& smlalbt(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((20971680 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (20971680 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& smlaltb(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((20971712 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (20971712 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& smlaltt(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((20971744 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (20971744 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& smlald(std::ostream& os, Condition cond, bool exchange) {
        #if BIGENDIAN
        write_binary(os, swap32(((121634832 | (uint32_t)cond) | ((uint32_t)exchange << 5))), 4);
        #else
        write_binary(os, ((121634832 | (uint32_t)cond) | ((uint32_t)exchange << 5)), 4);
        #endif

        return os;
    }

    std::ostream& smlawb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((18874496 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((18874496 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlawt(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((18874560 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((18874560 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlsd(std::ostream& os, Condition cond, bool exchange, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((((117440592 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((((117440592 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smlsld(std::ostream& os, Condition cond, bool exchange) {
        #if BIGENDIAN
        write_binary(os, swap32(((121634896 | (uint32_t)cond) | ((uint32_t)exchange << 5))), 4);
        #else
        write_binary(os, ((121634896 | (uint32_t)cond) | ((uint32_t)exchange << 5)), 4);
        #endif

        return os;
    }

    std::ostream& smmla(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((122683408 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((122683408 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smmls(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((122683600 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((122683600 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smmul(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((122744848 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((122744848 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smuad(std::ostream& os, Condition cond, bool exchange, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((117501968 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((117501968 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smulbb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((23068800 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((23068800 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smulbt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((23068832 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((23068832 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smultb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((23068864 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((23068864 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smultt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((23068896 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((23068896 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smull(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((12583056 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((12583056 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& smulwb(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((18874528 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((18874528 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smulwt(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((18874592 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((18874592 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& smusd(std::ostream& os, Condition cond, bool exchange, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((117502032 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((117502032 | (uint32_t)cond) | ((uint32_t)exchange << 5)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& srs(std::ostream& os, bool write, Mode mode, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((4165797120 | ((uint32_t)write << 21)) | ((uint32_t)mode << 0)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((4165797120 | ((uint32_t)write << 21)) | ((uint32_t)mode << 0)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& ssat(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((105906192 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((105906192 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& ssat16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((111152944 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((111152944 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& ssub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715824 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715824 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& ssub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715952 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715952 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& ssubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((101715792 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((101715792 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& stc(std::ostream& os, Condition cond, bool write, Reg rn, Coprocessor cpnum, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((201326592 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)cpnum << 8)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((201326592 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)cpnum << 8)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& stm(std::ostream& os, Condition cond, Reg rn, OffsetMode offset_mode, Addressing addressing_mode, RegList registers, bool write, bool user_mode) {
        assert((((uint32_t)user_mode == 0) || ((uint32_t)write == 0)));
        #if BIGENDIAN
        write_binary(os, swap32(((((((((134217728 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)) | ((uint32_t)addressing_mode << 23)) | (uint32_t)registers) | ((uint32_t)user_mode << 21)) | ((uint32_t)write << 10))), 4);
        #else
        write_binary(os, ((((((((134217728 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)) | ((uint32_t)addressing_mode << 23)) | (uint32_t)registers) | ((uint32_t)user_mode << 21)) | ((uint32_t)write << 10)), 4);
        #endif

        return os;
    }

    std::ostream& str(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((67108864 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((67108864 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& strb(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((71303168 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((71303168 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& strbt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((73400320 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23))), 4);
        #else
        write_binary(os, ((((73400320 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23)), 4);
        #endif

        return os;
    }

    std::ostream& strd(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((240 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((240 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& strex(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((25169808 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((25169808 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& strh(std::ostream& os, Condition cond, bool write, Reg rn, Reg rd, OffsetMode offset_mode, Addressing addressing_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((((176 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11))), 4);
        #else
        write_binary(os, ((((((176 | (uint32_t)cond) | ((uint32_t)write << 21)) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)addressing_mode << 23)) | ((uint32_t)offset_mode << 11)), 4);
        #endif

        return os;
    }

    std::ostream& strt(std::ostream& os, Condition cond, Reg rn, Reg rd, OffsetMode offset_mode) {
        #if BIGENDIAN
        write_binary(os, swap32(((((69206016 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23))), 4);
        #else
        write_binary(os, ((((69206016 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)offset_mode << 23)), 4);
        #endif

        return os;
    }

    std::ostream& swi(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((251658240 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (251658240 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& swp(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((16777360 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((16777360 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& swpb(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((20971664 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((20971664 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& sxtab(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((111149168 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((111149168 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& sxtab16(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((109052016 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((109052016 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& sxtah(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((112197744 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((112197744 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& sxtb(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((112132208 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((112132208 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& sxtb16(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((110035056 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((110035056 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& sxth(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((113180784 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((113180784 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& teq(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        write_binary(os, swap32(((19922944 | (uint32_t)cond) | ((uint32_t)rn << 16))), 4);
        #else
        write_binary(os, ((19922944 | (uint32_t)cond) | ((uint32_t)rn << 16)), 4);
        #endif

        return os;
    }

    std::ostream& tst(std::ostream& os, Condition cond, Reg rn) {
        #if BIGENDIAN
        write_binary(os, swap32(((17825792 | (uint32_t)cond) | ((uint32_t)rn << 16))), 4);
        #else
        write_binary(os, ((17825792 | (uint32_t)cond) | ((uint32_t)rn << 16)), 4);
        #endif

        return os;
    }

    std::ostream& uadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910032 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910032 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910160 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910160 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910064 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910064 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007184 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007184 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007312 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007312 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007216 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007216 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007280 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007280 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007408 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007408 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uhsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((108007248 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((108007248 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& umaal(std::ostream& os, Condition cond) {
        #if BIGENDIAN
        write_binary(os, swap32((4194448 | (uint32_t)cond)), 4);
        #else
        write_binary(os, (4194448 | (uint32_t)cond), 4);
        #endif

        return os;
    }

    std::ostream& umlal(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((10485904 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((10485904 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& umull(std::ostream& os, Condition cond, bool update_cprs, bool update_condition) {
        #if BIGENDIAN
        write_binary(os, swap32((((8388752 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20))), 4);
        #else
        write_binary(os, (((8388752 | (uint32_t)cond) | ((uint32_t)update_cprs << 20)) | ((uint32_t)update_condition << 20)), 4);
        #endif

        return os;
    }

    std::ostream& uqadd16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958608 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958608 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uqadd8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958736 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958736 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uqaddsubx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958640 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958640 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uqsub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958704 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958704 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uqsub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958832 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958832 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uqsubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((106958672 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((106958672 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& usad8(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((125890576 | (uint32_t)cond) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, ((125890576 | (uint32_t)cond) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& usada8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((125829136 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16))), 4);
        #else
        write_binary(os, (((125829136 | (uint32_t)cond) | ((uint32_t)rn << 12)) | ((uint32_t)rd << 16)), 4);
        #endif

        return os;
    }

    std::ostream& usat(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((115343376 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((115343376 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& usat16(std::ostream& os, Condition cond, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32(((115347248 | (uint32_t)cond) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, ((115347248 | (uint32_t)cond) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& usub16(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910128 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910128 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& usub8(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910256 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910256 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& usubaddx(std::ostream& os, Condition cond, Reg rn, Reg rd) {
        #if BIGENDIAN
        write_binary(os, swap32((((105910096 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12))), 4);
        #else
        write_binary(os, (((105910096 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)), 4);
        #endif

        return os;
    }

    std::ostream& uxtab(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((115343472 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((115343472 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& uxtab16(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((113246320 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((113246320 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& uxtah(std::ostream& os, Condition cond, Reg rn, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32(((((116392048 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, ((((116392048 | (uint32_t)cond) | ((uint32_t)rn << 16)) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& uxtb(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((116326512 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((116326512 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& uxtb16(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((114229360 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((114229360 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

    std::ostream& uxth(std::ostream& os, Condition cond, Reg rd, Rotation rotate) {
        #if BIGENDIAN
        write_binary(os, swap32((((117375088 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10))), 4);
        #else
        write_binary(os, (((117375088 | (uint32_t)cond) | ((uint32_t)rd << 12)) | ((uint32_t)rotate << 10)), 4);
        #endif

        return os;
    }

}
