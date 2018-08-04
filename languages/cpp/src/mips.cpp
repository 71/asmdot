// Automatically generated file.

#include <cassert>
#include <cstdint>
#include <ostream>

namespace mips
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
    /// A Mips register.
    struct Reg {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg, given its underlying value.
        Reg(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg ZERO;
        static const Reg AT;
        static const Reg V0;
        static const Reg V1;
        static const Reg A0;
        static const Reg A1;
        static const Reg A2;
        static const Reg A3;
        static const Reg T0;
        static const Reg T1;
        static const Reg T2;
        static const Reg T3;
        static const Reg T4;
        static const Reg T5;
        static const Reg T6;
        static const Reg T7;
        static const Reg S0;
        static const Reg S1;
        static const Reg S2;
        static const Reg S3;
        static const Reg S4;
        static const Reg S5;
        static const Reg S6;
        static const Reg S7;
        static const Reg T8;
        static const Reg T9;
        static const Reg K0;
        static const Reg K1;
        static const Reg GP;
        static const Reg SP;
        static const Reg FP;
        static const Reg RA;
    };

    const Reg Reg::ZERO = 0;
    const Reg Reg::AT = 1;
    const Reg Reg::V0 = 2;
    const Reg Reg::V1 = 3;
    const Reg Reg::A0 = 4;
    const Reg Reg::A1 = 5;
    const Reg Reg::A2 = 6;
    const Reg Reg::A3 = 7;
    const Reg Reg::T0 = 8;
    const Reg Reg::T1 = 9;
    const Reg Reg::T2 = 10;
    const Reg Reg::T3 = 11;
    const Reg Reg::T4 = 12;
    const Reg Reg::T5 = 13;
    const Reg Reg::T6 = 14;
    const Reg Reg::T7 = 15;
    const Reg Reg::S0 = 16;
    const Reg Reg::S1 = 17;
    const Reg Reg::S2 = 18;
    const Reg Reg::S3 = 19;
    const Reg Reg::S4 = 20;
    const Reg Reg::S5 = 21;
    const Reg Reg::S6 = 22;
    const Reg Reg::S7 = 23;
    const Reg Reg::T8 = 24;
    const Reg Reg::T9 = 25;
    const Reg Reg::K0 = 26;
    const Reg Reg::K1 = 27;
    const Reg Reg::GP = 28;
    const Reg Reg::SP = 29;
    const Reg Reg::FP = 30;
    const Reg Reg::RA = 31;


    std::ostream& sll(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((0 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((0 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& movci(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((1 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((1 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& srl(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((2 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((2 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& sra(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((3 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((3 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& sllv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((4 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((4 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& srlv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((6 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((6 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& srav(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((7 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((7 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& jr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((8 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((8 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& jalr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((9 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((9 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& movz(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((10 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((10 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& movn(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((11 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((11 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& syscall(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((12 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((12 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& breakpoint(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((13 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((13 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& sync(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((15 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((15 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& mfhi(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((16 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((16 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& mthi(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((17 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((17 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& mflo(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((18 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((18 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsllv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((20 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((20 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsrlv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((22 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((22 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsrav(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((23 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((23 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& mult(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((24 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((24 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& multu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((25 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((25 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& div(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((26 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((26 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& divu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((27 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((27 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dmult(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((28 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((28 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dmultu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((29 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((29 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& ddiv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((30 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((30 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& ddivu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((31 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((31 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((32 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((32 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& addu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((33 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((33 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((34 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((34 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& subu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((35 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((35 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((36 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((36 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& or_(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((37 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((37 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((38 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((38 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& nor(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((39 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((39 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& slt(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((42 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((42 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& sltu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((43 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((43 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dadd(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((44 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((44 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& daddu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((45 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((45 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsub(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((46 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((46 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsubu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((47 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((47 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& tge(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((48 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((48 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& tgeu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((49 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((49 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& tlt(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((50 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((50 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& tltu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((51 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((51 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& teq(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((52 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((52 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& tne(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((54 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((54 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsll(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((56 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((56 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dslr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((58 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((58 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& dsra(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((59 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((59 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& mhc0(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        write_binary(os, swap32(((((1073741824 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6))), 4);
        #else
        write_binary(os, ((((1073741824 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)rd & 31) << 11)) | (((uint32_t)shift & 31) << 6)), 4);
        #endif

        return os;
    }

    std::ostream& btlz(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bgez(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bltzl(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bgezl(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& sllv(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& tgei(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& jalr(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& tlti(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& tltiu(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& teqi(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& tnei(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bltzal(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bgezal(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bltzall(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& bgezall(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& dsllv(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& synci(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        write_binary(os, swap32(((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535))), 4);
        #else
        write_binary(os, ((67108864 | (((uint32_t)rs & 31) << 16)) | (((uint32_t)target >> 2) & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& addi(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((536870912 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((536870912 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& addiu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((603979776 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((603979776 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& andi(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((805306368 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((805306368 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& beq(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((268435456 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2))), 4);
        #else
        write_binary(os, (((268435456 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2)), 4);
        #endif

        return os;
    }

    std::ostream& blez(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((402653184 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2))), 4);
        #else
        write_binary(os, (((402653184 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2)), 4);
        #endif

        return os;
    }

    std::ostream& bne(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((335544320 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2))), 4);
        #else
        write_binary(os, (((335544320 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | (((uint32_t)imm & 65535) >> 2)), 4);
        #endif

        return os;
    }

    std::ostream& lw(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2348810240 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2348810240 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& lbu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2415919104 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2415919104 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& lhu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2483027968 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2483027968 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& lui(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((1006632960 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((1006632960 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& ori(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((872415232 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((872415232 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& sb(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2684354560 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2684354560 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& sh(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2751463424 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2751463424 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& slti(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((671088640 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((671088640 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& sltiu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((738197504 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((738197504 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& sw(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        write_binary(os, swap32((((2885681152 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535))), 4);
        #else
        write_binary(os, (((2885681152 | (((uint32_t)rs & 31) << 21)) | (((uint32_t)rt & 31) << 16)) | ((uint32_t)imm & 65535)), 4);
        #endif

        return os;
    }

    std::ostream& j(std::ostream& os, uint32_t address) {
        #if BIGENDIAN
        write_binary(os, swap32((134217728 | (((uint32_t)address >> 2) & 67108863))), 4);
        #else
        write_binary(os, (134217728 | (((uint32_t)address >> 2) & 67108863)), 4);
        #endif

        return os;
    }

    std::ostream& jal(std::ostream& os, uint32_t address) {
        #if BIGENDIAN
        write_binary(os, swap32((201326592 | (((uint32_t)address >> 2) & 67108863))), 4);
        #else
        write_binary(os, (201326592 | (((uint32_t)address >> 2) & 67108863)), 4);
        #endif

        return os;
    }

}
