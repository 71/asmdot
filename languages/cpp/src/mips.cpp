// Automatically generated file.

#include <cassert>
#include <ostream>

namespace mips
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
    static const Reg Zero = 0;
    static const Reg AT = 1;
    static const Reg V0 = 2;
    static const Reg V1 = 3;
    static const Reg A0 = 4;
    static const Reg A1 = 5;
    static const Reg A2 = 6;
    static const Reg A3 = 7;
    static const Reg T0 = 8;
    static const Reg T1 = 9;
    static const Reg T2 = 10;
    static const Reg T3 = 11;
    static const Reg T4 = 12;
    static const Reg T5 = 13;
    static const Reg T6 = 14;
    static const Reg T7 = 15;
    static const Reg S0 = 16;
    static const Reg S1 = 17;
    static const Reg S2 = 18;
    static const Reg S3 = 19;
    static const Reg S4 = 20;
    static const Reg S5 = 21;
    static const Reg S6 = 22;
    static const Reg S7 = 23;
    static const Reg T8 = 24;
    static const Reg T9 = 25;
    static const Reg K0 = 26;
    static const Reg K1 = 27;
    static const Reg GP = 28;
    static const Reg SP = 29;
    static const Reg FP = 30;
    static const Reg RA = 31;

    std::ostream& sll(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& movci(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& srl(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& sra(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& sllv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& srlv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& srav(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& jr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& jalr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& movz(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& movn(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& syscall(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& breakpoint(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& sync(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& mfhi(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& mthi(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& mflo(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsllv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsrlv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsrav(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& mult(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& multu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& div(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& divu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dmult(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dmultu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& ddiv(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& ddivu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& addu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& subu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& or(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& xor(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& nor(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& slt(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& sltu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dadd(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& daddu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsub(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsubu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& tge(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& tgeu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& tlt(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& tltu(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& teq(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& tne(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsll(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dslr(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& dsra(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& mhc0(std::ostream& os, Reg rd, Reg rs, Reg rt, uint8_t shift) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6))));
        #else
        os << std::bitset<32>(((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
        #endif

        return os;
    }

    std::ostream& btlz(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bgez(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bltzl(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bgezl(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& sllv(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& tgei(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& jalr(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& tlti(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& tltiu(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& teqi(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& tnei(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bltzal(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bgezal(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bltzall(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& bgezall(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& dsllv(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& synci(std::ostream& os, Reg rs, uint16_t target) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535))));
        #else
        os << std::bitset<32>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
        #endif

        return os;
    }

    std::ostream& addi(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& addiu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& andi(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& beq(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2))));
        #else
        os << std::bitset<32>((((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
        #endif

        return os;
    }

    std::ostream& blez(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2))));
        #else
        os << std::bitset<32>((((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
        #endif

        return os;
    }

    std::ostream& bne(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2))));
        #else
        os << std::bitset<32>((((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
        #endif

        return os;
    }

    std::ostream& lw(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& lbu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& lhu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& lui(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& ori(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& sb(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& sh(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& slti(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& sltiu(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& sw(std::ostream& os, Reg rs, Reg rt, uint16_t imm) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535))));
        #else
        os << std::bitset<32>((((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
        #endif

        return os;
    }

    std::ostream& j(std::ostream& os, uint32_t address) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((134217728 | ((address >> 2) & 67108863))));
        #else
        os << std::bitset<32>((134217728 | ((address >> 2) & 67108863)));
        #endif

        return os;
    }

    std::ostream& jal(std::ostream& os, uint32_t address) {
        #if BIGENDIAN
        os << std::bitset<32>(swap32((201326592 | ((address >> 2) & 67108863))));
        #else
        os << std::bitset<32>((201326592 | ((address >> 2) & 67108863)));
        #endif

        return os;
    }

