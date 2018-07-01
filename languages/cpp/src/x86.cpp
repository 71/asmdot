// Automatically generated file.

#include <cassert>
#include <ostream>

namespace x86
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

    using Reg8 = uint8_t;
    static const Reg8 al = 0;
    static const Reg8 cl = 1;
    static const Reg8 dl = 2;
    static const Reg8 bl = 3;
    static const Reg8 spl = 4;
    static const Reg8 bpl = 5;
    static const Reg8 sil = 6;
    static const Reg8 dil = 7;
    static const Reg8 r8b = 8;
    static const Reg8 r9b = 9;
    static const Reg8 r10b = 10;
    static const Reg8 r11b = 11;
    static const Reg8 r12b = 12;
    static const Reg8 r13b = 13;
    static const Reg8 r14b = 14;
    static const Reg8 r15b = 15;
    using Reg16 = uint8_t;
    static const Reg16 ax = 0;
    static const Reg16 cx = 1;
    static const Reg16 dx = 2;
    static const Reg16 bx = 3;
    static const Reg16 sp = 4;
    static const Reg16 bp = 5;
    static const Reg16 si = 6;
    static const Reg16 di = 7;
    static const Reg16 r8w = 8;
    static const Reg16 r9w = 9;
    static const Reg16 r10w = 10;
    static const Reg16 r11w = 11;
    static const Reg16 r12w = 12;
    static const Reg16 r13w = 13;
    static const Reg16 r14w = 14;
    static const Reg16 r15w = 15;
    using Reg32 = uint8_t;
    static const Reg32 eax = 0;
    static const Reg32 ecx = 1;
    static const Reg32 edx = 2;
    static const Reg32 ebx = 3;
    static const Reg32 esp = 4;
    static const Reg32 ebp = 5;
    static const Reg32 esi = 6;
    static const Reg32 edi = 7;
    static const Reg32 r8d = 8;
    static const Reg32 r9d = 9;
    static const Reg32 r10d = 10;
    static const Reg32 r11d = 11;
    static const Reg32 r12d = 12;
    static const Reg32 r13d = 13;
    static const Reg32 r14d = 14;
    static const Reg32 r15d = 15;
    using Reg64 = uint8_t;
    static const Reg64 rax = 0;
    static const Reg64 rcx = 1;
    static const Reg64 rdx = 2;
    static const Reg64 rbx = 3;
    static const Reg64 rsp = 4;
    static const Reg64 rbp = 5;
    static const Reg64 rsi = 6;
    static const Reg64 rdi = 7;
    static const Reg64 r8 = 8;
    static const Reg64 r9 = 9;
    static const Reg64 r10 = 10;
    static const Reg64 r11 = 11;
    static const Reg64 r12 = 12;
    static const Reg64 r13 = 13;
    static const Reg64 r14 = 14;
    static const Reg64 r15 = 15;
    using Reg128 = uint8_t;

    std::ostream& pushf(std::ostream& os) {
        os.put(156);
        return os;
    }

    std::ostream& popf(std::ostream& os) {
        os.put(157);
        return os;
    }

    std::ostream& ret(std::ostream& os) {
        os.put(195);
        return os;
    }

    std::ostream& clc(std::ostream& os) {
        os.put(248);
        return os;
    }

    std::ostream& stc(std::ostream& os) {
        os.put(249);
        return os;
    }

    std::ostream& cli(std::ostream& os) {
        os.put(250);
        return os;
    }

    std::ostream& sti(std::ostream& os) {
        os.put(251);
        return os;
    }

    std::ostream& cld(std::ostream& os) {
        os.put(252);
        return os;
    }

    std::ostream& std(std::ostream& os) {
        os.put(253);
        return os;
    }

    std::ostream& jo(std::ostream& os, int8_t operand) {
        os.put(112);
        os.put(operand);
        return os;
    }

    std::ostream& jno(std::ostream& os, int8_t operand) {
        os.put(113);
        os.put(operand);
        return os;
    }

    std::ostream& jb(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put(operand);
        return os;
    }

    std::ostream& jnae(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put(operand);
        return os;
    }

    std::ostream& jc(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put(operand);
        return os;
    }

    std::ostream& jnb(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put(operand);
        return os;
    }

    std::ostream& jae(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put(operand);
        return os;
    }

    std::ostream& jnc(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put(operand);
        return os;
    }

    std::ostream& jz(std::ostream& os, int8_t operand) {
        os.put(116);
        os.put(operand);
        return os;
    }

    std::ostream& je(std::ostream& os, int8_t operand) {
        os.put(116);
        os.put(operand);
        return os;
    }

    std::ostream& jnz(std::ostream& os, int8_t operand) {
        os.put(117);
        os.put(operand);
        return os;
    }

    std::ostream& jne(std::ostream& os, int8_t operand) {
        os.put(117);
        os.put(operand);
        return os;
    }

    std::ostream& jbe(std::ostream& os, int8_t operand) {
        os.put(118);
        os.put(operand);
        return os;
    }

    std::ostream& jna(std::ostream& os, int8_t operand) {
        os.put(118);
        os.put(operand);
        return os;
    }

    std::ostream& jnbe(std::ostream& os, int8_t operand) {
        os.put(119);
        os.put(operand);
        return os;
    }

    std::ostream& ja(std::ostream& os, int8_t operand) {
        os.put(119);
        os.put(operand);
        return os;
    }

    std::ostream& js(std::ostream& os, int8_t operand) {
        os.put(120);
        os.put(operand);
        return os;
    }

    std::ostream& jns(std::ostream& os, int8_t operand) {
        os.put(121);
        os.put(operand);
        return os;
    }

    std::ostream& jp(std::ostream& os, int8_t operand) {
        os.put(122);
        os.put(operand);
        return os;
    }

    std::ostream& jpe(std::ostream& os, int8_t operand) {
        os.put(122);
        os.put(operand);
        return os;
    }

    std::ostream& jnp(std::ostream& os, int8_t operand) {
        os.put(123);
        os.put(operand);
        return os;
    }

    std::ostream& jpo(std::ostream& os, int8_t operand) {
        os.put(123);
        os.put(operand);
        return os;
    }

    std::ostream& jl(std::ostream& os, int8_t operand) {
        os.put(124);
        os.put(operand);
        return os;
    }

    std::ostream& jnge(std::ostream& os, int8_t operand) {
        os.put(124);
        os.put(operand);
        return os;
    }

    std::ostream& jnl(std::ostream& os, int8_t operand) {
        os.put(125);
        os.put(operand);
        return os;
    }

    std::ostream& jge(std::ostream& os, int8_t operand) {
        os.put(125);
        os.put(operand);
        return os;
    }

    std::ostream& jle(std::ostream& os, int8_t operand) {
        os.put(126);
        os.put(operand);
        return os;
    }

    std::ostream& jng(std::ostream& os, int8_t operand) {
        os.put(126);
        os.put(operand);
        return os;
    }

    std::ostream& jnle(std::ostream& os, int8_t operand) {
        os.put(127);
        os.put(operand);
        return os;
    }

    std::ostream& jg(std::ostream& os, int8_t operand) {
        os.put(127);
        os.put(operand);
        return os;
    }

    std::ostream& inc(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((64 + operand));
        return os;
    }

    std::ostream& inc(std::ostream& os, Reg32 operand) {
        if ((operand > 7))
        {
            os.put(65);
        }
        os.put((64 + operand));
        return os;
    }

    std::ostream& dec(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((72 + operand));
        return os;
    }

    std::ostream& dec(std::ostream& os, Reg32 operand) {
        if ((operand > 7))
        {
            os.put(65);
        }
        os.put((72 + operand));
        return os;
    }

    std::ostream& push(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((80 + operand));
        return os;
    }

    std::ostream& push(std::ostream& os, Reg32 operand) {
        if ((operand > 7))
        {
            os.put(65);
        }
        os.put((80 + operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((88 + operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg32 operand) {
        if ((operand > 7))
        {
            os.put(65);
        }
        os.put((88 + operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg64 operand) {
        os.put((72 + get_prefix(operand)));
        os.put((88 + operand));
        return os;
    }

    std::ostream& add(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 0));
        os.put(value);
        return os;
    }

    std::ostream& or(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 1));
        os.put(value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 2));
        os.put(value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 3));
        os.put(value);
        return os;
    }

    std::ostream& and(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 4));
        os.put(value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 5));
        os.put(value);
        return os;
    }

    std::ostream& xor(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 6));
        os.put(value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put((reg + 7));
        os.put(value);
        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 0));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 0));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 0));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 0));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& or(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 1));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& or(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 1));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& or(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 1));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& or(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 1));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 2));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 2));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 2));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 2));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 3));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 3));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 3));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 3));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 4));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 4));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 4));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& and(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 4));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 5));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 5));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 5));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 5));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& xor(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 6));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& xor(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 6));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& xor(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 6));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& xor(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 6));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 7));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put((reg + 7));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put((reg + 7));
        #if BIGENDIAN
        os << std::bitset<16>(swap16(value));
        #else
        os << std::bitset<16>(value);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put((reg + 7));
        #if BIGENDIAN
        os << std::bitset<32>(swap32(value));
        #else
        os << std::bitset<32>(value);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 0));
        os.put(value);
        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 0));
        os.put(value);
        return os;
    }

    std::ostream& or(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 1));
        os.put(value);
        return os;
    }

    std::ostream& or(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 1));
        os.put(value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 2));
        os.put(value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 2));
        os.put(value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 3));
        os.put(value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 3));
        os.put(value);
        return os;
    }

    std::ostream& and(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 4));
        os.put(value);
        return os;
    }

    std::ostream& and(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 4));
        os.put(value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 5));
        os.put(value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 5));
        os.put(value);
        return os;
    }

    std::ostream& xor(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 6));
        os.put(value);
        return os;
    }

    std::ostream& xor(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 6));
        os.put(value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put((reg + 7));
        os.put(value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put((reg + 7));
        os.put(value);
        return os;
    }

