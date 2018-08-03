// Automatically generated file.

#include <cassert>
#include <cstdint>
#include <ostream>

namespace x86
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
    /// An x86 8-bits register.
    struct Reg8 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg8, given its underlying value.
        Reg8(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg8 al;
        static const Reg8 cl;
        static const Reg8 dl;
        static const Reg8 bl;
        static const Reg8 spl;
        static const Reg8 bpl;
        static const Reg8 sil;
        static const Reg8 dil;
        static const Reg8 r8b;
        static const Reg8 r9b;
        static const Reg8 r10b;
        static const Reg8 r11b;
        static const Reg8 r12b;
        static const Reg8 r13b;
        static const Reg8 r14b;
        static const Reg8 r15b;
    };

    const Reg8 Reg8::al = 0;
    const Reg8 Reg8::cl = 1;
    const Reg8 Reg8::dl = 2;
    const Reg8 Reg8::bl = 3;
    const Reg8 Reg8::spl = 4;
    const Reg8 Reg8::bpl = 5;
    const Reg8 Reg8::sil = 6;
    const Reg8 Reg8::dil = 7;
    const Reg8 Reg8::r8b = 8;
    const Reg8 Reg8::r9b = 9;
    const Reg8 Reg8::r10b = 10;
    const Reg8 Reg8::r11b = 11;
    const Reg8 Reg8::r12b = 12;
    const Reg8 Reg8::r13b = 13;
    const Reg8 Reg8::r14b = 14;
    const Reg8 Reg8::r15b = 15;

    ///
    /// An x86 16-bits register.
    struct Reg16 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg16, given its underlying value.
        Reg16(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg16 ax;
        static const Reg16 cx;
        static const Reg16 dx;
        static const Reg16 bx;
        static const Reg16 sp;
        static const Reg16 bp;
        static const Reg16 si;
        static const Reg16 di;
        static const Reg16 r8w;
        static const Reg16 r9w;
        static const Reg16 r10w;
        static const Reg16 r11w;
        static const Reg16 r12w;
        static const Reg16 r13w;
        static const Reg16 r14w;
        static const Reg16 r15w;
    };

    const Reg16 Reg16::ax = 0;
    const Reg16 Reg16::cx = 1;
    const Reg16 Reg16::dx = 2;
    const Reg16 Reg16::bx = 3;
    const Reg16 Reg16::sp = 4;
    const Reg16 Reg16::bp = 5;
    const Reg16 Reg16::si = 6;
    const Reg16 Reg16::di = 7;
    const Reg16 Reg16::r8w = 8;
    const Reg16 Reg16::r9w = 9;
    const Reg16 Reg16::r10w = 10;
    const Reg16 Reg16::r11w = 11;
    const Reg16 Reg16::r12w = 12;
    const Reg16 Reg16::r13w = 13;
    const Reg16 Reg16::r14w = 14;
    const Reg16 Reg16::r15w = 15;

    ///
    /// An x86 32-bits register.
    struct Reg32 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg32, given its underlying value.
        Reg32(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg32 eax;
        static const Reg32 ecx;
        static const Reg32 edx;
        static const Reg32 ebx;
        static const Reg32 esp;
        static const Reg32 ebp;
        static const Reg32 esi;
        static const Reg32 edi;
        static const Reg32 r8d;
        static const Reg32 r9d;
        static const Reg32 r10d;
        static const Reg32 r11d;
        static const Reg32 r12d;
        static const Reg32 r13d;
        static const Reg32 r14d;
        static const Reg32 r15d;
    };

    const Reg32 Reg32::eax = 0;
    const Reg32 Reg32::ecx = 1;
    const Reg32 Reg32::edx = 2;
    const Reg32 Reg32::ebx = 3;
    const Reg32 Reg32::esp = 4;
    const Reg32 Reg32::ebp = 5;
    const Reg32 Reg32::esi = 6;
    const Reg32 Reg32::edi = 7;
    const Reg32 Reg32::r8d = 8;
    const Reg32 Reg32::r9d = 9;
    const Reg32 Reg32::r10d = 10;
    const Reg32 Reg32::r11d = 11;
    const Reg32 Reg32::r12d = 12;
    const Reg32 Reg32::r13d = 13;
    const Reg32 Reg32::r14d = 14;
    const Reg32 Reg32::r15d = 15;

    ///
    /// An x86 64-bits register.
    struct Reg64 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg64, given its underlying value.
        Reg64(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg64 rax;
        static const Reg64 rcx;
        static const Reg64 rdx;
        static const Reg64 rbx;
        static const Reg64 rsp;
        static const Reg64 rbp;
        static const Reg64 rsi;
        static const Reg64 rdi;
        static const Reg64 r8;
        static const Reg64 r9;
        static const Reg64 r10;
        static const Reg64 r11;
        static const Reg64 r12;
        static const Reg64 r13;
        static const Reg64 r14;
        static const Reg64 r15;
    };

    const Reg64 Reg64::rax = 0;
    const Reg64 Reg64::rcx = 1;
    const Reg64 Reg64::rdx = 2;
    const Reg64 Reg64::rbx = 3;
    const Reg64 Reg64::rsp = 4;
    const Reg64 Reg64::rbp = 5;
    const Reg64 Reg64::rsi = 6;
    const Reg64 Reg64::rdi = 7;
    const Reg64 Reg64::r8 = 8;
    const Reg64 Reg64::r9 = 9;
    const Reg64 Reg64::r10 = 10;
    const Reg64 Reg64::r11 = 11;
    const Reg64 Reg64::r12 = 12;
    const Reg64 Reg64::r13 = 13;
    const Reg64 Reg64::r14 = 14;
    const Reg64 Reg64::r15 = 15;

    ///
    /// An x86 128-bits register.
    struct Reg128 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg128, given its underlying value.
        Reg128(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

    };



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
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jno(std::ostream& os, int8_t operand) {
        os.put(113);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jb(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnae(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jc(std::ostream& os, int8_t operand) {
        os.put(114);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnb(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jae(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnc(std::ostream& os, int8_t operand) {
        os.put(115);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jz(std::ostream& os, int8_t operand) {
        os.put(116);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& je(std::ostream& os, int8_t operand) {
        os.put(116);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnz(std::ostream& os, int8_t operand) {
        os.put(117);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jne(std::ostream& os, int8_t operand) {
        os.put(117);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jbe(std::ostream& os, int8_t operand) {
        os.put(118);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jna(std::ostream& os, int8_t operand) {
        os.put(118);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnbe(std::ostream& os, int8_t operand) {
        os.put(119);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& ja(std::ostream& os, int8_t operand) {
        os.put(119);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& js(std::ostream& os, int8_t operand) {
        os.put(120);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jns(std::ostream& os, int8_t operand) {
        os.put(121);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jp(std::ostream& os, int8_t operand) {
        os.put(122);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jpe(std::ostream& os, int8_t operand) {
        os.put(122);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnp(std::ostream& os, int8_t operand) {
        os.put(123);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jpo(std::ostream& os, int8_t operand) {
        os.put(123);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jl(std::ostream& os, int8_t operand) {
        os.put(124);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnge(std::ostream& os, int8_t operand) {
        os.put(124);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnl(std::ostream& os, int8_t operand) {
        os.put(125);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jge(std::ostream& os, int8_t operand) {
        os.put(125);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jle(std::ostream& os, int8_t operand) {
        os.put(126);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jng(std::ostream& os, int8_t operand) {
        os.put(126);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jnle(std::ostream& os, int8_t operand) {
        os.put(127);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& jg(std::ostream& os, int8_t operand) {
        os.put(127);
        os.put((int8_t)operand);
        return os;
    }

    std::ostream& inc(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((64 + (uint8_t)operand));
        return os;
    }

    std::ostream& inc(std::ostream& os, Reg32 operand) {
        if (((uint8_t)operand > 7))
        {
            os.put(65);
        }
        os.put((64 + (uint8_t)operand));
        return os;
    }

    std::ostream& dec(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((72 + (uint8_t)operand));
        return os;
    }

    std::ostream& dec(std::ostream& os, Reg32 operand) {
        if (((uint8_t)operand > 7))
        {
            os.put(65);
        }
        os.put((72 + (uint8_t)operand));
        return os;
    }

    std::ostream& push(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((80 + (uint8_t)operand));
        return os;
    }

    std::ostream& push(std::ostream& os, Reg32 operand) {
        if (((uint8_t)operand > 7))
        {
            os.put(65);
        }
        os.put((80 + (uint8_t)operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg16 operand) {
        os.put((102 + get_prefix(operand)));
        os.put((88 + (uint8_t)operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg32 operand) {
        if (((uint8_t)operand > 7))
        {
            os.put(65);
        }
        os.put((88 + (uint8_t)operand));
        return os;
    }

    std::ostream& pop(std::ostream& os, Reg64 operand) {
        os.put((72 + get_prefix(operand)));
        os.put((88 + (uint8_t)operand));
        return os;
    }

    std::ostream& add(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 0));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& or_(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 1));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 2));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 3));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& and_(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 4));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 5));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 6));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg8 reg, int8_t value) {
        os.put(128);
        os.put(((uint8_t)reg + 7));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 0));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 0));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 0));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 0));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& or_(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 1));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& or_(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 1));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& or_(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 1));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& or_(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 1));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 2));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 2));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 2));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 2));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 3));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 3));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 3));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 3));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 4));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 4));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 4));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& and_(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 4));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 5));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 5));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 5));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 5));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 6));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 6));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 6));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 6));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int16_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 7));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int32_t value) {
        os.put(102);
        os.put(129);
        os.put(((uint8_t)reg + 7));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int16_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 7));
        #if BIGENDIAN
        write_binary(os, swap16((int16_t)value), 2);
        #else
        write_binary(os, (int16_t)value, 2);
        #endif

        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int32_t value) {
        os.put(129);
        os.put(((uint8_t)reg + 7));
        #if BIGENDIAN
        write_binary(os, swap32((int32_t)value), 4);
        #else
        write_binary(os, (int32_t)value, 4);
        #endif

        return os;
    }

    std::ostream& add(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 0));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& add(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 0));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& or_(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 1));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& or_(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 1));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 2));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& adc(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 2));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 3));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sbb(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 3));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& and_(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 4));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& and_(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 4));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 5));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& sub(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 5));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 6));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& xor_(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 6));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg16 reg, int8_t value) {
        os.put(102);
        os.put(131);
        os.put(((uint8_t)reg + 7));
        os.put((int8_t)value);
        return os;
    }

    std::ostream& cmp(std::ostream& os, Reg32 reg, int8_t value) {
        os.put(131);
        os.put(((uint8_t)reg + 7));
        os.put((int8_t)value);
        return os;
    }

}
