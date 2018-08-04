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

        static const Reg8 AL;
        static const Reg8 CL;
        static const Reg8 DL;
        static const Reg8 BL;
        static const Reg8 SPL;
        static const Reg8 BPL;
        static const Reg8 SIL;
        static const Reg8 DIL;
        static const Reg8 R8B;
        static const Reg8 R9B;
        static const Reg8 R10B;
        static const Reg8 R11B;
        static const Reg8 R12B;
        static const Reg8 R13B;
        static const Reg8 R14B;
        static const Reg8 R15B;
    };

    const Reg8 Reg8::AL = 0;
    const Reg8 Reg8::CL = 1;
    const Reg8 Reg8::DL = 2;
    const Reg8 Reg8::BL = 3;
    const Reg8 Reg8::SPL = 4;
    const Reg8 Reg8::BPL = 5;
    const Reg8 Reg8::SIL = 6;
    const Reg8 Reg8::DIL = 7;
    const Reg8 Reg8::R8B = 8;
    const Reg8 Reg8::R9B = 9;
    const Reg8 Reg8::R10B = 10;
    const Reg8 Reg8::R11B = 11;
    const Reg8 Reg8::R12B = 12;
    const Reg8 Reg8::R13B = 13;
    const Reg8 Reg8::R14B = 14;
    const Reg8 Reg8::R15B = 15;

    ///
    /// An x86 16-bits register.
    struct Reg16 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg16, given its underlying value.
        Reg16(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg16 AX;
        static const Reg16 CX;
        static const Reg16 DX;
        static const Reg16 BX;
        static const Reg16 SP;
        static const Reg16 BP;
        static const Reg16 SI;
        static const Reg16 DI;
        static const Reg16 R8W;
        static const Reg16 R9W;
        static const Reg16 R10W;
        static const Reg16 R11W;
        static const Reg16 R12W;
        static const Reg16 R13W;
        static const Reg16 R14W;
        static const Reg16 R15W;
    };

    const Reg16 Reg16::AX = 0;
    const Reg16 Reg16::CX = 1;
    const Reg16 Reg16::DX = 2;
    const Reg16 Reg16::BX = 3;
    const Reg16 Reg16::SP = 4;
    const Reg16 Reg16::BP = 5;
    const Reg16 Reg16::SI = 6;
    const Reg16 Reg16::DI = 7;
    const Reg16 Reg16::R8W = 8;
    const Reg16 Reg16::R9W = 9;
    const Reg16 Reg16::R10W = 10;
    const Reg16 Reg16::R11W = 11;
    const Reg16 Reg16::R12W = 12;
    const Reg16 Reg16::R13W = 13;
    const Reg16 Reg16::R14W = 14;
    const Reg16 Reg16::R15W = 15;

    ///
    /// An x86 32-bits register.
    struct Reg32 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg32, given its underlying value.
        Reg32(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg32 EAX;
        static const Reg32 ECX;
        static const Reg32 EDX;
        static const Reg32 EBX;
        static const Reg32 ESP;
        static const Reg32 EBP;
        static const Reg32 ESI;
        static const Reg32 EDI;
        static const Reg32 R8D;
        static const Reg32 R9D;
        static const Reg32 R10D;
        static const Reg32 R11D;
        static const Reg32 R12D;
        static const Reg32 R13D;
        static const Reg32 R14D;
        static const Reg32 R15D;
    };

    const Reg32 Reg32::EAX = 0;
    const Reg32 Reg32::ECX = 1;
    const Reg32 Reg32::EDX = 2;
    const Reg32 Reg32::EBX = 3;
    const Reg32 Reg32::ESP = 4;
    const Reg32 Reg32::EBP = 5;
    const Reg32 Reg32::ESI = 6;
    const Reg32 Reg32::EDI = 7;
    const Reg32 Reg32::R8D = 8;
    const Reg32 Reg32::R9D = 9;
    const Reg32 Reg32::R10D = 10;
    const Reg32 Reg32::R11D = 11;
    const Reg32 Reg32::R12D = 12;
    const Reg32 Reg32::R13D = 13;
    const Reg32 Reg32::R14D = 14;
    const Reg32 Reg32::R15D = 15;

    ///
    /// An x86 64-bits register.
    struct Reg64 {
        /// Underlying value.
        uint8_t value;

        /// Creates a new Reg64, given its underlying value.
        Reg64(const uint8_t underlyingValue) : value(underlyingValue) {}

        /// Converts the wrapper to its underlying value.
        operator uint8_t() { return value; }

        static const Reg64 RAX;
        static const Reg64 RCX;
        static const Reg64 RDX;
        static const Reg64 RBX;
        static const Reg64 RSP;
        static const Reg64 RBP;
        static const Reg64 RSI;
        static const Reg64 RDI;
        static const Reg64 R8;
        static const Reg64 R9;
        static const Reg64 R10;
        static const Reg64 R11;
        static const Reg64 R12;
        static const Reg64 R13;
        static const Reg64 R14;
        static const Reg64 R15;
    };

    const Reg64 Reg64::RAX = 0;
    const Reg64 Reg64::RCX = 1;
    const Reg64 Reg64::RDX = 2;
    const Reg64 Reg64::RBX = 3;
    const Reg64 Reg64::RSP = 4;
    const Reg64 Reg64::RBP = 5;
    const Reg64 Reg64::RSI = 6;
    const Reg64 Reg64::RDI = 7;
    const Reg64 Reg64::R8 = 8;
    const Reg64 Reg64::R9 = 9;
    const Reg64 Reg64::R10 = 10;
    const Reg64 Reg64::R11 = 11;
    const Reg64 Reg64::R12 = 12;
    const Reg64 Reg64::R13 = 13;
    const Reg64 Reg64::R14 = 14;
    const Reg64 Reg64::R15 = 15;

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
