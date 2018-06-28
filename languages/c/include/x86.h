// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 

inline uint16_t asm_swapu16(uint16_t value) 
{
    return (value << 8) | (value >> 8);
}

inline int16_t asm_swapi16(int16_t value) 
{
    return (value << 8) | ((value >> 8) & 0xFF);
}

inline uint32_t asm_swapu32(uint32_t value)
{
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
    return (value << 16) | (value >> 16);
}

inline int32_t asm_swapi32(int32_t value)
{
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
    return (value << 16) | ((value >> 16) & 0xFFFF);
}

inline uint64_t asm_swapu64(uint64_t value)
{
    value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
    value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
    return (value << 32) | (value >> 32);
}

inline int64_t asm_swapi64(int64_t value)
{
    value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
    value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
    return (value << 32) | ((value >> 32) & 0xFFFFFFFFULL);
}

#ifdef BIGENDIAN
#define asm_be_

#define get_prefix(r) (r > 7 && (r -= 8) == r)

#define Reg8 uint8_t
#define Reg8_al 0
#define Reg8_cl 1
#define Reg8_dl 2
#define Reg8_bl 3
#define Reg8_spl 4
#define Reg8_bpl 5
#define Reg8_sil 6
#define Reg8_dil 7
#define Reg8_r8b 8
#define Reg8_r9b 9
#define Reg8_r10b 10
#define Reg8_r11b 11
#define Reg8_r12b 12
#define Reg8_r13b 13
#define Reg8_r14b 14
#define Reg8_r15b 15
#define Reg16 uint8_t
#define Reg16_ax 0
#define Reg16_cx 1
#define Reg16_dx 2
#define Reg16_bx 3
#define Reg16_sp 4
#define Reg16_bp 5
#define Reg16_si 6
#define Reg16_di 7
#define Reg16_r8w 8
#define Reg16_r9w 9
#define Reg16_r10w 10
#define Reg16_r11w 11
#define Reg16_r12w 12
#define Reg16_r13w 13
#define Reg16_r14w 14
#define Reg16_r15w 15
#define Reg32 uint8_t
#define Reg32_eax 0
#define Reg32_ecx 1
#define Reg32_edx 2
#define Reg32_ebx 3
#define Reg32_esp 4
#define Reg32_ebp 5
#define Reg32_esi 6
#define Reg32_edi 7
#define Reg32_r8d 8
#define Reg32_r9d 9
#define Reg32_r10d 10
#define Reg32_r11d 11
#define Reg32_r12d 12
#define Reg32_r13d 13
#define Reg32_r14d 14
#define Reg32_r15d 15
#define Reg64 uint8_t
#define Reg64_rax 0
#define Reg64_rcx 1
#define Reg64_rdx 2
#define Reg64_rbx 3
#define Reg64_rsp 4
#define Reg64_rbp 5
#define Reg64_rsi 6
#define Reg64_rdi 7
#define Reg64_r8 8
#define Reg64_r9 9
#define Reg64_r10 10
#define Reg64_r11 11
#define Reg64_r12 12
#define Reg64_r13 13
#define Reg64_r14 14
#define Reg64_r15 15
#define Reg128 uint8_t

void CALLCONV pushf(void** buf) {
    *(uint8_t*)buf = 156;
    *(byte*)buf += 1;
}

void CALLCONV popf(void** buf) {
    *(uint8_t*)buf = 157;
    *(byte*)buf += 1;
}

void CALLCONV ret(void** buf) {
    *(uint8_t*)buf = 195;
    *(byte*)buf += 1;
}

void CALLCONV clc(void** buf) {
    *(uint8_t*)buf = 248;
    *(byte*)buf += 1;
}

void CALLCONV stc(void** buf) {
    *(uint8_t*)buf = 249;
    *(byte*)buf += 1;
}

void CALLCONV cli(void** buf) {
    *(uint8_t*)buf = 250;
    *(byte*)buf += 1;
}

void CALLCONV sti(void** buf) {
    *(uint8_t*)buf = 251;
    *(byte*)buf += 1;
}

void CALLCONV cld(void** buf) {
    *(uint8_t*)buf = 252;
    *(byte*)buf += 1;
}

void CALLCONV std(void** buf) {
    *(uint8_t*)buf = 253;
    *(byte*)buf += 1;
}

void CALLCONV jo_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 112;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jno_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 113;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jb_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnae_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jc_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnb_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jae_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnc_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jz_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 116;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV je_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 116;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnz_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 117;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jne_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 117;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jbe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 118;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jna_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 118;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnbe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 119;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV ja_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 119;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV js_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 120;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jns_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 121;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jp_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 122;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jpe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 122;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnp_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 123;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jpo_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 123;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jl_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 124;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnge_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 124;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnl_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 125;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jge_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 125;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jle_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 126;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jng_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 126;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnle_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 127;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV jg_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 127;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV inc_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV inc_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r64(void** buf, Reg64 operand) {
    *(uint8_t*)buf = (72 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV add_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV or_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV adc_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV and_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sub_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV xor_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV add_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV add_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV add_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV add_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV or_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV or_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV or_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV or_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV adc_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV adc_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV adc_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV adc_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV sbb_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV sbb_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV sbb_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV sbb_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV and_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV and_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV and_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV and_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV sub_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV sub_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV sub_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV sub_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV xor_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV xor_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV xor_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV xor_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV cmp_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV cmp_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV cmp_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swapi16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV cmp_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swapi32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV add_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV add_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV or_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV or_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV adc_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV adc_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV and_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV and_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sub_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV sub_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV xor_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV xor_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

