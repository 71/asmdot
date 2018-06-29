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

void CALLCONV x86_pushf(void** buf) {
    *(uint8_t*)buf = 156;
    *(byte*)buf += 1;
}

void CALLCONV x86_popf(void** buf) {
    *(uint8_t*)buf = 157;
    *(byte*)buf += 1;
}

void CALLCONV x86_ret(void** buf) {
    *(uint8_t*)buf = 195;
    *(byte*)buf += 1;
}

void CALLCONV x86_clc(void** buf) {
    *(uint8_t*)buf = 248;
    *(byte*)buf += 1;
}

void CALLCONV x86_stc(void** buf) {
    *(uint8_t*)buf = 249;
    *(byte*)buf += 1;
}

void CALLCONV x86_cli(void** buf) {
    *(uint8_t*)buf = 250;
    *(byte*)buf += 1;
}

void CALLCONV x86_sti(void** buf) {
    *(uint8_t*)buf = 251;
    *(byte*)buf += 1;
}

void CALLCONV x86_cld(void** buf) {
    *(uint8_t*)buf = 252;
    *(byte*)buf += 1;
}

void CALLCONV x86_std(void** buf) {
    *(uint8_t*)buf = 253;
    *(byte*)buf += 1;
}

void CALLCONV x86_jo_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 112;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jno_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 113;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jb_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnae_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jc_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 114;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnb_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jae_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnc_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 115;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jz_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 116;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_je_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 116;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnz_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 117;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jne_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 117;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jbe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 118;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jna_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 118;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnbe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 119;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_ja_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 119;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_js_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 120;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jns_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 121;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jp_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 122;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jpe_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 122;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnp_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 123;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jpo_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 123;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jl_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 124;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnge_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 124;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnl_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 125;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jge_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 125;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jle_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 126;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jng_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 126;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnle_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 127;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jg_imm8(void** buf, int8_t operand) {
    *(uint8_t*)buf = 127;
    *(byte*)buf += 1;
    *(uint8_t*)buf = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_inc_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_inc_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_dec_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_dec_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_push_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_push_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop_r16(void** buf, Reg16 operand) {
    *(uint8_t*)buf = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)buf = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop_r64(void** buf, Reg64 operand) {
    *(uint8_t*)buf = (72 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)buf = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_add_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp_rm8_imm8(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)buf = 128;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_add_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_add_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_add_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_add_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_or_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_or_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_or_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_or_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_adc_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_adc_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_adc_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_adc_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_sbb_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_sbb_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_sbb_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_sbb_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_and_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_and_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_and_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_and_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_sub_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_sub_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_sub_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_sub_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_xor_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_xor_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_xor_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_xor_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_cmp_rm16_imm16(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_cmp_rm16_imm32(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_cmp_rm32_imm16(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int16_t*)(*buf) = asm_swap16(value);
#else
    *(int16_t*)(*buf) = value;
#endif
    *(byte*)buf += 2;
}

void CALLCONV x86_cmp_rm32_imm32(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)buf = 129;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
#if BIGENDIAN
    *(int32_t*)(*buf) = asm_swap32(value);
#else
    *(int32_t*)(*buf) = value;
#endif
    *(byte*)buf += 4;
}

void CALLCONV x86_add_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_add_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 0);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 1);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 2);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 3);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 4);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 5);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 6);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp_rm16_imm8(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)buf = 102;
    *(byte*)buf += 1;
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp_rm32_imm8(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)buf = 131;
    *(byte*)buf += 1;
    *(uint8_t*)buf = (reg + 7);
    *(byte*)buf += 1;
    *(uint8_t*)buf = value;
    *(byte*)buf += 1;
}

