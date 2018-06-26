// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 

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
    *(uint8_t*)(*buf) = 156;
    *(byte*)buf += 1;
}

void CALLCONV x86_popf(void** buf) {
    *(uint8_t*)(*buf) = 157;
    *(byte*)buf += 1;
}

void CALLCONV x86_ret(void** buf) {
    *(uint8_t*)(*buf) = 195;
    *(byte*)buf += 1;
}

void CALLCONV x86_clc(void** buf) {
    *(uint8_t*)(*buf) = 248;
    *(byte*)buf += 1;
}

void CALLCONV x86_stc(void** buf) {
    *(uint8_t*)(*buf) = 249;
    *(byte*)buf += 1;
}

void CALLCONV x86_cli(void** buf) {
    *(uint8_t*)(*buf) = 250;
    *(byte*)buf += 1;
}

void CALLCONV x86_sti(void** buf) {
    *(uint8_t*)(*buf) = 251;
    *(byte*)buf += 1;
}

void CALLCONV x86_cld(void** buf) {
    *(uint8_t*)(*buf) = 252;
    *(byte*)buf += 1;
}

void CALLCONV x86_std(void** buf) {
    *(uint8_t*)(*buf) = 253;
    *(byte*)buf += 1;
}

void CALLCONV x86_jo(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 112;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jno(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 113;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jb(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnae(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jc(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnb(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jae(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnc(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jz(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 116;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_je(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 116;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnz(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 117;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jne(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 117;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jbe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 118;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jna(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 118;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnbe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 119;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_ja(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 119;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_js(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 120;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jns(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 121;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jp(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 122;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jpe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 122;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnp(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 123;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jpo(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 123;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jl(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 124;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnge(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 124;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnl(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 125;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jge(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 125;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jle(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 126;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jng(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 126;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jnle(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 127;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_jg(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 127;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV x86_inc(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_inc(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_dec(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_dec(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_push(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_push(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_pop(void** buf, Reg64 operand) {
    *(uint8_t*)(*buf) = (72 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV x86_add(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_add(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_add(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_add(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_add(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_or(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_or(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_or(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_or(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_adc(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_adc(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_adc(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_adc(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_sbb(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_sbb(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_sbb(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_sbb(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_and(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_and(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_and(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_and(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_sub(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_sub(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_sub(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_sub(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_xor(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_xor(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_xor(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_xor(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_cmp(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_cmp(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_cmp(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV x86_cmp(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV x86_add(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_add(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_or(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_adc(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sbb(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_and(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_sub(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_xor(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV x86_cmp(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

