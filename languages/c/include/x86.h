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

void CALLCONV pushf(void** buf) {
    *(uint8_t*)(*buf) = 156;
    *(byte*)buf += 1;
}

void CALLCONV popf(void** buf) {
    *(uint8_t*)(*buf) = 157;
    *(byte*)buf += 1;
}

void CALLCONV ret(void** buf) {
    *(uint8_t*)(*buf) = 195;
    *(byte*)buf += 1;
}

void CALLCONV clc(void** buf) {
    *(uint8_t*)(*buf) = 248;
    *(byte*)buf += 1;
}

void CALLCONV stc(void** buf) {
    *(uint8_t*)(*buf) = 249;
    *(byte*)buf += 1;
}

void CALLCONV cli(void** buf) {
    *(uint8_t*)(*buf) = 250;
    *(byte*)buf += 1;
}

void CALLCONV sti(void** buf) {
    *(uint8_t*)(*buf) = 251;
    *(byte*)buf += 1;
}

void CALLCONV cld(void** buf) {
    *(uint8_t*)(*buf) = 252;
    *(byte*)buf += 1;
}

void CALLCONV std(void** buf) {
    *(uint8_t*)(*buf) = 253;
    *(byte*)buf += 1;
}

void CALLCONV jo(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 112;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jno(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 113;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jb(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnae(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jc(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 114;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnb(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jae(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnc(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 115;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jz(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 116;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV je(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 116;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnz(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 117;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jne(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 117;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jbe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 118;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jna(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 118;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnbe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 119;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV ja(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 119;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV js(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 120;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jns(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 121;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jp(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 122;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jpe(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 122;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnp(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 123;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jpo(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 123;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jl(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 124;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnge(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 124;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnl(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 125;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jge(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 125;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jle(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 126;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jng(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 126;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jnle(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 127;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV jg(void** buf, int8_t operand) {
    *(uint8_t*)(*buf) = 127;
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = operand;
    *(byte*)buf += 1;
}

void CALLCONV inc(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV inc(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop(void** buf, Reg64 operand) {
    *(uint8_t*)(*buf) = (72 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV add(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV or(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV adc(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV and(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sub(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV xor(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp(void** buf, Reg8 reg, int8_t value) {
    *(uint8_t*)(*buf) = 128;
    *(byte*)buf += 1;
    *(Reg8*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV add(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV add(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV add(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV add(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV or(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV or(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV or(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV or(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV adc(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV adc(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV adc(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV adc(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV sbb(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV sbb(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV sbb(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV sbb(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV and(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV and(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV sub(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV sub(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV xor(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV xor(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV xor(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV xor(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV cmp(void** buf, Reg16 reg, int16_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV cmp(void** buf, Reg16 reg, int32_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV cmp(void** buf, Reg32 reg, int16_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int16_t*)(*buf) = value;
    *(byte*)buf += 2;
}

void CALLCONV cmp(void** buf, Reg32 reg, int32_t value) {
    *(uint8_t*)(*buf) = 129;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int32_t*)(*buf) = value;
    *(byte*)buf += 4;
}

void CALLCONV add(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV add(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 0);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV or(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV or(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 1);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV adc(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV adc(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 2);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sbb(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 3);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV and(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV and(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 4);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sub(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV sub(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 5);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV xor(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV xor(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 6);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp(void** buf, Reg16 reg, int8_t value) {
    *(uint8_t*)(*buf) = 102;
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg16*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

void CALLCONV cmp(void** buf, Reg32 reg, int8_t value) {
    *(uint8_t*)(*buf) = 131;
    *(byte*)buf += 1;
    *(Reg32*)(*buf) = (reg + 7);
    *(byte*)buf += 1;
    *(int8_t*)(*buf) = value;
    *(byte*)buf += 1;
}

