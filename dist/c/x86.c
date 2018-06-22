// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
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
void CALLCONV inc_r16(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV inc_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (64 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec_r16(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV dec_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (72 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push_r16(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV push_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (80 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r16(void** buf, Reg16 operand) {
    *(uint8_t*)(*buf) = (102 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r32(void** buf, Reg32 operand) {
    if ((operand > 7))
    {
        *(uint8_t*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

void CALLCONV pop_r64(void** buf, Reg64 operand) {
    *(uint8_t*)(*buf) = (72 + get_prefix(operand));
    *(byte*)buf += 1;
    *(uint8_t*)(*buf) = (88 + operand);
    *(byte*)buf += 1;
}

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

