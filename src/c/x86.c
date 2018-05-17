// Automatically generated file.

#include <stdint.h>

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)

#ifndef uint32
#define uint32 unsigned int
#endif

#ifndef int32
#define int32 int
#endif

#ifndef int8
#define int8 char
#endif

#ifndef uint8
#define uint8 unsigned char
#endif
void CALLCONV inc_r16(void** buf, reg16 operand) {
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf) = 0x40 + operand;
    *(byte*)buf += 1;
}

void CALLCONV inc_r32(void** buf, reg32 operand) {
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf) = 0x40 + operand;
    *(byte*)buf += 1;
}

void CALLCONV dec_r16(void** buf, reg16 operand) {
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf) = 0x48 + operand;
    *(byte*)buf += 1;
}

void CALLCONV dec_r32(void** buf, reg32 operand) {
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf) = 0x48 + operand;
    *(byte*)buf += 1;
}

void CALLCONV push_r16(void** buf, reg16 operand) {
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf) = 0x50 + operand;
    *(byte*)buf += 1;
}

void CALLCONV push_r32(void** buf, reg32 operand) {
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf) = 0x50 + operand;
    *(byte*)buf += 1;
}

void CALLCONV pop_r16(void** buf, reg16 operand) {
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf) = 0x58 + operand;
    *(byte*)buf += 1;
}

void CALLCONV pop_r32(void** buf, reg32 operand) {
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf) = 0x58 + operand;
    *(byte*)buf += 1;
}

void CALLCONV pop_r64(void** buf, reg64 operand) {
    *(byte*)(*buf) = 0x48 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf) = 0x58 + operand;
    *(byte*)buf += 1;
}

void CALLCONV pushf(void** buf) {
    *(byte*)(*buf) = 156;
    *(byte*)buf += 1;
}

void CALLCONV popf(void** buf) {
    *(byte*)(*buf) = 157;
    *(byte*)buf += 1;
}

void CALLCONV ret(void** buf) {
    *(byte*)(*buf) = 195;
    *(byte*)buf += 1;
}


#define ax 0x0
#define cx 0x1
#define dx 0x2
#define bx 0x3
#define sp 0x4
#define bp 0x5
#define si 0x6
#define di 0x7
#define r8 0x8
#define r9 0x9
#define r10 0xa
#define r11 0xb
#define r12 0xc
#define r13 0xd
#define r14 0xe
#define r15 0xf
