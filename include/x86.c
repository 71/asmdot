
// Automatically generated file.
// Please see ../asm/{}.py for more informations.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
#define r_ax 0x0
#define r_cx 0x1
#define r_dx 0x2
#define r_bx 0x3
#define r_sp 0x4
#define r_bp 0x5
#define r_si 0x6
#define r_di 0x7
#define r_08 0x8
#define r_09 0x9
#define r_10 0xa
#define r_11 0xb
#define r_12 0xc
#define r_13 0xd
#define r_14 0xe
#define r_15 0xf
int inc_r16(reg16 operand, void** buf) {
    char offset = 0;
    *(unsigned char*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(unsigned char*)(*buf + offset) = 0x40 + operand;
    *(byte*)buf += 1;
    return offset;
}

int inc_r32(reg32 operand, void** buf) {
    char offset = 0;
    if ((operand > 7))
    {
        *(unsigned char*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(unsigned char*)(*buf + offset) = 0x40 + operand;
    *(byte*)buf += 1;
    return offset;
}

int dec_r16(reg16 operand, void** buf) {
    char offset = 0;
    *(unsigned char*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(unsigned char*)(*buf + offset) = 0x48 + operand;
    *(byte*)buf += 1;
    return offset;
}

int dec_r32(reg32 operand, void** buf) {
    char offset = 0;
    if ((operand > 7))
    {
        *(unsigned char*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(unsigned char*)(*buf + offset) = 0x48 + operand;
    *(byte*)buf += 1;
    return offset;
}

int push_r16(reg16 operand, void** buf) {
    char offset = 0;
    *(unsigned char*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(unsigned char*)(*buf + offset) = 0x50 + operand;
    *(byte*)buf += 1;
    return offset;
}

int push_r32(reg32 operand, void** buf) {
    char offset = 0;
    if ((operand > 7))
    {
        *(unsigned char*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(unsigned char*)(*buf + offset) = 0x50 + operand;
    *(byte*)buf += 1;
    return offset;
}

int pop_r16(reg16 operand, void** buf) {
    char offset = 0;
    *(unsigned char*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(unsigned char*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int pop_r32(reg32 operand, void** buf) {
    char offset = 0;
    if ((operand > 7))
    {
        *(unsigned char*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(unsigned char*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int pop_r64(reg64 operand, void** buf) {
    char offset = 0;
    *(unsigned char*)(*buf) = 0x48 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(unsigned char*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int pushf(void** buf) {
    *(unsigned char*)(*buf) = 156;
    *(byte*)buf += 1;
    return 1;
}

int popf(void** buf) {
    *(unsigned char*)(*buf) = 157;
    *(byte*)buf += 1;
    return 1;
}

int ret(void** buf) {
    *(unsigned char*)(*buf) = 195;
    *(byte*)buf += 1;
    return 1;
}

