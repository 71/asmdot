// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
int CALLCONV inc_r16(reg16 operand, void** buf) {
    int8 offset = 0;
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf + offset) = 0x40 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV inc_r32(reg32 operand, void** buf) {
    int8 offset = 0;
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf + offset) = 0x40 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV dec_r16(reg16 operand, void** buf) {
    int8 offset = 0;
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf + offset) = 0x48 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV dec_r32(reg32 operand, void** buf) {
    int8 offset = 0;
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf + offset) = 0x48 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV push_r16(reg16 operand, void** buf) {
    int8 offset = 0;
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf + offset) = 0x50 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV push_r32(reg32 operand, void** buf) {
    int8 offset = 0;
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf + offset) = 0x50 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV pop_r16(reg16 operand, void** buf) {
    int8 offset = 0;
    *(byte*)(*buf) = 0x66 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV pop_r32(reg32 operand, void** buf) {
    int8 offset = 0;
    if ((operand > 7))
    {
        *(byte*)(*buf) = 65;
        *(byte*)buf += 1;
    }
    *(byte*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV pop_r64(reg64 operand, void** buf) {
    int8 offset = 0;
    *(byte*)(*buf) = 0x48 + prefix_adder(operand);
    *(byte*)buf += 1;
    *(byte*)(*buf + offset) = 0x58 + operand;
    *(byte*)buf += 1;
    return offset;
}

int CALLCONV pushf(void** buf) {
    *(byte*)(*buf) = 156;
    *(byte*)buf += 1;
    return 1;
}

int CALLCONV popf(void** buf) {
    *(byte*)(*buf) = 157;
    *(byte*)buf += 1;
    return 1;
}

int CALLCONV ret(void** buf) {
    *(byte*)(*buf) = 195;
    *(byte*)buf += 1;
    return 1;
}

#define ax 0x0
#define cx 0x1
#define dx 0x2
#define bx 0x3
#define sp 0x4
#define bp 0x5
#define si 0x6
#define di 0x7
#define 08 0x8
#define 09 0x9
#define 10 0xa
#define 11 0xb
#define 12 0xc
#define 13 0xd
#define 14 0xe
#define 15 0xf
