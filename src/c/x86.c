// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
int inc_r16(reg16 operand, void* buf) {
    int8 offset = 0;
    *(byte*)(buf) = 0x66 + prefix_adder(operand);
    offset += 1;
    *(byte*)(buf + offset) = 0x40 + operand;
    offset += 1;
    return offset;
}

int inc_r32(reg32 operand, void* buf) {
    int8 offset = 0;
    if ((operand > 7))

    {
        *(byte*)(buf) = 65;
        offset += 1;
    }
    *(byte*)(buf + offset) = 0x40 + operand;
    offset += 1;
    return offset;
}

int dec_r16(reg16 operand, void* buf) {
    int8 offset = 0;
    *(byte*)(buf) = 0x66 + prefix_adder(operand);
    offset += 1;
    *(byte*)(buf + offset) = 0x48 + operand;
    offset += 1;
    return offset;
}

int dec_r32(reg32 operand, void* buf) {
    int8 offset = 0;
    if ((operand > 7))

    {
        *(byte*)(buf) = 65;
        offset += 1;
    }
    *(byte*)(buf + offset) = 0x48 + operand;
    offset += 1;
    return offset;
}

int push_r16(reg16 operand, void* buf) {
    int8 offset = 0;
    *(byte*)(buf) = 0x66 + prefix_adder(operand);
    offset += 1;
    *(byte*)(buf + offset) = 0x50 + operand;
    offset += 1;
    return offset;
}

int push_r32(reg32 operand, void* buf) {
    int8 offset = 0;
    if ((operand > 7))

    {
        *(byte*)(buf) = 65;
        offset += 1;
    }
    *(byte*)(buf + offset) = 0x50 + operand;
    offset += 1;
    return offset;
}

int pop_r16(reg16 operand, void* buf) {
    int8 offset = 0;
    *(byte*)(buf) = 0x66 + prefix_adder(operand);
    offset += 1;
    *(byte*)(buf + offset) = 0x58 + operand;
    offset += 1;
    return offset;
}

int pop_r32(reg32 operand, void* buf) {
    int8 offset = 0;
    if ((operand > 7))

    {
        *(byte*)(buf) = 65;
        offset += 1;
    }
    *(byte*)(buf + offset) = 0x58 + operand;
    offset += 1;
    return offset;
}

int pop_r64(reg64 operand, void* buf) {
    int8 offset = 0;
    *(byte*)(buf) = 0x48 + prefix_adder(operand);
    offset += 1;
    *(byte*)(buf + offset) = 0x58 + operand;
    offset += 1;
    return offset;
}

int pushf(void* buf) {
    *(byte*)(buf) = 156;
    return 1;
}

int popf(void* buf) {
    *(byte*)(buf) = 157;
    return 1;
}

int ret(void* buf) {
    *(byte*)(buf) = 195;
    return 1;
}

#define rax 0x0
#define rcx 0x1
#define rdx 0x2
#define rbx 0x3
#define rsp 0x4
#define rbp 0x5
#define rsi 0x6
#define rdi 0x7
#define r08 0x8
#define r09 0x9
#define r10 0xa
#define r11 0xb
#define r12 0xc
#define r13 0xd
#define r14 0xe
#define r15 0xf
