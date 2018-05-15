// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
int inc_r16(reg16 operand, void* buf);
int inc_r32(reg32 operand, void* buf);
int dec_r16(reg16 operand, void* buf);
int dec_r32(reg32 operand, void* buf);
int push_r16(reg16 operand, void* buf);
int push_r32(reg32 operand, void* buf);
int pop_r16(reg16 operand, void* buf);
int pop_r32(reg32 operand, void* buf);
int pop_r64(reg64 operand, void* buf);
int pushf(void* buf);
int popf(void* buf);
int ret(void* buf);
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
