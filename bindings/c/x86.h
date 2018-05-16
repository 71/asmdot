// Automatically generated file.

#define byte unsigned char
#define bool _Bool
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)
int CALLCONV inc_r16(reg16 operand, void** buf);
int CALLCONV inc_r32(reg32 operand, void** buf);
int CALLCONV dec_r16(reg16 operand, void** buf);
int CALLCONV dec_r32(reg32 operand, void** buf);
int CALLCONV push_r16(reg16 operand, void** buf);
int CALLCONV push_r32(reg32 operand, void** buf);
int CALLCONV pop_r16(reg16 operand, void** buf);
int CALLCONV pop_r32(reg32 operand, void** buf);
int CALLCONV pop_r64(reg64 operand, void** buf);
int CALLCONV pushf(void** buf);
int CALLCONV popf(void** buf);
int CALLCONV ret(void** buf);
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
