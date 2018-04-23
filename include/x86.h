
// Automatically generated file.
// Please see ../asm/x86.py for more informations.

#define byte unsigned char
#define bool boolean
#define RET(x) return x
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 ? 1 : 0)

int CALLCONV inc_r16(/* register */ reg16 operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x40 + operand;
  RET(1);
}

int CALLCONV inc_r32(/* register */ reg32 operand, void** buf) {
  *(byte*)(buf++) = 0x40 + operand;
  RET(1);
}

int CALLCONV dec_r16(/* register */ reg16 operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x48 + operand;
  RET(1);
}

int CALLCONV dec_r32(/* register */ reg32 operand, void** buf) {
  *(byte*)(buf++) = 0x48 + operand;
  RET(1);
}

int CALLCONV push_r16(/* register */ reg16 operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x50 + operand;
  RET(1);
}

int CALLCONV push_r32(/* register */ reg32 operand, void** buf) {
  *(byte*)(buf++) = 0x50 + operand;
  RET(1);
}

int CALLCONV pop_r16(/* register */ reg16 operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x58 + operand;
  RET(1);
}

int CALLCONV pop_r32(/* register */ reg32 operand, void** buf) {
  *(byte*)(buf++) = 0x58 + operand;
  RET(1);
}

int CALLCONV pop_r64(/* register */ reg64 operand, void** buf) {
  #if !NO64BITS_PREFIX
  *(byte*)(buf++) = 0x48 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x58 + operand;
  RET(1);
}

int CALLCONV pushf(void** buf) {
  *(byte*)(buf++) = 0x9c;
  RET(1);
}

int CALLCONV popf(void** buf) {
  *(byte*)(buf++) = 0x9d;
  RET(1);
}

int CALLCONV ret(void** buf) {
  *(byte*)(buf++) = 0xc3;
  RET(1);
}

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
