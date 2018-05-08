
// Automatically generated file.
// Please see ../asm/x86.py for more informations.

#define byte unsigned char
#define bool _Bool
#define RET(x) return x
#define CALLCONV 


#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)

int CALLCONV inc_r16(/* register */ reg16 operand, void** buf) {
  void* initaddr = *buf;
  #if !NO16BITS_PREFIX
  *(byte*)((*buf)++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)((*buf)++) = 0x40 + operand;
  RET(*buf - initaddr);
}

int CALLCONV inc_r16_r32(/* register */ reg32 operand, void** buf) {
  void* initaddr = *buf;
  if (operand > 7) *(byte*)((*buf)++) = 0x41;
  *(byte*)((*buf)++) = 0x40 + operand;
  RET(*buf - initaddr);
}

int CALLCONV dec_r16(/* register */ reg16 operand, void** buf) {
  void* initaddr = *buf;
  #if !NO16BITS_PREFIX
  *(byte*)((*buf)++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)((*buf)++) = 0x48 + operand;
  RET(*buf - initaddr);
}

int CALLCONV dec_r16_r32(/* register */ reg32 operand, void** buf) {
  void* initaddr = *buf;
  if (operand > 7) *(byte*)((*buf)++) = 0x41;
  *(byte*)((*buf)++) = 0x48 + operand;
  RET(*buf - initaddr);
}

int CALLCONV push_r16(/* register */ reg16 operand, void** buf) {
  void* initaddr = *buf;
  #if !NO16BITS_PREFIX
  *(byte*)((*buf)++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)((*buf)++) = 0x50 + operand;
  RET(*buf - initaddr);
}

int CALLCONV push_r16_r32(/* register */ reg32 operand, void** buf) {
  void* initaddr = *buf;
  if (operand > 7) *(byte*)((*buf)++) = 0x41;
  *(byte*)((*buf)++) = 0x50 + operand;
  RET(*buf - initaddr);
}

int CALLCONV pop_r16(/* register */ reg16 operand, void** buf) {
  void* initaddr = *buf;
  #if !NO16BITS_PREFIX
  *(byte*)((*buf)++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)((*buf)++) = 0x58 + operand;
  RET(*buf - initaddr);
}

int CALLCONV pop_r16_r32(/* register */ reg32 operand, void** buf) {
  void* initaddr = *buf;
  if (operand > 7) *(byte*)((*buf)++) = 0x41;
  *(byte*)((*buf)++) = 0x58 + operand;
  RET(*buf - initaddr);
}

int CALLCONV pop_r16_r32_r64(/* register */ reg64 operand, void** buf) {
  void* initaddr = *buf;
  #if !NO64BITS_PREFIX
  *(byte*)((*buf)++) = 0x48 + prefix_adder(operand);
  #endif
  *(byte*)((*buf)++) = 0x58 + operand;
  RET(*buf - initaddr);
}

int CALLCONV pushf(void** buf) {
  void* initaddr = *buf;
  *(byte*)((*buf)++) = 0x9c;
  RET(*buf - initaddr);
}

int CALLCONV popf(void** buf) {
  void* initaddr = *buf;
  *(byte*)((*buf)++) = 0x9d;
  RET(*buf - initaddr);
}

int CALLCONV ret(void** buf) {
  void* initaddr = *buf;
  *(byte*)((*buf)++) = 0xc3;
  RET(*buf - initaddr);
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
