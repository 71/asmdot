
// Automatically generated file.
// Please see ../asm/x86.py for more informations.

#define byte unsigned char
#define bool boolean
#define RET(x) return x
#define CALLCONV 


#define reg byte
#define prefix_adder(r) (r > 7 ? 1 : 0)

int CALLCONV inc_r16(/* register */ reg operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x40 + operand;
  RET(1);
}

int CALLCONV inc_r32(/* register */ reg operand, void** buf) {
  *(byte*)(buf++) = 0x40 + operand;
  RET(1);
}

int CALLCONV dec_r16(/* register */ reg operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x48 + operand;
  RET(1);
}

int CALLCONV dec_r32(/* register */ reg operand, void** buf) {
  *(byte*)(buf++) = 0x48 + operand;
  RET(1);
}

int CALLCONV push_r16(/* register */ reg operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x50 + operand;
  RET(1);
}

int CALLCONV push_r32(/* register */ reg operand, void** buf) {
  *(byte*)(buf++) = 0x50 + operand;
  RET(1);
}

int CALLCONV pop_r16(/* register */ reg operand, void** buf) {
  #if !NO16BITS_PREFIX
  *(byte*)(buf++) = 0x66 + prefix_adder(operand);
  #endif
  *(byte*)(buf++) = 0x58 + operand;
  RET(1);
}

int CALLCONV pop_r32(/* register */ reg operand, void** buf) {
  *(byte*)(buf++) = 0x58 + operand;
  RET(1);
}

int CALLCONV pop_r64(/* register */ reg operand, void** buf) {
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

#define r_ax 0x00
#define r_cx 0x01
#define r_dx 0x02
#define r_bx 0x03
#define r_sp 0x04
#define r_bp 0x05
#define r_si 0x06
#define r_di 0x07
#define r_08 0x08
#define r_09 0x09
#define r_10 0x0a
#define r_11 0x0b
#define r_12 0x0c
#define r_13 0x0d
#define r_14 0x0e
#define r_15 0x0f
