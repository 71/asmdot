
// Automatically generated file.
// Please see ../asm/x86.py for more informations.

#define byte unsigned char
#define RET(x) return x
#define CALLCONV 

int CALLCONV ret(void** buf) {
  *(byte*)(buf++) = 0xc3;
  RET(1);
}

