// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 

inline uint16_t asm_swap16(uint16_t value) 
{
    return (value << 8) | (value >> 8);
}

inline uint32_t asm_swap32(uint32_t value)
{
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0xFF00FF); 
    return (value << 16) | (value >> 16);
}

inline uint64_t asm_swap64(uint64_t value)
{
    value = ((value << 8) & 0xFF00FF00FF00FF00ULL) | ((value >> 8) & 0x00FF00FF00FF00FFULL);
    value = ((value << 16) & 0xFFFF0000FFFF0000ULL) | ((value >> 16) & 0x0000FFFF0000FFFFULL);
    return (value << 32) | (value >> 32);
}

#define Reg uint8_t
#define Reg_Zero 0
#define Reg_AT 1
#define Reg_V0 2
#define Reg_V1 3
#define Reg_A0 4
#define Reg_A1 5
#define Reg_A2 6
#define Reg_A3 7
#define Reg_T0 8
#define Reg_T1 9
#define Reg_T2 10
#define Reg_T3 11
#define Reg_T4 12
#define Reg_T5 13
#define Reg_T6 14
#define Reg_T7 15
#define Reg_S0 16
#define Reg_S1 17
#define Reg_S2 18
#define Reg_S3 19
#define Reg_S4 20
#define Reg_S5 21
#define Reg_S6 22
#define Reg_S7 23
#define Reg_T8 24
#define Reg_T9 25
#define Reg_K0 26
#define Reg_K1 27
#define Reg_GP 28
#define Reg_SP 29
#define Reg_FP 30
#define Reg_RA 31

void CALLCONV mips_sll(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_movci(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_srl(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sra(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sllv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_srlv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_srav(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_jr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_jalr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_movz(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_movn(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_syscall(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_breakpoint(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sync(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mfhi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mthi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mflo(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mfhi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((19 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((19 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsllv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsrlv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsrav(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mult(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_multu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_div(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_divu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dmult(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dmultu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_ddiv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_ddivu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_add(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_addu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sub(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_subu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_and(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_or(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_xor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_nor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_slt(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sltu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dadd(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_daddu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsub(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsubu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tge(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tgeu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tlt(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tltu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_teq(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tne(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsll(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dslr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsra(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_mhc0(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)));
#else
    *(uint32_t*)(*buf) = ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_btlz(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bgez(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bltzl(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bgezl(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sllv(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tgei(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_jalr(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tlti(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tltiu(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_teqi(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_tnei(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bltzal(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bgezal(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bltzall(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bgezall(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_dsllv(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_synci(void** buf, Reg rs, uint16_t target) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)));
#else
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_addi(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_addiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_andi(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_beq(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
#else
    *(uint32_t*)(*buf) = (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_blez(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
#else
    *(uint32_t*)(*buf) = (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_bne(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)));
#else
    *(uint32_t*)(*buf) = (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_lw(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_lbu(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_lhu(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_lui(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_ori(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sb(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sh(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_slti(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sltiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_sw(void** buf, Reg rs, Reg rt, uint16_t imm) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)));
#else
    *(uint32_t*)(*buf) = (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_j(void** buf, uint32_t address) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((134217728 | ((address >> 2) & 67108863)));
#else
    *(uint32_t*)(*buf) = (134217728 | ((address >> 2) & 67108863));
#endif
    *(byte*)buf += 4;
}

void CALLCONV mips_jal(void** buf, uint32_t address) {
#if BIGENDIAN
    *(uint32_t*)(*buf) = asm_swap32((201326592 | ((address >> 2) & 67108863)));
#else
    *(uint32_t*)(*buf) = (201326592 | ((address >> 2) & 67108863));
#endif
    *(byte*)buf += 4;
}

