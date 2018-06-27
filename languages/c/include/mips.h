// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 

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

void CALLCONV sll(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV movci(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV srl(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV sra(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV sllv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV srlv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV srav(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV jr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV jalr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV movz(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV movn(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV syscall(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV breakpoint(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV sync(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mfhi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mthi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mflo(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mfhi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((19 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsllv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsrlv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsrav(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mult(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV multu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV div(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV divu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dmult(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dmultu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV ddiv(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV ddivu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV add(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV addu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV subu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV or(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV xor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV nor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV slt(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV sltu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dadd(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV daddu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsub(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsubu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV tge(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV tgeu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV tlt(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV tltu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV teq(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV tne(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsll(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dslr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV dsra(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV mhc0(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
    *(byte*)buf += 4;
}

void CALLCONV btlz(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bgez(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bltzl(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bgezl(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV sllv(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV tgei(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV jalr(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV tlti(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV tltiu(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV teqi(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV tnei(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bltzal(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bgezal(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bltzall(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV bgezall(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV dsllv(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV synci(void** buf, Reg rs, uint16_t target) {
    *(uint32_t*)(*buf) = ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
    *(byte*)buf += 4;
}

void CALLCONV addi(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV addiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV andi(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV beq(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
    *(byte*)buf += 4;
}

void CALLCONV blez(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
    *(byte*)buf += 4;
}

void CALLCONV bne(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
    *(byte*)buf += 4;
}

void CALLCONV lw(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV lbu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV lhu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV lui(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV ori(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV sb(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV sh(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV slti(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV sltiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV sw(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
    *(byte*)buf += 4;
}

void CALLCONV j(void** buf, uint32_t address) {
    *(uint32_t*)(*buf) = (134217728 | ((address >> 2) & 67108863));
    *(byte*)buf += 4;
}

void CALLCONV jal(void** buf, uint32_t address) {
    *(uint32_t*)(*buf) = (201326592 | ((address >> 2) & 67108863));
    *(byte*)buf += 4;
}

