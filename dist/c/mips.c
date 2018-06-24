// Automatically generated file.

#include <assert.h>
#include <stdint.h>

#define byte uint8_t
#define bool _Bool
#define CALLCONV 



#define reg byte

#define Reg uint8_t
#define Reg_zero 0
#define Reg_at 1
#define Reg_v0 2
#define Reg_v1 3
#define Reg_a0 4
#define Reg_a1 5
#define Reg_a2 6
#define Reg_a3 7
#define Reg_t0 8
#define Reg_t1 9
#define Reg_t2 10
#define Reg_t3 11
#define Reg_t4 12
#define Reg_t5 13
#define Reg_t6 14
#define Reg_t7 15
#define Reg_s0 16
#define Reg_s1 17
#define Reg_s2 18
#define Reg_s3 19
#define Reg_s4 20
#define Reg_s5 21
#define Reg_s6 22
#define Reg_s7 23
#define Reg_t8 24
#define Reg_t9 25
#define Reg_k0 26
#define Reg_k1 27
#define Reg_gp 28
#define Reg_sp 29
#define Reg_fp 30
#define Reg_ra 31
void CALLCONV add(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((32 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV addu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((33 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV and(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((36 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV div(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((26 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV divu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((27 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV jr(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((8 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV mfhi(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((16 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV mflo(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((18 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV mhc0(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((1073741824 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV mult(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((24 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV multu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((25 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV nor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((39 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV xor(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((38 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV or(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((37 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV slt(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((42 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV sltu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((43 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV sll(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((0 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV srl(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((2 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV sra(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((3 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV sub(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((34 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV subu(void** buf, Reg rd, Reg rs, Reg rt, uint8_t shift) {
    *(uint32_t*)(*buf) = ((((35 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6));
    *(byte*)buf += 4;
}

void CALLCONV addi(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((536870912 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV addiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((603979776 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV andi(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((805306368 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV beq(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((268435456 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV blez(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((402653184 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV bne(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((335544320 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV lbu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2415919104 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV lhu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2483027968 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV lui(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((1006632960 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV ori(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((872415232 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV sb(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2684354560 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV sh(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2751463424 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV slti(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((671088640 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV sltiu(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((738197504 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV sw(void** buf, Reg rs, Reg rt, uint16_t imm) {
    *(uint32_t*)(*buf) = (((2885681152 | (rs << 21)) | (rt << 16)) | imm);
    *(byte*)buf += 4;
}

void CALLCONV j(void** buf, uint32_t addr) {
    *(uint32_t*)(*buf) = (2885681152 | (67108863 & (addr << 2)));
    *(byte*)buf += 4;
}

void CALLCONV jal(void** buf, uint32_t addr) {
    *(uint32_t*)(*buf) = (2885681152 | (67108863 & (addr << 2)));
    *(byte*)buf += 4;
}

