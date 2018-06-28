// An x86 8-bits register.
export const enum Reg8 {
    al = 0,
    cl = 1,
    dl = 2,
    bl = 3,
    spl = 4,
    bpl = 5,
    sil = 6,
    dil = 7,
    r8b = 8,
    r9b = 9,
    r10b = 10,
    r11b = 11,
    r12b = 12,
    r13b = 13,
    r14b = 14,
    r15b = 15,
}

// An x86 16-bits register.
export const enum Reg16 {
    ax = 0,
    cx = 1,
    dx = 2,
    bx = 3,
    sp = 4,
    bp = 5,
    si = 6,
    di = 7,
    r8w = 8,
    r9w = 9,
    r10w = 10,
    r11w = 11,
    r12w = 12,
    r13w = 13,
    r14w = 14,
    r15w = 15,
}

// An x86 32-bits register.
export const enum Reg32 {
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7,
    r8d = 8,
    r9d = 9,
    r10d = 10,
    r11d = 11,
    r12d = 12,
    r13d = 13,
    r14d = 14,
    r15d = 15,
}

// An x86 64-bits register.
export const enum Reg64 {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4,
    rbp = 5,
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
}

// An x86 128-bits register.
export type Reg128 = number;



export class X86Assembler {
    private ofs: number = 0;

    public constructor(readonly buffer: DataView) {}

    public get offset(): number { return this.ofs; }
    public set offset(ofs: number) {
        if (ofs < 0 || ofs > this.buffer.byteLength)
            throw RangeError();
        
        this.ofs = ofs;
    }

    // Emits a 'pushf' instruction.
    pushf() {
        this.buffer.setUint8(this.ofs, 156);
        this.ofs += 1;
    }

    // Emits a 'popf' instruction.
    popf() {
        this.buffer.setUint8(this.ofs, 157);
        this.ofs += 1;
    }

    // Emits a 'ret' instruction.
    ret() {
        this.buffer.setUint8(this.ofs, 195);
        this.ofs += 1;
    }

    // Emits a 'clc' instruction.
    clc() {
        this.buffer.setUint8(this.ofs, 248);
        this.ofs += 1;
    }

    // Emits a 'stc' instruction.
    stc() {
        this.buffer.setUint8(this.ofs, 249);
        this.ofs += 1;
    }

    // Emits a 'cli' instruction.
    cli() {
        this.buffer.setUint8(this.ofs, 250);
        this.ofs += 1;
    }

    // Emits a 'sti' instruction.
    sti() {
        this.buffer.setUint8(this.ofs, 251);
        this.ofs += 1;
    }

    // Emits a 'cld' instruction.
    cld() {
        this.buffer.setUint8(this.ofs, 252);
        this.ofs += 1;
    }

    // Emits a 'std' instruction.
    std() {
        this.buffer.setUint8(this.ofs, 253);
        this.ofs += 1;
    }

    // Emits a 'jo' instruction.
    jo_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 112);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jno' instruction.
    jno_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 113);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jb' instruction.
    jb_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnae' instruction.
    jnae_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jc' instruction.
    jc_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnb' instruction.
    jnb_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jae' instruction.
    jae_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnc' instruction.
    jnc_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jz' instruction.
    jz_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 116);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'je' instruction.
    je_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 116);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnz' instruction.
    jnz_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 117);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jne' instruction.
    jne_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 117);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jbe' instruction.
    jbe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 118);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jna' instruction.
    jna_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 118);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnbe' instruction.
    jnbe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 119);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'ja' instruction.
    ja_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 119);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'js' instruction.
    js_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 120);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jns' instruction.
    jns_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 121);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jp' instruction.
    jp_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 122);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jpe' instruction.
    jpe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 122);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnp' instruction.
    jnp_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 123);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jpo' instruction.
    jpo_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 123);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jl' instruction.
    jl_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 124);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnge' instruction.
    jnge_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 124);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnl' instruction.
    jnl_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 125);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jge' instruction.
    jge_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 125);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jle' instruction.
    jle_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 126);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jng' instruction.
    jng_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 126);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnle' instruction.
    jnle_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 127);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jg' instruction.
    jg_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 127);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits an 'inc' instruction.
    inc_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (64 + operand));
        this.ofs += 1;
    }

    // Emits an 'inc' instruction.
    inc_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (64 + operand));
        this.ofs += 1;
    }

    // Emits a 'dec' instruction.
    dec_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (72 + operand));
        this.ofs += 1;
    }

    // Emits a 'dec' instruction.
    dec_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (72 + operand));
        this.ofs += 1;
    }

    // Emits a 'push' instruction.
    push_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (80 + operand));
        this.ofs += 1;
    }

    // Emits a 'push' instruction.
    push_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (80 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    pop_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    pop_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    pop_r64(operand: Reg64) {
        this.buffer.setUint8(this.ofs, (72 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits an 'add' instruction.
    add_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'or' instruction.
    or_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'adc' instruction.
    adc_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sbb' instruction.
    sbb_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'and' instruction.
    and_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sub' instruction.
    sub_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'xor' instruction.
    xor_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'cmp' instruction.
    cmp_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'add' instruction.
    add_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'add' instruction.
    add_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    add_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'add' instruction.
    add_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'or' instruction.
    or_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'or' instruction.
    or_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'or' instruction.
    or_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'or' instruction.
    or_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'adc' instruction.
    adc_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'adc' instruction.
    adc_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'adc' instruction.
    adc_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'adc' instruction.
    adc_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sbb' instruction.
    sbb_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sbb' instruction.
    sbb_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sbb' instruction.
    sbb_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sbb' instruction.
    sbb_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    and_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'and' instruction.
    and_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    and_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'and' instruction.
    and_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    sub_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sub' instruction.
    sub_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    sub_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sub' instruction.
    sub_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'xor' instruction.
    xor_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'xor' instruction.
    xor_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'xor' instruction.
    xor_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'xor' instruction.
    xor_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'cmp' instruction.
    cmp_rm16_imm16(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'cmp' instruction.
    cmp_rm16_imm32(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'cmp' instruction.
    cmp_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'cmp' instruction.
    cmp_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    add_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'add' instruction.
    add_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'or' instruction.
    or_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'or' instruction.
    or_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'adc' instruction.
    adc_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'adc' instruction.
    adc_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sbb' instruction.
    sbb_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sbb' instruction.
    sbb_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'and' instruction.
    and_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'and' instruction.
    and_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sub' instruction.
    sub_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sub' instruction.
    sub_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'xor' instruction.
    xor_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'xor' instruction.
    xor_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'cmp' instruction.
    cmp_rm16_imm8(reg: Reg16, value: number) {
        this.buffer.setUint8(this.ofs, 102);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'cmp' instruction.
    cmp_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

}
