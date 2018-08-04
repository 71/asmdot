// An x86 8-bits register.
export const enum Reg8 {
    AL = 0,
    CL = 1,
    DL = 2,
    BL = 3,
    SPL = 4,
    BPL = 5,
    SIL = 6,
    DIL = 7,
    R8B = 8,
    R9B = 9,
    R10B = 10,
    R11B = 11,
    R12B = 12,
    R13B = 13,
    R14B = 14,
    R15B = 15,
}

// An x86 16-bits register.
export const enum Reg16 {
    AX = 0,
    CX = 1,
    DX = 2,
    BX = 3,
    SP = 4,
    BP = 5,
    SI = 6,
    DI = 7,
    R8W = 8,
    R9W = 9,
    R10W = 10,
    R11W = 11,
    R12W = 12,
    R13W = 13,
    R14W = 14,
    R15W = 15,
}

// An x86 32-bits register.
export const enum Reg32 {
    EAX = 0,
    ECX = 1,
    EDX = 2,
    EBX = 3,
    ESP = 4,
    EBP = 5,
    ESI = 6,
    EDI = 7,
    R8D = 8,
    R9D = 9,
    R10D = 10,
    R11D = 11,
    R12D = 12,
    R13D = 13,
    R14D = 14,
    R15D = 15,
}

// An x86 64-bits register.
export const enum Reg64 {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
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
    public pushf() {
        this.buffer.setUint8(this.ofs, 156);
        this.ofs += 1;
    }

    // Emits a 'popf' instruction.
    public popf() {
        this.buffer.setUint8(this.ofs, 157);
        this.ofs += 1;
    }

    // Emits a 'ret' instruction.
    public ret() {
        this.buffer.setUint8(this.ofs, 195);
        this.ofs += 1;
    }

    // Emits a 'clc' instruction.
    public clc() {
        this.buffer.setUint8(this.ofs, 248);
        this.ofs += 1;
    }

    // Emits a 'stc' instruction.
    public stc() {
        this.buffer.setUint8(this.ofs, 249);
        this.ofs += 1;
    }

    // Emits a 'cli' instruction.
    public cli() {
        this.buffer.setUint8(this.ofs, 250);
        this.ofs += 1;
    }

    // Emits a 'sti' instruction.
    public sti() {
        this.buffer.setUint8(this.ofs, 251);
        this.ofs += 1;
    }

    // Emits a 'cld' instruction.
    public cld() {
        this.buffer.setUint8(this.ofs, 252);
        this.ofs += 1;
    }

    // Emits a 'std' instruction.
    public std() {
        this.buffer.setUint8(this.ofs, 253);
        this.ofs += 1;
    }

    // Emits a 'jo' instruction.
    public jo_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 112);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jno' instruction.
    public jno_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 113);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jb' instruction.
    public jb_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnae' instruction.
    public jnae_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jc' instruction.
    public jc_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 114);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnb' instruction.
    public jnb_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jae' instruction.
    public jae_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnc' instruction.
    public jnc_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 115);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jz' instruction.
    public jz_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 116);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'je' instruction.
    public je_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 116);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnz' instruction.
    public jnz_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 117);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jne' instruction.
    public jne_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 117);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jbe' instruction.
    public jbe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 118);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jna' instruction.
    public jna_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 118);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnbe' instruction.
    public jnbe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 119);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'ja' instruction.
    public ja_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 119);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'js' instruction.
    public js_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 120);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jns' instruction.
    public jns_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 121);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jp' instruction.
    public jp_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 122);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jpe' instruction.
    public jpe_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 122);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnp' instruction.
    public jnp_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 123);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jpo' instruction.
    public jpo_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 123);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jl' instruction.
    public jl_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 124);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnge' instruction.
    public jnge_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 124);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnl' instruction.
    public jnl_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 125);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jge' instruction.
    public jge_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 125);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jle' instruction.
    public jle_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 126);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jng' instruction.
    public jng_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 126);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jnle' instruction.
    public jnle_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 127);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits a 'jg' instruction.
    public jg_imm8(operand: number) {
        this.buffer.setUint8(this.ofs, 127);
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, operand);
        this.ofs += 1;
    }

    // Emits an 'inc' instruction.
    public inc_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (64 + operand));
        this.ofs += 1;
    }

    // Emits an 'inc' instruction.
    public inc_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (64 + operand));
        this.ofs += 1;
    }

    // Emits a 'dec' instruction.
    public dec_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (72 + operand));
        this.ofs += 1;
    }

    // Emits a 'dec' instruction.
    public dec_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (72 + operand));
        this.ofs += 1;
    }

    // Emits a 'push' instruction.
    public push_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (80 + operand));
        this.ofs += 1;
    }

    // Emits a 'push' instruction.
    public push_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (80 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    public pop_r16(operand: Reg16) {
        this.buffer.setUint8(this.ofs, (102 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    public pop_r32(operand: Reg32) {
        if ((operand > 7)) {
            this.buffer.setUint8(this.ofs, 65);
            this.ofs += 1;
        }
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits a 'pop' instruction.
    public pop_r64(operand: Reg64) {
        this.buffer.setUint8(this.ofs, (72 + getPrefix(operand)));
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (88 + operand));
        this.ofs += 1;
    }

    // Emits an 'add' instruction.
    public add_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'or' instruction.
    public or_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'adc' instruction.
    public adc_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sbb' instruction.
    public sbb_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'and' instruction.
    public and_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sub' instruction.
    public sub_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'xor' instruction.
    public xor_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'cmp' instruction.
    public cmp_rm8_imm8(reg: Reg8, value: number) {
        this.buffer.setUint8(this.ofs, 128);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'add' instruction.
    public add_rm16_imm16(reg: Reg16, value: number) {
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
    public add_rm16_imm32(reg: Reg16, value: number) {
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
    public add_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'add' instruction.
    public add_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'or' instruction.
    public or_rm16_imm16(reg: Reg16, value: number) {
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
    public or_rm16_imm32(reg: Reg16, value: number) {
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
    public or_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'or' instruction.
    public or_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'adc' instruction.
    public adc_rm16_imm16(reg: Reg16, value: number) {
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
    public adc_rm16_imm32(reg: Reg16, value: number) {
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
    public adc_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'adc' instruction.
    public adc_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sbb' instruction.
    public sbb_rm16_imm16(reg: Reg16, value: number) {
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
    public sbb_rm16_imm32(reg: Reg16, value: number) {
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
    public sbb_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sbb' instruction.
    public sbb_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    public and_rm16_imm16(reg: Reg16, value: number) {
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
    public and_rm16_imm32(reg: Reg16, value: number) {
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
    public and_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits an 'and' instruction.
    public and_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    public sub_rm16_imm16(reg: Reg16, value: number) {
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
    public sub_rm16_imm32(reg: Reg16, value: number) {
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
    public sub_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'sub' instruction.
    public sub_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'xor' instruction.
    public xor_rm16_imm16(reg: Reg16, value: number) {
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
    public xor_rm16_imm32(reg: Reg16, value: number) {
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
    public xor_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'xor' instruction.
    public xor_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits a 'cmp' instruction.
    public cmp_rm16_imm16(reg: Reg16, value: number) {
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
    public cmp_rm16_imm32(reg: Reg16, value: number) {
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
    public cmp_rm32_imm16(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt16(this.ofs, value, true);
        this.ofs += 2;
    }

    // Emits a 'cmp' instruction.
    public cmp_rm32_imm32(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 129);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt32(this.ofs, value, true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    public add_rm16_imm8(reg: Reg16, value: number) {
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
    public add_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 0));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'or' instruction.
    public or_rm16_imm8(reg: Reg16, value: number) {
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
    public or_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 1));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'adc' instruction.
    public adc_rm16_imm8(reg: Reg16, value: number) {
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
    public adc_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 2));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sbb' instruction.
    public sbb_rm16_imm8(reg: Reg16, value: number) {
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
    public sbb_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 3));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits an 'and' instruction.
    public and_rm16_imm8(reg: Reg16, value: number) {
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
    public and_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 4));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'sub' instruction.
    public sub_rm16_imm8(reg: Reg16, value: number) {
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
    public sub_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 5));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'xor' instruction.
    public xor_rm16_imm8(reg: Reg16, value: number) {
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
    public xor_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 6));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

    // Emits a 'cmp' instruction.
    public cmp_rm16_imm8(reg: Reg16, value: number) {
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
    public cmp_rm32_imm8(reg: Reg32, value: number) {
        this.buffer.setUint8(this.ofs, 131);
        this.ofs += 1;
        this.buffer.setUint8(this.ofs, (reg + 7));
        this.ofs += 1;
        this.buffer.setInt8(this.ofs, value);
        this.ofs += 1;
    }

}
