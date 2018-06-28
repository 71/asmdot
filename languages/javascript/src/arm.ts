import * from "./helpers";

// An ARM register.
export type Reg = number;

export const r0 = 0;
export const r1 = 1;
export const r2 = 2;
export const r3 = 3;
export const r4 = 4;
export const r5 = 5;
export const r6 = 6;
export const r7 = 7;
export const r8 = 8;
export const r9 = 9;
export const r10 = 10;
export const r11 = 11;
export const r12 = 12;
export const r13 = 13;
export const r14 = 14;
export const r15 = 15;
export const a1 = 0;
export const a2 = 1;
export const a3 = 2;
export const a4 = 3;
export const v1 = 4;
export const v2 = 5;
export const v3 = 6;
export const v4 = 7;
export const v5 = 8;
export const v6 = 9;
export const v7 = 10;
export const v8 = 11;
export const ip = 12;
export const sp = 13;
export const lr = 14;
export const pc = 15;
export const wr = 7;
export const sb = 9;
export const sl = 10;
export const fp = 11;

// A list of ARM registers, where each register corresponds to a single bit.
export const enum RegList {
    // Register #1.
    R0 = 0,
    // Register #2.
    R1 = 1,
    // Register #3.
    R2 = 2,
    // Register #4.
    R3 = 3,
    // Register #5.
    R4 = 4,
    // Register #6.
    R5 = 5,
    // Register #7.
    R6 = 6,
    // Register #8.
    R7 = 7,
    // Register #9.
    R8 = 8,
    // Register #10.
    R9 = 9,
    // Register #11.
    R10 = 10,
    // Register #12.
    R11 = 11,
    // Register #13.
    R12 = 12,
    // Register #14.
    R13 = 13,
    // Register #15.
    R14 = 14,
    // Register #16.
    R15 = 15,
    // Register A1.
    A1 = 0,
    // Register A2.
    A2 = 1,
    // Register A3.
    A3 = 2,
    // Register A4.
    A4 = 3,
    // Register V1.
    V1 = 4,
    // Register V2.
    V2 = 5,
    // Register V3.
    V3 = 6,
    // Register V4.
    V4 = 7,
    // Register V5.
    V5 = 8,
    // Register V6.
    V6 = 9,
    // Register V7.
    V7 = 10,
    // Register V8.
    V8 = 11,
    // Register IP.
    IP = 12,
    // Register SP.
    SP = 13,
    // Register LR.
    LR = 14,
    // Register PC.
    PC = 15,
    // Register WR.
    WR = 7,
    // Register SB.
    SB = 9,
    // Register SL.
    SL = 10,
    // Register FP.
    FP = 11,
}

// An ARM coprocessor.
export type Coprocessor = number;

export const cp0 = 0;
export const cp1 = 1;
export const cp2 = 2;
export const cp3 = 3;
export const cp4 = 4;
export const cp5 = 5;
export const cp6 = 6;
export const cp7 = 7;
export const cp8 = 8;
export const cp9 = 9;
export const cp10 = 10;
export const cp11 = 11;
export const cp12 = 12;
export const cp13 = 13;
export const cp14 = 14;
export const cp15 = 15;

// Condition for an ARM instruction to be executed.
export const enum Condition {
    // Equal.
    EQ = 0,
    // Not equal.
    NE = 1,
    // Unsigned higher or same.
    HS = 2,
    // Unsigned lower.
    LO = 3,
    // Minus / negative.
    MI = 4,
    // Plus / positive or zero.
    PL = 5,
    // Overflow.
    VS = 6,
    // No overflow.
    VC = 7,
    // Unsigned higher.
    HI = 8,
    // Unsigned lower or same.
    LS = 9,
    // Signed greater than or equal.
    GE = 10,
    // Signed less than.
    LT = 11,
    // Signed greater than.
    GT = 12,
    // Signed less than or equal.
    LE = 13,
    // Always (unconditional).
    AL = 14,
    // Unpredictable (ARMv4 or lower).
    UN = 15,
    // Carry set.
    CS = 2,
    // Carry clear.
    CC = 3,
}

// Processor mode.
export const enum Mode {
    // User mode.
    USR = 16,
    // FIQ (high-speed data transfer) mode.
    FIQ = 17,
    // IRQ (general-purpose interrupt handling) mode.
    IRQ = 18,
    // Supervisor mode.
    SVC = 19,
    // Abort mode.
    ABT = 23,
    // Undefined mode.
    UND = 27,
    // System (privileged) mode.
    SYS = 31,
}

// Kind of a shift.
export const enum Shift {
    // Logical shift left.
    LSL = 0,
    // Logical shift right.
    LSR = 1,
    // Arithmetic shift right.
    ASR = 2,
    // Rotate right.
    ROR = 3,
    // Shifted right by one bit.
    RRX = 3,
}

// Kind of a right rotation.
export const enum Rotation {
    // Do not rotate.
    NOP = 0,
    // Rotate 8 bits to the right.
    ROR8 = 1,
    // Rotate 16 bits to the right.
    ROR16 = 2,
    // Rotate 24 bits to the right.
    ROR24 = 3,
}

// Field mask bits.
export const enum FieldMask {
    // Control field mask bit.
    C = 1,
    // Extension field mask bit.
    X = 2,
    // Status field mask bit.
    S = 4,
    // Flags field mask bit.
    F = 8,
}

// Interrupt flags.
export const enum InterruptFlags {
    // FIQ interrupt bit.
    F = 1,
    // IRQ interrupt bit.
    I = 2,
    // Imprecise data abort bit.
    A = 4,
}

// Addressing type.
export const enum Addressing {
    // Post-indexed addressing.
    PostIndexed = 0,
    // Pre-indexed addressing (or offset addressing if `write` is false).
    PreIndexed = 1,
    // Offset addressing (or pre-indexed addressing if `write` is true).
    Offset = 1,
}

// Offset adding or subtracting mode.
export const enum OffsetMode {
    // Subtract offset from the base.
    Subtract = 0,
    // Add offset to the base.
    Add = 1,
}



export class ArmAssembler {
    private ofs: number = 0;

    public constructor(readonly buffer: DataView) {}

    public get offset(): number { return this.ofs; }
    public set offset(ofs: number) {
        if (ofs < 0 || ofs > this.buffer.byteLength)
            throw RangeError();
        
        this.ofs = ofs;
    }

    // Emits an 'adc' instruction.
    adc(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((10485760 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    add(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((8388608 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    and(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((0 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'eor' instruction.
    eor(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((2097152 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'orr' instruction.
    orr(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((25165824 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'rsb' instruction.
    rsb(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((6291456 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'rsc' instruction.
    rsc(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((14680064 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'sbc' instruction.
    sbc(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((12582912 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    sub(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((4194304 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'bkpt' instruction.
    bkpt(immed: number) {
        this.buffer.setUint32(this.ofs, ((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)), true);
        this.ofs += 4;
    }

    // Emits a 'b' instruction.
    b(cond: Condition) {
        this.buffer.setUint32(this.ofs, (167772160 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'bic' instruction.
    bic(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((29360128 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 16)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'blx' instruction.
    blx(cond: Condition) {
        this.buffer.setUint32(this.ofs, (19922736 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'bx' instruction.
    bx(cond: Condition) {
        this.buffer.setUint32(this.ofs, (19922704 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'bxj' instruction.
    bxj(cond: Condition) {
        this.buffer.setUint32(this.ofs, (19922720 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'blxun' instruction.
    blxun() {
        this.buffer.setUint32(this.ofs, 4194304000, true);
        this.ofs += 4;
    }

    // Emits a 'clz' instruction.
    clz(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((24055568 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'cmn' instruction.
    cmn(cond: Condition, rn: Reg) {
        this.buffer.setUint32(this.ofs, ((24117248 | cond) | (rn << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'cmp' instruction.
    cmp(cond: Condition, rn: Reg) {
        this.buffer.setUint32(this.ofs, ((22020096 | cond) | (rn << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'cpy' instruction.
    cpy(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((27262976 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'cps' instruction.
    cps(mode: Mode) {
        this.buffer.setUint32(this.ofs, (4043440128 | (mode << 0)), true);
        this.ofs += 4;
    }

    // Emits a 'cpsie' instruction.
    cpsie(iflags: InterruptFlags) {
        this.buffer.setUint32(this.ofs, (4043833344 | (iflags << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'cpsid' instruction.
    cpsid(iflags: InterruptFlags) {
        this.buffer.setUint32(this.ofs, (4044095488 | (iflags << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'cpsie_mode' instruction.
    cpsie_mode(iflags: InterruptFlags, mode: Mode) {
        this.buffer.setUint32(this.ofs, ((4043964416 | (iflags << 6)) | (mode << 0)), true);
        this.ofs += 4;
    }

    // Emits a 'cpsid_mode' instruction.
    cpsid_mode(iflags: InterruptFlags, mode: Mode) {
        this.buffer.setUint32(this.ofs, ((4044226560 | (iflags << 6)) | (mode << 0)), true);
        this.ofs += 4;
    }

    // Emits a 'ldc' instruction.
    ldc(cond: Condition, write: boolean, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((202375168 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldm' instruction.
    ldm(cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: boolean, copy_spsr: boolean) {
        if (!(((copy_spsr ? 1 : 0) == 1) ^ ((write ? 1 : 0) == (registers & 32768)))) throw Error();
        this.buffer.setUint32(this.ofs, ((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | ((copy_spsr ? 1 : 0) << 21)) | ((write ? 1 : 0) << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'ldr' instruction.
    ldr(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((68157440 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrb' instruction.
    ldrb(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((72351744 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrbt' instruction.
    ldrbt(cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) {
        this.buffer.setUint32(this.ofs, ((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrd' instruction.
    ldrd(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((208 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrex' instruction.
    ldrex(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((26218399 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrh' instruction.
    ldrh(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((1048752 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrsb' instruction.
    ldrsb(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((1048784 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrsh' instruction.
    ldrsh(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((1048816 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ldrt' instruction.
    ldrt(cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) {
        this.buffer.setUint32(this.ofs, ((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)), true);
        this.ofs += 4;
    }

    // Emits a 'cdp' instruction.
    cdp(cond: Condition, cpnum: Coprocessor) {
        this.buffer.setUint32(this.ofs, ((234881024 | cond) | (cpnum << 8)), true);
        this.ofs += 4;
    }

    // Emits a 'mcr' instruction.
    mcr(cond: Condition, rd: Reg, cpnum: Coprocessor) {
        this.buffer.setUint32(this.ofs, (((234881040 | cond) | (rd << 12)) | (cpnum << 8)), true);
        this.ofs += 4;
    }

    // Emits a 'mrc' instruction.
    mrc(cond: Condition, rd: Reg, cpnum: Coprocessor) {
        this.buffer.setUint32(this.ofs, (((235929616 | cond) | (rd << 12)) | (cpnum << 8)), true);
        this.ofs += 4;
    }

    // Emits a 'mcrr' instruction.
    mcrr(cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) {
        this.buffer.setUint32(this.ofs, ((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)), true);
        this.ofs += 4;
    }

    // Emits a 'mla' instruction.
    mla(cond: Condition, update_cprs: boolean, rn: Reg, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((((2097296 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rn << 12)) | (rd << 16)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'mov' instruction.
    mov(cond: Condition, update_cprs: boolean, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, ((((27262976 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'mrrc' instruction.
    mrrc(cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) {
        this.buffer.setUint32(this.ofs, ((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)), true);
        this.ofs += 4;
    }

    // Emits a 'mrs' instruction.
    mrs(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((17760256 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'mul' instruction.
    mul(cond: Condition, update_cprs: boolean, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, ((((144 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rd << 16)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'mvn' instruction.
    mvn(cond: Condition, update_cprs: boolean, rd: Reg, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, ((((31457280 | cond) | ((update_cprs ? 1 : 0) << 20)) | (rd << 12)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'msr_imm' instruction.
    msr_imm(cond: Condition, fieldmask: FieldMask) {
        this.buffer.setUint32(this.ofs, ((52490240 | cond) | (fieldmask << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'msr_reg' instruction.
    msr_reg(cond: Condition, fieldmask: FieldMask) {
        this.buffer.setUint32(this.ofs, ((18935808 | cond) | (fieldmask << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'pkhbt' instruction.
    pkhbt(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((109051920 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'pkhtb' instruction.
    pkhtb(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((109051984 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'pld' instruction.
    pld(rn: Reg, offset_mode: OffsetMode) {
        this.buffer.setUint32(this.ofs, ((4115722240 | (rn << 16)) | (offset_mode << 23)), true);
        this.ofs += 4;
    }

    // Emits a 'qadd' instruction.
    qadd(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777296 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qadd16' instruction.
    qadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764304 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qadd8' instruction.
    qadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764432 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qaddsubx' instruction.
    qaddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764336 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qdadd' instruction.
    qdadd(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((20971600 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qdsub' instruction.
    qdsub(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((23068752 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qsub' instruction.
    qsub(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((18874448 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qsub16' instruction.
    qsub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764400 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qsub8' instruction.
    qsub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764528 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'qsubaddx' instruction.
    qsubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((102764368 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'rev' instruction.
    rev(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((113184560 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'rev16' instruction.
    rev16(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((113184688 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'revsh' instruction.
    revsh(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((117378992 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'rfe' instruction.
    rfe(write: boolean, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((4161800704 | ((write ? 1 : 0) << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'sadd16' instruction.
    sadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715728 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'sadd8' instruction.
    sadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715856 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'saddsubx' instruction.
    saddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715760 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'sel' instruction.
    sel(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((109055920 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'setendbe' instruction.
    setendbe() {
        this.buffer.setUint32(this.ofs, 4043375104, true);
        this.ofs += 4;
    }

    // Emits a 'setendle' instruction.
    setendle() {
        this.buffer.setUint32(this.ofs, 4043374592, true);
        this.ofs += 4;
    }

    // Emits a 'shadd16' instruction.
    shadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103812880 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'shadd8' instruction.
    shadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103813008 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'shaddsubx' instruction.
    shaddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103812912 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'shsub16' instruction.
    shsub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103812976 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'shsub8' instruction.
    shsub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103813104 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'shsubaddx' instruction.
    shsubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((103812944 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'smlabb' instruction.
    smlabb(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777344 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlabt' instruction.
    smlabt(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777376 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlatb' instruction.
    smlatb(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777408 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlatt' instruction.
    smlatt(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777440 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlad' instruction.
    smlad(cond: Condition, exchange: boolean, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((((117440528 | cond) | ((exchange ? 1 : 0) << 5)) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlal' instruction.
    smlal(cond: Condition, update_cprs: boolean, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((14680208 | cond) | ((update_cprs ? 1 : 0) << 20)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'smlalbb' instruction.
    smlalbb(cond: Condition) {
        this.buffer.setUint32(this.ofs, (20971648 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'smlalbt' instruction.
    smlalbt(cond: Condition) {
        this.buffer.setUint32(this.ofs, (20971680 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'smlaltb' instruction.
    smlaltb(cond: Condition) {
        this.buffer.setUint32(this.ofs, (20971712 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'smlaltt' instruction.
    smlaltt(cond: Condition) {
        this.buffer.setUint32(this.ofs, (20971744 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'smlald' instruction.
    smlald(cond: Condition, exchange: boolean) {
        this.buffer.setUint32(this.ofs, ((121634832 | cond) | ((exchange ? 1 : 0) << 5)), true);
        this.ofs += 4;
    }

    // Emits a 'smlawb' instruction.
    smlawb(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((18874496 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlawt' instruction.
    smlawt(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((18874560 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlsd' instruction.
    smlsd(cond: Condition, exchange: boolean, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((((117440592 | cond) | ((exchange ? 1 : 0) << 5)) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smlsld' instruction.
    smlsld(cond: Condition, exchange: boolean) {
        this.buffer.setUint32(this.ofs, ((121634896 | cond) | ((exchange ? 1 : 0) << 5)), true);
        this.ofs += 4;
    }

    // Emits a 'smmla' instruction.
    smmla(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((122683408 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smmls' instruction.
    smmls(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((122683600 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smmul' instruction.
    smmul(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((122744848 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smuad' instruction.
    smuad(cond: Condition, exchange: boolean, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((117501968 | cond) | ((exchange ? 1 : 0) << 5)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smulbb' instruction.
    smulbb(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((23068800 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smulbt' instruction.
    smulbt(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((23068832 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smultb' instruction.
    smultb(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((23068864 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smultt' instruction.
    smultt(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((23068896 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smull' instruction.
    smull(cond: Condition, update_cprs: boolean, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((12583056 | cond) | ((update_cprs ? 1 : 0) << 20)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits a 'smulwb' instruction.
    smulwb(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((18874528 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smulwt' instruction.
    smulwt(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((18874592 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'smusd' instruction.
    smusd(cond: Condition, exchange: boolean, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((117502032 | cond) | ((exchange ? 1 : 0) << 5)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'srs' instruction.
    srs(write: boolean, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((4165797120 | ((write ? 1 : 0) << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'ssat' instruction.
    ssat(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((105906192 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'ssat16' instruction.
    ssat16(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((111152944 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'ssub16' instruction.
    ssub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715824 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'ssub8' instruction.
    ssub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715952 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'ssubaddx' instruction.
    ssubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((101715792 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'stc' instruction.
    stc(cond: Condition, write: boolean, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((201326592 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'stm' instruction.
    stm(cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: boolean, user_mode: boolean) {
        if (!(((user_mode ? 1 : 0) == 0) || ((write ? 1 : 0) == 0))) throw Error();
        this.buffer.setUint32(this.ofs, ((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | ((user_mode ? 1 : 0) << 21)) | ((write ? 1 : 0) << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'str' instruction.
    str(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((67108864 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'strb' instruction.
    strb(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((71303168 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'strbt' instruction.
    strbt(cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) {
        this.buffer.setUint32(this.ofs, ((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)), true);
        this.ofs += 4;
    }

    // Emits a 'strd' instruction.
    strd(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((240 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'strex' instruction.
    strex(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((25169808 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'strh' instruction.
    strh(cond: Condition, write: boolean, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) {
        this.buffer.setUint32(this.ofs, ((((((176 | cond) | ((write ? 1 : 0) << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)), true);
        this.ofs += 4;
    }

    // Emits a 'strt' instruction.
    strt(cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) {
        this.buffer.setUint32(this.ofs, ((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)), true);
        this.ofs += 4;
    }

    // Emits a 'swi' instruction.
    swi(cond: Condition) {
        this.buffer.setUint32(this.ofs, (251658240 | cond), true);
        this.ofs += 4;
    }

    // Emits a 'swp' instruction.
    swp(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((16777360 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'swpb' instruction.
    swpb(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((20971664 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits a 'sxtab' instruction.
    sxtab(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'sxtab16' instruction.
    sxtab16(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'sxtah' instruction.
    sxtah(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'sxtb' instruction.
    sxtb(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((112132208 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'sxtb16' instruction.
    sxtb16(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((110035056 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'sxth' instruction.
    sxth(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((113180784 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits a 'teq' instruction.
    teq(cond: Condition, rn: Reg) {
        this.buffer.setUint32(this.ofs, ((19922944 | cond) | (rn << 16)), true);
        this.ofs += 4;
    }

    // Emits a 'tst' instruction.
    tst(cond: Condition, rn: Reg) {
        this.buffer.setUint32(this.ofs, ((17825792 | cond) | (rn << 16)), true);
        this.ofs += 4;
    }

    // Emits an 'uadd16' instruction.
    uadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910032 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uadd8' instruction.
    uadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910160 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uaddsubx' instruction.
    uaddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910064 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhadd16' instruction.
    uhadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007184 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhadd8' instruction.
    uhadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007312 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhaddsubx' instruction.
    uhaddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007216 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhsub16' instruction.
    uhsub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007280 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhsub8' instruction.
    uhsub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007408 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uhsubaddx' instruction.
    uhsubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((108007248 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'umaal' instruction.
    umaal(cond: Condition) {
        this.buffer.setUint32(this.ofs, (4194448 | cond), true);
        this.ofs += 4;
    }

    // Emits an 'umlal' instruction.
    umlal(cond: Condition, update_cprs: boolean, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((10485904 | cond) | ((update_cprs ? 1 : 0) << 20)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'umull' instruction.
    umull(cond: Condition, update_cprs: boolean, update_condition: boolean) {
        this.buffer.setUint32(this.ofs, (((8388752 | cond) | ((update_cprs ? 1 : 0) << 20)) | ((update_condition ? 1 : 0) << 20)), true);
        this.ofs += 4;
    }

    // Emits an 'uqadd16' instruction.
    uqadd16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958608 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uqadd8' instruction.
    uqadd8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958736 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uqaddsubx' instruction.
    uqaddsubx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958640 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uqsub16' instruction.
    uqsub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958704 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uqsub8' instruction.
    uqsub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958832 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uqsubaddx' instruction.
    uqsubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((106958672 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'usad8' instruction.
    usad8(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((125890576 | cond) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits an 'usada8' instruction.
    usada8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((125829136 | cond) | (rn << 12)) | (rd << 16)), true);
        this.ofs += 4;
    }

    // Emits an 'usat' instruction.
    usat(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((115343376 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'usat16' instruction.
    usat16(cond: Condition, rd: Reg) {
        this.buffer.setUint32(this.ofs, ((115347248 | cond) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'usub16' instruction.
    usub16(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910128 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'usub8' instruction.
    usub8(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910256 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'usubaddx' instruction.
    usubaddx(cond: Condition, rn: Reg, rd: Reg) {
        this.buffer.setUint32(this.ofs, (((105910096 | cond) | (rn << 16)) | (rd << 12)), true);
        this.ofs += 4;
    }

    // Emits an 'uxtab' instruction.
    uxtab(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits an 'uxtab16' instruction.
    uxtab16(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits an 'uxtah' instruction.
    uxtah(cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits an 'uxtb' instruction.
    uxtb(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((116326512 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits an 'uxtb16' instruction.
    uxtb16(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((114229360 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

    // Emits an 'uxth' instruction.
    uxth(cond: Condition, rd: Reg, rotate: Rotation) {
        this.buffer.setUint32(this.ofs, (((117375088 | cond) | (rd << 12)) | (rotate << 10)), true);
        this.ofs += 4;
    }

}
