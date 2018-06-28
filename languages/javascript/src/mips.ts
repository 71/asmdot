// A Mips register.
export const enum Reg {
    Zero = 0,
    AT = 1,
    V0 = 2,
    V1 = 3,
    A0 = 4,
    A1 = 5,
    A2 = 6,
    A3 = 7,
    T0 = 8,
    T1 = 9,
    T2 = 10,
    T3 = 11,
    T4 = 12,
    T5 = 13,
    T6 = 14,
    T7 = 15,
    S0 = 16,
    S1 = 17,
    S2 = 18,
    S3 = 19,
    S4 = 20,
    S5 = 21,
    S6 = 22,
    S7 = 23,
    T8 = 24,
    T9 = 25,
    K0 = 26,
    K1 = 27,
    GP = 28,
    SP = 29,
    FP = 30,
    RA = 31,
}



export class MipsAssembler {
    private ofs: number = 0;

    public constructor(readonly buffer: DataView) {}

    public get offset(): number { return this.ofs; }
    public set offset(ofs: number) {
        if (ofs < 0 || ofs > this.buffer.byteLength)
            throw RangeError();
        
        this.ofs = ofs;
    }

    // Emits a 'sll' instruction.
    sll(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movci' instruction.
    movci(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srl' instruction.
    srl(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sra' instruction.
    sra(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sllv' instruction.
    sllv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srlv' instruction.
    srlv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srav' instruction.
    srav(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'jr' instruction.
    jr(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'jalr' instruction.
    jalr(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movz' instruction.
    movz(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movn' instruction.
    movn(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'syscall' instruction.
    syscall(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'breakpoint' instruction.
    breakpoint(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sync' instruction.
    sync(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mfhi' instruction.
    mfhi(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mthi' instruction.
    mthi(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mflo' instruction.
    mflo(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mfhi' instruction.
    mfhi(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((19 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsllv' instruction.
    dsllv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsrlv' instruction.
    dsrlv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsrav' instruction.
    dsrav(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mult' instruction.
    mult(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'multu' instruction.
    multu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'div' instruction.
    div(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'divu' instruction.
    divu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dmult' instruction.
    dmult(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dmultu' instruction.
    dmultu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'ddiv' instruction.
    ddiv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'ddivu' instruction.
    ddivu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    add(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'addu' instruction.
    addu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    sub(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'subu' instruction.
    subu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    and(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'or' instruction.
    or(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'xor' instruction.
    xor(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'nor' instruction.
    nor(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'slt' instruction.
    slt(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sltu' instruction.
    sltu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dadd' instruction.
    dadd(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'daddu' instruction.
    daddu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsub' instruction.
    dsub(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsubu' instruction.
    dsubu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tge' instruction.
    tge(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tgeu' instruction.
    tgeu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tlt' instruction.
    tlt(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tltu' instruction.
    tltu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'teq' instruction.
    teq(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tne' instruction.
    tne(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsll' instruction.
    dsll(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dslr' instruction.
    dslr(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsra' instruction.
    dsra(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mhc0' instruction.
    mhc0(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'btlz' instruction.
    btlz(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgez' instruction.
    bgez(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzl' instruction.
    bltzl(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezl' instruction.
    bgezl(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sllv' instruction.
    sllv(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tgei' instruction.
    tgei(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'jalr' instruction.
    jalr(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tlti' instruction.
    tlti(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tltiu' instruction.
    tltiu(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'teqi' instruction.
    teqi(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tnei' instruction.
    tnei(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzal' instruction.
    bltzal(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezal' instruction.
    bgezal(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzall' instruction.
    bltzall(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezall' instruction.
    bgezall(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'dsllv' instruction.
    dsllv(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'synci' instruction.
    synci(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'addi' instruction.
    addi(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'addiu' instruction.
    addiu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'andi' instruction.
    andi(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'beq' instruction.
    beq(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'blez' instruction.
    blez(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'bne' instruction.
    bne(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'lw' instruction.
    lw(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lbu' instruction.
    lbu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lhu' instruction.
    lhu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lui' instruction.
    lui(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'ori' instruction.
    ori(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sb' instruction.
    sb(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sh' instruction.
    sh(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'slti' instruction.
    slti(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sltiu' instruction.
    sltiu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sw' instruction.
    sw(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'j' instruction.
    j(address: number) {
        this.buffer.setUint32(this.ofs, (134217728 | ((address >> 2) & 67108863)), true);
        this.ofs += 4;
    }

    // Emits a 'jal' instruction.
    jal(address: number) {
        this.buffer.setUint32(this.ofs, (201326592 | ((address >> 2) & 67108863)), true);
        this.ofs += 4;
    }

}
