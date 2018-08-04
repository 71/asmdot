// A Mips register.
export const enum Reg {
    ZERO = 0,
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
    public sll(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movci' instruction.
    public movci(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srl' instruction.
    public srl(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sra' instruction.
    public sra(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sllv' instruction.
    public sllv_r(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srlv' instruction.
    public srlv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'srav' instruction.
    public srav(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'jr' instruction.
    public jr(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'jalr' instruction.
    public jalr_r(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movz' instruction.
    public movz(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'movn' instruction.
    public movn(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'syscall' instruction.
    public syscall(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'breakpoint' instruction.
    public breakpoint(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sync' instruction.
    public sync(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mfhi' instruction.
    public mfhi(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mthi' instruction.
    public mthi(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mflo' instruction.
    public mflo(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsllv' instruction.
    public dsllv_r(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsrlv' instruction.
    public dsrlv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsrav' instruction.
    public dsrav(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mult' instruction.
    public mult(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'multu' instruction.
    public multu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'div' instruction.
    public div(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'divu' instruction.
    public divu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dmult' instruction.
    public dmult(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dmultu' instruction.
    public dmultu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'ddiv' instruction.
    public ddiv(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'ddivu' instruction.
    public ddivu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'add' instruction.
    public add(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'addu' instruction.
    public addu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sub' instruction.
    public sub(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'subu' instruction.
    public subu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'and' instruction.
    public and(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits an 'or' instruction.
    public or(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'xor' instruction.
    public xor(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'nor' instruction.
    public nor(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'slt' instruction.
    public slt(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'sltu' instruction.
    public sltu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dadd' instruction.
    public dadd(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'daddu' instruction.
    public daddu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsub' instruction.
    public dsub(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsubu' instruction.
    public dsubu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tge' instruction.
    public tge(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tgeu' instruction.
    public tgeu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tlt' instruction.
    public tlt(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tltu' instruction.
    public tltu(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'teq' instruction.
    public teq(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'tne' instruction.
    public tne(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsll' instruction.
    public dsll(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dslr' instruction.
    public dslr(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'dsra' instruction.
    public dsra(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'mhc0' instruction.
    public mhc0(rd: Reg, rs: Reg, rt: Reg, shift: number) {
        this.buffer.setUint32(this.ofs, ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)), true);
        this.ofs += 4;
    }

    // Emits a 'btlz' instruction.
    public btlz(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgez' instruction.
    public bgez(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzl' instruction.
    public bltzl(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezl' instruction.
    public bgezl(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sllv' instruction.
    public sllv_ri(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tgei' instruction.
    public tgei(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'jalr' instruction.
    public jalr_ri(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tlti' instruction.
    public tlti(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tltiu' instruction.
    public tltiu(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'teqi' instruction.
    public teqi(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'tnei' instruction.
    public tnei(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzal' instruction.
    public bltzal(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezal' instruction.
    public bgezal(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bltzall' instruction.
    public bltzall(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'bgezall' instruction.
    public bgezall(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'dsllv' instruction.
    public dsllv_ri(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'synci' instruction.
    public synci(rs: Reg, target: number) {
        this.buffer.setUint32(this.ofs, ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'addi' instruction.
    public addi(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'addiu' instruction.
    public addiu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'andi' instruction.
    public andi(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'beq' instruction.
    public beq(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'blez' instruction.
    public blez(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'bne' instruction.
    public bne(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)), true);
        this.ofs += 4;
    }

    // Emits a 'lw' instruction.
    public lw(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lbu' instruction.
    public lbu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lhu' instruction.
    public lhu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'lui' instruction.
    public lui(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits an 'ori' instruction.
    public ori(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sb' instruction.
    public sb(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sh' instruction.
    public sh(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'slti' instruction.
    public slti(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sltiu' instruction.
    public sltiu(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'sw' instruction.
    public sw(rs: Reg, rt: Reg, imm: number) {
        this.buffer.setUint32(this.ofs, (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)), true);
        this.ofs += 4;
    }

    // Emits a 'j' instruction.
    public j(address: number) {
        this.buffer.setUint32(this.ofs, (134217728 | ((address >> 2) & 67108863)), true);
        this.ofs += 4;
    }

    // Emits a 'jal' instruction.
    public jal(address: number) {
        this.buffer.setUint32(this.ofs, (201326592 | ((address >> 2) & 67108863)), true);
        this.ofs += 4;
    }

}
