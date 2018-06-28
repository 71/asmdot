import { ArmAssembler, Reg, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, a1, a2, a3, a4, v1, v2, v3, v4, v5, v6, v7, v8, ip, sp, lr, pc, wr, sb, sl, fp, RegList, Coprocessor, cp0, cp1, cp2, cp3, cp4, cp5, cp6, cp7, cp8, cp9, cp10, cp11, cp12, cp13, cp14, cp15, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode, MipsAssembler, Reg, Zero, AT, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3, T4, T5, T6, T7, S0, S1, S2, S3, S4, S5, S6, S7, T8, T9, K0, K1, GP, SP, FP, RA, X86Assembler, Reg8, al, cl, dl, bl, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b, Reg16, ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w, Reg32, eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d, Reg64, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, Reg128 } from "../src/x86";

test("should assemble single ret instruction", () => {
    const arrayBuffer = new ArrayBuffer(100);
    const dataView = new DataView(arrayBuffer);

    const buffer = new X86Assembler(dataView);

    buffer.ret();

    expect(arrayBuffer).toBe([ 195 ]);
});

