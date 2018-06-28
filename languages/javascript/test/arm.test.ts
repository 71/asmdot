import { ArmAssembler, Reg, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, a1, a2, a3, a4, v1, v2, v3, v4, v5, v6, v7, v8, ip, sp, lr, pc, wr, sb, sl, fp, RegList, Coprocessor, cp0, cp1, cp2, cp3, cp4, cp5, cp6, cp7, cp8, cp9, cp10, cp11, cp12, cp13, cp14, cp15, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode } from "../src/arm";

test("should encode single cps instruction", () => {
    const arrayBuffer = new ArrayBuffer(100);
    const dataView = new DataView(arrayBuffer);

    const buffer = new ArmAssembler(dataView);

    buffer.cps(Mode.USR);

    expect(arrayBuffer).toBe([ 16, 0, 2, 241 ]);
});

