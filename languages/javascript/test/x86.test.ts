import { ArmAssembler, Reg, RegList, Coprocessor, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode, MipsAssembler, Reg, X86Assembler, Reg8, Reg16, Reg32, Reg64, Reg128 } from "../src/x86";

test("should assemble single ret instruction", () => {
    const arrayBuffer = new ArrayBuffer(100);
    const dataView = new DataView(arrayBuffer);

    const buffer = new X86Assembler(dataView);

    buffer.ret();

    expect(arrayBuffer).toBe([ 195 ]);
});

