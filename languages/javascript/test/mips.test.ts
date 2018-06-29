import { arrayBufferToArray } from "./helpers";
import { ArmAssembler, Reg, RegList, Coprocessor, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode, MipsAssembler, Reg } from "../src/mips";

test("should assemble single addi instruction", () => {
    const arrayBuffer = new ArrayBuffer(4);
    const dataView = new DataView(arrayBuffer);

    const buffer = new MipsAssembler(dataView);

    buffer.addi(Reg.T1, Reg.T2, 0);

    expect(arrayBufferToArray(arrayBuffer)).toEqual([ 0, 0, 73, 33 ]);
});

