import { ArmAssembler, Reg, RegList, Coprocessor, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode } from "../src/arm";

test("should encode single cps instruction", () => {
    const arrayBuffer = new ArrayBuffer(100);
    const dataView = new DataView(arrayBuffer);

    const buffer = new ArmAssembler(dataView);

    buffer.cps(Mode.USR);

    expect(arrayBuffer).toBe([ 16, 0, 2, 241 ]);
});

