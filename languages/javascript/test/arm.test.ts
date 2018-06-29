import { arrayBufferToArray } from "./helpers";
import { ArmAssembler, Reg, RegList, Coprocessor, Condition, Mode, Shift, Rotation, FieldMask, InterruptFlags, Addressing, OffsetMode } from "../src/arm";

test("should encode single cps instruction", () => {
    const arrayBuffer = new ArrayBuffer(4);
    const dataView = new DataView(arrayBuffer);

    const buffer = new ArmAssembler(dataView);

    buffer.cps(Mode.USR);

    expect(arrayBufferToArray(arrayBuffer)).toEqual([ 16, 0, 2, 241 ]);
});

