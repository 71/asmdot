import * from "../src/arm.ts";

    test("should encode single cps instruction", () =>
        const arrayBuffer = new ArrayBuffer(100);
        const dataView = new DataView(arrayBuffer);

        const buffer = new ArmAssembler(dataView);

        buffer.cps(USR);

        expect(arrayBuffer).toBe([ 16, 0, 2, 241 ]);

