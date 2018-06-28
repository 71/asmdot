import * from "../src/mips.ts";

    test("should assemble single addi instruction", () =>
        const arrayBuffer = new ArrayBuffer(100);
        const dataView = new DataView(arrayBuffer);

        const buffer = new MipsAssembler(dataView);

        buffer.addi(T1, T2, 0);

        expect(arrayBuffer).toBe([ 0, 0, 73, 33 ]);

