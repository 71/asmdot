import * from "../src/x86.ts";

    test("should assemble single ret instruction", () =>
        const arrayBuffer = new ArrayBuffer(100);
        const dataView = new DataView(arrayBuffer);

        const buffer = new X86Assembler(dataView);

        buffer.ret();

        expect(arrayBuffer).toBe([ 195 ]);

