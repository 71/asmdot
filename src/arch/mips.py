from asm.ast import *
from asm.parse import *

from functools import reduce

class MipsArchitecture(Architecture):

    @property
    def name(self) -> str:
        return "mips"
    
    @property
    def declarations(self) -> Declarations:
        mips_registers = [
                "zero", "at", "v0", "v1",
                "a0", "a1", "a2", "a3",
                "t0", "t1", "t2", "t3",
                "t4", "t5", "t6", "t7",
                "s0", "s1", "s2", "s3",
                "s4", "s5", "s6", "s7",
                "t8", "t9", "k0", "k1",
                "gp", "sp", "fp", "ra"
        ]
        yield DistinctType(TYPE_MIPS_REG, "Mips register", [Constant(n, i) for i, n in enumerate(mips_registers)])

    def translate(self, input: IO[str]) -> Functions:
        for line in input:
            line = line.strip()

            if not line.startswith("#") and len(line) > 0:
                chunks = line.split(" ")
                mode = chunks[0]
                name = chunks[1]

                if mode == "R":
                    """ 
                    Type R
                    (opcode: 6b) (rs: 5b) (rt: 5b) (rd: 5b) (shift: 5b) (funct: 6b) 
                    OP rd, rs, rt
                    """
                    func = Function(name, [param("rd", TYPE_MIPS_REG), param("rs", TYPE_MIPS_REG), 
                        param("rt", TYPE_MIPS_REG), param("shift", TYPE_U8)])
                    
                    opcode = int(chunks[2], 16)
                    fcnt = int(chunks[3], 16)

                    vals = [
                            Literal((opcode << 26) | (fcnt & 0x3f), TYPE_U32),
                            Binary(OP_SHL, Var("rs"), 21),
                            Binary(OP_SHL, Var("rt"), 16),
                            Binary(OP_SHL, Var("rd"), 11),
                            Binary(OP_SHL, Var("shift"), 6)
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))
                    func += Increase(4)
                    yield func
                elif mode == "J":
                    """
                    Type J
                    (opcode: 6b) (addr: 26b)
                    OP addr
                    addr has least two bits truncated and 4 topmost bits truncated too
                    """
                    func = Function(name, [param("addr", TYPE_U32)])

                    code = Literal(opcode << 26, TYPE_U32)
                    truncated = Binary(OP_BITWISE_AND, 0x3ffffff, Binary(OP_SHL, Var("addr"), 2))
                    
                    func += Set(TYPE_U32, Binary(OP_BITWISE_OR, code, truncated))
                    func += Increase(4)
                    yield func
                else:
                    """
                    Type I
                    (opcode: 6b) (rs: 5b) (rt: 5b) (imm: 16b)
                    OP rt, IMM(rs)
                    OP rs, rt, IMM # for beq
                    """
                    func = Function(name, [param("rs", TYPE_MIPS_REG), param("rt", TYPE_MIPS_REG),
                        param("imm", TYPE_U16)])

                    opcode = int(chunks[2], 16)

                    vals = [
                        Literal(opcode << 26, TYPE_U32),
                        Binary(OP_SHL, Var("rs"), 21),
                        Binary(OP_SHL, Var("rt"), 16),
                        Var("imm")
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))
                    func += Increase(4)
                    yield func
