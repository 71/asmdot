from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

from functools import reduce

class MipsArchitecture(Architecture):

    @property
    def name(self) -> str:
        return 'mips'
    
    @property
    def declarations(self) -> Declarations:
        mips_registers = [
                'Zero', 'AT', 'V0', 'V1',
                'A0', 'A1', 'A2', 'A3',
                'T0', 'T1', 'T2', 'T3',
                'T4', 'T5', 'T6', 'T7',
                'S0', 'S1', 'S2', 'S3',
                'S4', 'S5', 'S6', 'S7',
                'T8', 'T9', 'K0', 'K1',
                'GP', 'SP', 'FP', 'RA'
        ]
        yield DistinctType(TYPE_MIPS_REG, 'A Mips register.', [ Constant(n, i) for i, n in enumerate(mips_registers) ])

    def translate(self, input: IO[str]) -> Functions:
        for line in input:
            line = line.strip()

            if not line.startswith('#') and len(line) > 0:
                chunks = line.split(' ')
                mode = chunks[0]
                name = chunks[1]

                if mode == 'R': 
                    # Type R
                    # (opcode: 6b) (rs: 5b) (rt: 5b) (rd: 5b) (shift: 5b) (funct: 6b) 
                    # OP rd, rs, rt

                    func = Function(name, [param('rd', TYPE_MIPS_REG), param('rs', TYPE_MIPS_REG), 
                        param('rt', TYPE_MIPS_REG), param('shift', TYPE_U8)])
                    
                    opcode = int(chunks[2], 16)
                    fcnt = int(chunks[3], 16)

                    vals = [
                            Literal((opcode << 26) | (fcnt & 0x3f), TYPE_U32),
                            Binary(OP_SHL, Var('rs'), 21),
                            Binary(OP_SHL, Var('rt'), 16),
                            Binary(OP_SHL, Var('rd'), 11),
                            Binary(OP_SHL, Var('shift'), 6)
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))

                    yield func
                
                elif mode == 'J':
                    # Type J
                    # (opcode: 6b) (addr: 26b)
                    # OP addr
                    # addr has least two bits truncated and 4 topmost bits truncated too

                    func = Function(name, [param('addr', TYPE_U32)])

                    code = Literal(opcode << 26, TYPE_U32)
                    truncated = Binary(OP_BITWISE_AND, 0x3ffffff, Binary(OP_SHL, Var('addr'), 2))
                    
                    func += Set(TYPE_U32, Binary(OP_BITWISE_OR, code, truncated))

                    yield func
                
                else:
                    # Type I
                    # (opcode: 6b) (rs: 5b) (rt: 5b) (imm: 16b)
                    # OP rt, IMM(rs)
                    # OP rs, rt, IMM # for beq

                    func = Function(name, [param('rs', TYPE_MIPS_REG), param('rt', TYPE_MIPS_REG),
                        param('imm', TYPE_U16)])

                    opcode = int(chunks[2], 16)

                    vals = [
                        Literal(opcode << 26, TYPE_U32),
                        Binary(OP_SHL, Var('rs'), 21),
                        Binary(OP_SHL, Var('rt'), 16),
                        Var('imm')
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))

                    yield func
