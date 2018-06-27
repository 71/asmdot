from ...ast  import *   # pylint: disable=W0614
from ..      import *   # pylint: disable=W0614

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

    @translate()
    def functions(self, input: IO[str]) -> Functions:
        def cast(var: Union[str, Expression], bits: int) -> Binary:
            """Casts a variable to a fixed number of bits."""
            if isinstance(var, str):
                var = Var(var)
            return Binary(OP_BITWISE_AND, var, Literal((1 << bits) - 1, TYPE_U32))

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

                    func = Function(name, [ param('rd', TYPE_MIPS_REG, TYPE_U32),
                                            param('rs', TYPE_MIPS_REG, TYPE_U32), 
                                            param('rt', TYPE_MIPS_REG, TYPE_U32),
                                            param('shift', TYPE_U8, TYPE_U32) ])
                    
                    opcode = int(chunks[2], 16)
                    fcnt = int(chunks[3], 16)

                    vals = [
                            Literal((opcode << 26) | (fcnt & 0x3f), TYPE_U32),
                            Binary(OP_SHL, cast(Var('rs'), 5), Literal(21, TYPE_U32)),
                            Binary(OP_SHL, cast(Var('rt'), 5), Literal(16, TYPE_U32)),
                            Binary(OP_SHL, cast(Var('rd'), 5), Literal(11, TYPE_U32)),
                            Binary(OP_SHL, cast(Var('shift'), 5), Literal(6, TYPE_U32))
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))

                    yield func
                
                elif mode == 'RI':
                    # type RI
                    # mode for branches
                    # (opcode: 6b) (register source: 5b) (funct: 5b) (imm: 16b)
                    func = Function(name, [ param('rs', TYPE_MIPS_REG, TYPE_U32),
                                            param('target', TYPE_U16, TYPE_U32) ])
                    
                    opcode = int(chunks[2], 16)
                    fcnt = int(chunks[3], 16)
                    
                    vals = [
                        Literal(opcode << 26, TYPE_U32),
                        Binary(OP_SHL, cast(Var('rs'), 5), Literal(16, TYPE_U32)),
                        cast(Binary(OP_SHR, Var('target'), Literal(2, TYPE_U32)), 16)
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))
                    
                    yield func

                elif mode == 'J':
                    # Type J
                    # (opcode: 6b) (addr: 26b)
                    # OP address
                    # address has least two bits truncated and 4 topmost bits truncated too

                    func = Function(name, [ param('address', TYPE_U32) ])

                    opcode = int(chunks[2], 16)

                    code = Literal(opcode << 26, TYPE_U32)
                    truncated = cast(Binary(OP_SHR, Var('address'), Literal(2, TYPE_U32)), 26)
                    
                    func += Set(TYPE_U32, Binary(OP_BITWISE_OR, code, truncated))

                    yield func
                
                else:
                    # Type I
                    # (opcode: 6b) (rs: 5b) (rt: 5b) (imm: 16b)
                    # OP rt, IMM(rs)
                    # OP rs, rt, IMM # for beq

                    func = Function(name, [ param('rs', TYPE_MIPS_REG, TYPE_U32),
                                            param('rt', TYPE_MIPS_REG, TYPE_U32),
                                            param('imm', TYPE_U16, TYPE_U32)])

                    opcode = int(chunks[2], 16)
                    immediate = cast(Var('imm'), 16)

                    if name in ['beq', 'bne', 'blez', 'bgtz']:
                        immediate = Binary(OP_SHR, immediate, 2)

                    vals = [
                        Literal(opcode << 26, TYPE_U32),
                        Binary(OP_SHL, cast(Var('rs'), 5), Literal(21, TYPE_U32)),
                        Binary(OP_SHL, cast(Var('rt'), 5), Literal(16, TYPE_U32)),
                        immediate
                    ]

                    func += Set(TYPE_U32, reduce(lambda a, b: Binary(OP_BITWISE_OR, a, b), vals))

                    yield func
