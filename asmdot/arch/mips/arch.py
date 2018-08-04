from ...ast  import *   # pylint: disable=W0614
from ..      import *   # pylint: disable=W0614

from functools import reduce

class MipsArchitecture(Architecture):

    @property
    def name(self) -> str:
        return 'mips'

    @property
    def tests(self):
        from .tests import MipsTestSource

        return MipsTestSource()
    
    @property
    def declarations(self) -> Declarations:
        mips_registers = [
                'zero', 'at', 'v0', 'v1',
                'a0', 'a1', 'a2', 'a3',
                't0', 't1', 't2', 't3',
                't4', 't5', 't6', 't7',
                's0', 's1', 's2', 's3',
                's4', 's5', 's6', 's7',
                't8', 't9', 'k0', 'k1',
                'gp', 'sp', 'fp', 'ra'
        ]
        yield DistinctType(TYPE_MIPS_REG, 'A Mips register.', [ Constant(n, i) for i, n in enumerate(mips_registers) ])

    @property
    def functions(self) -> Functions:
        def cast(var: Union[str, Expression], bits: int) -> Binary:
            """Casts a variable to a fixed number of bits."""
            if isinstance(var, str):
                var = Var(var)
            return Binary(OP_BITWISE_AND, var, Literal((1 << bits) - 1, TYPE_U32))

        with open(relative('data.txt'), 'r') as input:
            for line in input:
                line = line.strip()

                if not line.startswith('#') and len(line) > 0:
                    chunks = line.split(' ')
                    mode = chunks[0]
                    fullname = chunks[1]
                    u_idx = fullname.find('_')
                    name = fullname if u_idx == -1 else fullname[:u_idx]

                    if mode == 'R': 
                        # Type R
                        # (opcode: 6b) (rs: 5b) (rt: 5b) (rd: 5b) (shift: 5b) (funct: 6b) 
                        # OP rd, rs, rt

                        func = Function(name, [ param('rd', TYPE_MIPS_REG, TYPE_U32),
                                                param('rs', TYPE_MIPS_REG, TYPE_U32), 
                                                param('rt', TYPE_MIPS_REG, TYPE_U32),
                                                param('shift', TYPE_U8, TYPE_U32) ],
                                        fullname=fullname)
                        
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
                                                param('target', TYPE_U16, TYPE_U32) ],
                                        fullname=fullname)
                        
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

                        func = Function(name, [ param('address', TYPE_U32) ],
                                        fullname=fullname)

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
                                                param('imm', TYPE_U16, TYPE_U32)],
                                        fullname=fullname)

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
