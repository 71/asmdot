from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

from logzero import logger
from parsy import regex, string, ParseError


# Utils

@no_type_check  # mypy wants a return statement :(
def type_for_size(size: int) -> IrType:
    assert size in (8, 16, 32, 64, 128)

    if size == 8: return TYPE_X86_R8
    if size == 16: return TYPE_X86_R16
    if size == 32: return TYPE_X86_R32
    if size == 64: return TYPE_X86_R64
    if size == 128: return TYPE_X86_R128

def emit_opcode(opcode: Union[int, Expression]) -> Iterator[Statement]:
    if not isinstance(opcode, int):
        yield Set(TYPE_BYTE, opcode)
        yield Increase(1)
    elif opcode < 255:
        yield Set(TYPE_BYTE, Literal(opcode, TYPE_BYTE))
        yield Increase(1)
    else:
        if opcode < 255 * 255:
            size = 2
        else:
            size = 3
        
        yield Set(TYPE_I32, Literal(opcode, TYPE_I32))
        yield Increase(size)

def emit_prefix(sra: bool, bits: int) -> Iterator[Statement]:
    assert bits in (16, 64)

    v: Expression = Literal( 0x66 if bits == 16 else 0x48 , TYPE_BYTE)

    if sra:
        v = Binary(OP_ADD, v, Call(BUILTIN_X86_PREFIX, [ Param('operand') ]))

    return emit_opcode(v)

def pregister(name: str, size: int) -> Parameter:
    return param(name, type_for_size(size))


# Parser

def get_x86_parser(opts: Options):
    mnemo   = regex(r'[a-zA-Z]{3,}')
    opcode  = regex(r'[0-9a-fA-F]{1,2}').map(lambda x: int(x, base=16))
    hyphen  = string('-')

    @parse(opcode.sep_by(hyphen) << ws)
    def opcodes(opcodes: List[int]) -> int:
        r = 0

        for i, opcode in enumerate(opcodes):
            r = (r << (i * 4)) + opcode

        return r

    @parse(r'r\d{1,3}(-\d{2,3})?')
    def rsize(s: str) -> List[int]:
        i = s.find('-')

        if i == -1:
            return [ int(s[1:]) ]
        else:
            min, max = int(s[1:i]), int(s[i+1:])

            return [ n for n in [8, 16, 32, 64, 128] if min <= n <= max ]

    @parse(opcodes, mnemo)
    def instr_nop(opcode: int, name: str) -> Function:
        f = Function(name, [])
        f += emit_opcode(opcode)

        return f
    
    @parse(opcodes, mnemo, ws, rsize)
    def instr_single_reg(opcode: int, name: str, _, sizes: List[int]) -> Iterator[Function]:
        sra = True

        for size in sizes:
            f = Function(name, [ pregister('operand', size) ], fullname=f'{name}_r{size}')

            if size == 16:
                f += emit_prefix(sra, 16)
            elif size == 64:
                f += emit_prefix(sra, 64)
            else:
                f += Conditional(
                    Binary(OP_GT, Param('operand'), Literal(7, TYPE_BYTE)),
                    Block(list(emit_opcode(0x41)))
                )
            
            opcode_lit: Expression = Literal(opcode, TYPE_U8)

            if sra:
                opcode_lit = Binary(OP_ADD, opcode_lit, Param('operand'))

            f += emit_opcode(opcode_lit)

            yield f

    return instr_single_reg | instr_nop


# Architecture

class X86Architecture(Architecture):

    @property
    def name(self) -> str:
        return 'x86'
    
    def translate(self, input: IO[str]) -> Iterator[Function]:
        parser = get_x86_parser(self)

        for line in input:
            line = line.strip()

            if not len(line):
                continue

            try:
                instrs = parser.parse(line)

                if isinstance(instrs, Function):
                    yield instrs
                else:
                    for i in instrs:
                        yield i

            except ParseError as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)
            except Exception as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)

                break
