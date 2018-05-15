from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

from logzero import logger
from parsy import regex, string, ParseError

# Parser

def get_x86_parser(opts: Options):
    def define_offset() -> Statement:
        return Define(TYPE_I8, 'offset', Literal(0))
    def offset_var() -> Expression:
        return Var('offset')

    def emit_opcode(opcode, offset=None, inc=True) -> Iterator[Statement]:
        inc_target = None if opts.mutable_buffer else 'offset'

        if not isinstance(opcode, int):
            yield Set(TYPE_BYTE, opcode, offset)

            if inc or opts.mutable_buffer:
                yield Increase(1, inc_target)
        elif opcode < 255:
            yield Set(TYPE_BYTE, Literal(opcode), offset)

            if inc or opts.mutable_buffer:
                yield Increase(1, inc_target)
        else:
            if opcode < 255 * 255:
                size = 2
            else:
                size = 3
            
            yield Set(TYPE_I32, Literal(opcode), offset)

            if inc or opts.mutable_buffer:
                yield Increase(size, inc_target)

    def emit_prefix(sra, bits) -> Iterator[Statement]:
        if bits == 16:
            return emit_opcode('0x66 + prefix_adder(operand)' if sra else '0x66')
        elif bits == 64:
            return emit_opcode('0x48 + prefix_adder(operand)' if sra else '0x48')
        else:
            assert(False)

    def pregister(name, size) -> Parameter:
        return param(name, IrType(f'reg{size}'))



    mnemo   = regex(r'[a-zA-Z]{3,}')
    opcode  = regex(r'[0-9a-fA-F]{1,2}').map(lambda x: int(x, base=16))
    hyphen  = string('-')

    @parse(opcode.sep_by(hyphen) << ws)
    def opcodes(opcodes):
        r = 0

        for i, opcode in enumerate(opcodes):
            r = (r << (i * 4)) + opcode

        return r

    @parse(r'r\d{1,3}(-\d{2,3})?')
    def rsize(s):
        i = s.find('-')

        if i == -1:
            return [ int(s[1:]) ]
        else:
            min, max = int(s[1:i]), int(s[i+1:])

            return [ n for n in [8, 16, 32, 64, 128] if min <= n <= max ]

    @parse(opcodes, mnemo)
    def instr_nop(opcode, name):
        f = Function(name, [])

        f += emit_opcode(opcode, inc=False)
        f += Return(Literal(1 if opcode < 255 else 2 if opcode < 255*255 else 3))

        return f
    
    @parse(opcodes, mnemo, ws, rsize)
    def instr_single_reg(opcode, name, _, sizes):
        sra = True

        for size in sizes:
            f = Function(name, [ pregister('operand', size) ], fullname=f'{name}_r{size}')

            f += define_offset()

            if size == 16:
                f += emit_prefix(sra, 16)
            elif size == 64:
                f += emit_prefix(sra, 64)
            else:
                f += Conditional(
                    Binary(OP_GT, Param('operand'), Literal(7)),
                    Block(list(emit_opcode(0x41)))
                )

            if sra:
                opcd = f'0x{opcode:02x} + operand'
                f += emit_opcode(opcd, offset_var())
            else:
                f += emit_opcode(opcode, offset_var())

            if opts.return_size:
                f += Return(offset_var())

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
