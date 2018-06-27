from ...ast  import *   # pylint: disable=W0614
from ..parse import *   # pylint: disable=W0614

from logzero import logger
from parsy import regex, string, ParseError

# The x86 parser works by recognizing specific instructions (for instance,
# an instruction with no operand, or an instruction with one register operand),
# and generating one or many (when multiple sizes can be accepted) functions
# that correspond to that instruction.
#
# To make all this easier, we also have a set of parsers that do not return functions,
# but instead return other values that can then be aggregated into a full instruction.


# Helpers

@no_type_check  # mypy wants a return statement :(
def regtype_for_size(size: int) -> IrType:
    assert size in (8, 16, 32, 64, 128)

    if size == 8: return TYPE_X86_R8
    if size == 16: return TYPE_X86_R16
    if size == 32: return TYPE_X86_R32
    if size == 64: return TYPE_X86_R64
    if size == 128: return TYPE_X86_R128

@no_type_check  # mypy wants a return statement :(
def immtype_for_size(size: int) -> IrType:
    assert size in (8, 16, 32, 64)

    if size == 8: return TYPE_I8
    if size == 16: return TYPE_I16
    if size == 32: return TYPE_I32
    if size == 64: return TYPE_I64


def emit_opcode(opcode: Union[int, List[int], Expression]) -> Iterator[Statement]:
    if isinstance(opcode, int):
        yield Set(TYPE_BYTE, Literal(opcode, TYPE_BYTE))
    elif isinstance(opcode, tuple(expressionClasses)):
        yield Set(TYPE_BYTE, opcode)
    else:
        for opc in opcode:
            yield Set(TYPE_BYTE, Literal(opc, TYPE_BYTE))

def emit_prefix(sra: bool, bits: int) -> Iterator[Statement]:
    assert bits in (16, 64)

    v: Expression = Literal( 0x66 if bits == 16 else 0x48 , TYPE_BYTE)

    if sra:
        v = Binary(OP_ADD, v, Call(BUILTIN_X86_PREFIX, [ Var('operand') ]))

    return emit_opcode(v)

def pregister(name: str, size: int) -> Parameter:
    return param(name, regtype_for_size(size))

def pimm(name: str, size: int) -> Parameter:
    return param(name, immtype_for_size(size))


# Parser

def get_x86_parser(opts: Options):
    mnemo   = regex(r'[a-zA-Z]+')
    mnemos  = mnemo.sep_by(string('/'))

    opcode  = regex(r'[0-9a-fA-F]{1,2}').map(lambda x: int(x, base=16))
    hyphen  = string('-')

    funcs   = {}

    def parse_instr(*args):
        """Indicates a function that parses an instruction.
           Informations such as opcode and name will be added automatically."""

        def decorator(func):
            funcs[func.__name__] = func

            @parse(opcodes, mnemos, ws, *args)
            def inner(opcodes: List[int], names: List[str], _, *args):
                for fun in func(opcodes, *args):
                    for name in names:
                        fullname = name + fun.fullname
                        yield fun.with_name(name, fullname)
            
            return inner
        
        return decorator

    opcodes = opcode.sep_by(hyphen) << ws
    
    def get_size_parser(prefix: str):
        @parse(prefix + r'\d{1,3}(-\d{2,3})?')
        def inner(s: str) -> List[int]:
            b = len(s) - len(s.lstrip('abcdefghijklmnopqrstuvwxyz'))
            i = s.find('-')

            if i == -1:
                return [ int(s[b:]) ]
            else:
                min, max = int(s[b:i]), int(s[i+1:])

                return [ n for n in [8, 16, 32, 64, 128] if min <= n <= max ]
        
        return inner

    rsize = get_size_parser('r')
    rmsize = get_size_parser('rm')
    immsize = get_size_parser('(imm|rel)')

    @parse(opcodes, mnemos)
    def instr_nop(opcodes: List[int], names: List[str]) -> Functions:
        opc = emit_opcode(opcodes)

        for name in names:
            f = Function(name, [])
            f.body.extend(opc)

            yield f

    @parse_instr(rsize)
    def instr_single_reg(opcodes: List[int], sizes: List[int]) -> Functions:
        sra = True

        for size in sizes:
            f = Function('', [ pregister('operand', size) ], fullname=f'_r{size}')

            if size == 16:
                f += emit_prefix(sra, 16)
            elif size == 64:
                f += emit_prefix(sra, 64)
            else:
                f += Conditional(
                    Binary(OP_GT, Var('operand'), Literal(7, TYPE_BYTE)),
                    Block(list(emit_opcode(0x41)))
                )
            
            if len(opcodes) > 1:
                for i in range(len(opcodes) - 1):
                    f += emit_opcode(opcodes[i])

            opcode_lit: Expression = Literal(opcodes[len(opcodes) - 1], TYPE_U8)

            if sra:
                opcode_lit = Binary(OP_ADD, opcode_lit, Var('operand'))

            f += emit_opcode(opcode_lit)

            yield f
    
    @parse_instr(immsize)
    def instr_single_imm(opcodes: List[int], sizes: List[int]) -> Functions:
        for size in sizes:
            f = Function('', [ pimm('operand', size) ], fullname=f'_imm{size}')

            if size == 16:
                f += emit_prefix(False, 16)
            elif size == 64:
                f += emit_prefix(False, 64)
            
            f += emit_opcode(opcodes)
            f += Set(immtype_for_size(size), Var('operand'))

            yield f
    
    @parse_instr(rmsize, ws, immsize, ws, string('+'), opcode)
    def instr_reg_imm_plus(opcodes: List[int], rsizes: List[int], _, immsizes: List[int],
                           __, ___, plus: int) -> Functions:
        for rsize in rsizes:
            for isize in immsizes:
                fullname = f'_rm{rsize}_imm{isize}'
                f = Function('', [ pregister('reg', rsize), pimm('value', isize) ], fullname)

                if rsize == 16:
                    f += emit_prefix(False, 16)
                elif rsize == 64:
                    f += emit_prefix(False, 64)
                
                f += emit_opcode(opcodes)
                f += Set(regtype_for_size(rsize), Binary(OP_ADD, Var('reg'), Literal(plus, TYPE_U8)))
                f += Set(immtype_for_size(isize), Var('value'))

                yield f

    return instr_reg_imm_plus | instr_single_reg | instr_single_imm | instr_nop


# Architecture

class X86Architecture(Architecture):

    @property
    def name(self) -> str:
        return 'x86'
    
    @property
    def declarations(self) -> Declarations:
        yield DistinctType(TYPE_X86_R8,   'An x86 8-bits register.',   [ Constant(n, i) for i, n in enumerate('al, cl, dl, bl, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b'.split(', ')) ])
        yield DistinctType(TYPE_X86_R16,  'An x86 16-bits register.',  [ Constant(n, i) for i, n in enumerate('ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w'.split(', ')) ])
        yield DistinctType(TYPE_X86_R32,  'An x86 32-bits register.',  [ Constant(n, i) for i, n in enumerate('eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d'.split(', ')) ])
        yield DistinctType(TYPE_X86_R64,  'An x86 64-bits register.',  [ Constant(n, i) for i, n in enumerate('rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15'.split(', ')) ])
        yield DistinctType(TYPE_X86_R128, 'An x86 128-bits register.', [])
    
    def translate(self, input: IO[str]) -> Functions:
        parser = get_x86_parser(self)

        for line in input:
            if not len(line) or line[0] == '#':
                continue

            line = line.strip()

            if not len(line):
                continue

            try:
                for fun in parser.parse(line):
                    yield fun

            except ParseError as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)
            except Exception as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)

                break
