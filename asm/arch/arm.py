from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

from logzero import logger

# The ARM parser works by first creating a default ARM instruction (class defined below),
# and then setting its attributes as it encounters new elements.
# The current 'index' is also tracked, since values will be shifted to the left by
# this value when an instruction is encoded.
#
# For example, encountering the 'mode' keyword when parsing a line will set the
# 'mode_index' attribute of the ArmInstruction to the current index, which indicates
# that the encoded instruction will shift the parameter 'mode' to the left by a factor
# of 'index'.
#
# Once an ArmInstruction if fully built using the parser, it can be transformed into
# an AST using its 'to_function' method. The reason why we don't build the AST as we go
# is because some operands may be 'merged' into one; as such, knowledge of the whole
# instruction is needed before creating the AST.


# Helpers

class ArmInstruction:
    opts: Options

    mnemo = ''
    full_mnemo = ''
    has_condition = False
    bits = 0

    def with_mnemonic(self, mnemo):
        self.mnemo = mnemo.replace('#', '')
        self.full_mnemo = mnemo

    def update(self, key, val=None):
        if val:
            setattr(self, key, val)

            return self
        else:
            return lambda v: setattr(self, key, v)

    def add_bit(self, pos):
        self.bits += 1 << pos

    def __call__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)
    
    def to_function(self):
        params = []
        x : Expression = Literal(self.bits, TYPE_U32)

        def switch(name: str, val: int) -> Expression:
            return Binary(OP_SHL, Var(name), Literal(val, TYPE_BYTE))
        def add_expr(expr: Expression):
            nonlocal x

            x = Binary(OP_BITWISE_OR, x, expr)
        def shl(expr: Expression, v: int) -> Expression:
            return Binary(OP_SHL, expr, Literal(v, TYPE_U32))

        if self.has_condition:
            params.append(param('cond', TYPE_ARM_COND))
            x = Binary(OP_BITWISE_OR, x, Var('cond'))

        for attr, name in [ ('w', 'write'), ('i', 'i'), ('s', 's') ]:
            val = getattr(self, f'{attr}_index', None)

            if val is not None:
                params.append(pswitch(name))
                add_expr(switch(name, val))
        
        for attr, name in [ ('rn', 'rn'), ('rd', 'rd') ]:
            val = getattr(self, f'{attr}_index', None)

            if val is not None:
                params.append(param(name, TYPE_ARM_REG))
                add_expr(shl(Var(name), val))
        
        for name, typ in [ ('iflags', TYPE_ARM_IFLAGS), ('fieldmask', TYPE_ARM_FIELD), ('shift', TYPE_ARM_SHIFT), ('rotate', TYPE_ARM_ROTATION) ]:
            val = getattr(self, f'{name}_index', None)

            if val is not None:
                params.append(param(name, typ))
                add_expr(shl(Var(name), val))

        if hasattr(self, 'mode_index'):
            params.append(param('mode', TYPE_ARM_MODE))
            add_expr(shl(Var('mode'), self.mode_index))

        f = Function(self.mnemo, params)
        
        f += Set(TYPE_U32, x)
        f += Increase(4)

        return f


# Lexing / parsing

from parsy import string, Result, ParseError

def get_arm_parser(opts: Options):
    pos   = 32
    instr = ArmInstruction()
    instr.opts = opts

    mnemo = regex(r'[a-zA-Z0-9_#]+').map(instr.with_mnemonic)

    @parse('cond')
    def cond(_):
        nonlocal pos

        instr.has_condition = True
        pos -= 4
    
    @parse('0')
    def bit0(_):
        nonlocal pos

        pos -= 1
    
    @parse('1')
    def bit1(_):
        nonlocal pos

        pos -= 1
        instr.add_bit(pos)

    @parse(r'[\w+]+')
    def keyword(keyword):
        nonlocal pos

        keywords = [
            ('W', 1), ('S', 1), ('I', 1), ('L', 1), ('N', 1), ('R', 1), ('H', 1),
            ('Rn', 4), ('Rd', 4), ('Rm', 4), ('Rs', 4),
            ('RdHi', 4), ('RdLo', 4), ('CRd', 4), ('CRn', 4), ('CRm', 4),
            ('topimm', 12), ('botimm', 4), ('simm24', 24), ('shiftimm', 5), ('mode', 5),
            ('iflags', 3), ('fieldmask', 4), ('rotate', 2), ('shift', 2)
        ]

        for word, size in keywords:
            if word != keyword:
                continue

            pos -= size
            setattr(instr, f'{word.lower()}_index', pos)

            return

        logger.error(f'Unknown operand "{keyword}".')

    @parse('shifter')
    def shifter(_):
        nonlocal pos

        instr.shifter = (pos, 32 - pos)
        pos = 0
    
    @parse(end)
    def verify(_):
        nonlocal pos
    
        if pos != 0:
            logger.error(f'Invalid instruction "{instr.mnemo}".')

    modif = cond | bit0 | bit1 | shifter | keyword.desc('operand')
    full  = seq( (mnemo << ws), modif.sep_by(ws), verify )

    return full.result(instr)


# Architecture

class ArmArchitecture(Architecture):

    @property
    def name(self):
        return 'arm'
    
    @property
    def declarations(self) -> Iterator[Declaration]:
        yield DistinctType(TYPE_ARM_REG, 'An ARM register.')

        yield Enumeration(TYPE_ARM_COND, False, 'Condition for an ARM instruction to be executed.', [
            EnumerationMember('EQ', 0x0, 'Equal.'),
            EnumerationMember('NE', 0x1, 'Not equal.'),
            EnumerationMember('HS', 0x2, 'Unsigned higher or same.'),
            EnumerationMember('LO', 0x3, 'Unsigned lower.'),
            EnumerationMember('MI', 0x4, 'Minus / negative.'),
            EnumerationMember('PL', 0x5, 'Plus / positive or zero.'),
            EnumerationMember('VS', 0x6, 'Overflow.'),
            EnumerationMember('VC', 0x7, 'No overflow.'),
            EnumerationMember('HI', 0x8, 'Unsigned higher.'),
            EnumerationMember('LS', 0x9, 'Unsigned lower or same.'),
            EnumerationMember('GE', 0xA, 'Signed greater than or equal.'),
            EnumerationMember('LT', 0xB, 'Signed less than.'),
            EnumerationMember('GT', 0xC, 'Signed greater than.'),
            EnumerationMember('LE', 0xD, 'Signed less than or equal.'),
            EnumerationMember('AL', 0xE, 'Always (unconditional).'),
            EnumerationMember('UN', 0xF, 'Unpredictable (ARMv4 or lower).')
        ], [
            EnumerationMember('CS', 0x2, 'Carry set.'),
            EnumerationMember('CC', 0x3, 'Carry clear.')
        ])

        yield Enumeration(TYPE_ARM_MODE, False, 'Processor mode.', [
            EnumerationMember('USR', 0b10000, 'User mode.'),
            EnumerationMember('FIQ', 0b10001, 'FIQ (high-speed data transfer) mode.'),
            EnumerationMember('IRQ', 0b10010, 'IRQ (general-purpose interrupt handling) mode.'),
            EnumerationMember('SVC', 0b10011, 'Supervisor mode.'),
            EnumerationMember('ABT', 0b10111, 'Abort mode.'),
            EnumerationMember('UND', 0b11011, 'Undefined mode.'),
            EnumerationMember('SYS', 0b11111, 'System (privileged) mode.'),
        ], [])

        yield Enumeration(TYPE_ARM_SHIFT, False, 'Kind of a shift.', [
            EnumerationMember('LSL', 0b00, 'Logical shift left.'),
            EnumerationMember('LSR', 0b01, 'Logical shift right.'),
            EnumerationMember('ASR', 0b10, 'Arithmetic shift right.'),
            EnumerationMember('ROR', 0b11, 'Rotate right.')
        ], [
            EnumerationMember('RRX', 0b11, 'Shifted right by one bit.')
        ])

        yield Enumeration(TYPE_ARM_ROTATION, False, 'Kind of a right rotation.', [
            EnumerationMember('NOP',   0b00, 'Do not rotate.'),
            EnumerationMember('ROR8',  0b01, 'Rotate 8 bits to the right.'),
            EnumerationMember('ROR16', 0b10, 'Rotate 16 bits to the right.'),
            EnumerationMember('ROR24', 0b11, 'Rotate 24 bits to the right.')
        ])

        yield Enumeration(TYPE_ARM_FIELD, True, 'Field mask bits.', [
            EnumerationMember('C', 0b0001, 'Control field mask bit.'),
            EnumerationMember('X', 0b0010, 'Extension field mask bit.'),
            EnumerationMember('S', 0b0100, 'Status field mask bit.'),
            EnumerationMember('F', 0b1000, 'Flags field mask bit.')
        ])

        yield Enumeration(TYPE_ARM_IFLAGS, True, 'Interrupt flags.', [
            EnumerationMember('F', 0b001, 'FIQ interrupt bit.'),
            EnumerationMember('I', 0b010, 'IRQ interrupt bit.'),
            EnumerationMember('A', 0b100, 'Imprecise data abort bit.')
        ])

    def translate(self, input: IO[str]):
        for line in input:
            line = line.strip()

            if not len(line):
                continue

            try:
                yield get_arm_parser(self).parse(line).to_function()
            except ParseError as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)
            except Exception as err:
                stripped_line = line.strip('\n')

                logger.error(f'Invalid instruction: "{stripped_line}".')
                logger.exception(err)

                break
