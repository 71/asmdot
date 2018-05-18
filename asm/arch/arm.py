from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

from logzero import logger


# Helpers

class ArmInstruction:
    opts: Options

    mnemo = ''
    full_mnemo = ''
    has_condition = False
    bits = 0

    w_index = 0
    i_index = 0
    s_index = 0

    rn_index = 0
    rd_index = 0
    shifter_index = 0
    mode_index = 0

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
            return Binary(OP_SHL, Param(name), Literal(val, TYPE_BYTE))
        def add_expr(expr: Expression):
            nonlocal x

            x = Binary(OP_BITWISE_OR, x, expr)
        def shl(expr: Expression, v: int) -> Expression:
            return Binary(OP_SHL, expr, Literal(v, TYPE_U32))

        if self.has_condition:
            params.append(param('cond', TYPE_ARM_COND))
            x = Binary(OP_BITWISE_OR, x, Param('cond'))

        for attr, name in [ ('w', 'write'), ('i', 'i'), ('s', 's') ]:
            val = getattr(self, f'{attr}_index', None)

            if val:
                params.append(pswitch(name))
                add_expr(switch(name, val))
        
        for attr, name in [ ('rn', 'rn'), ('rd', 'rd') ]:
            val = getattr(self, f'{attr}_index', None)

            if val:
                params.append(param(name, TYPE_ARM_REG))
                add_expr(shl(Param(name), val))
        
        for name, typ in [ ('iflags', TYPE_ARM_IFLAGS), ('fieldmask', TYPE_ARM_FIELD), ('shift', TYPE_ARM_SHIFT), ('rotate', TYPE_ARM_ROTATION) ]:
            val = getattr(self, f'{name}_index', None)

            if val:
                params.append(param(name, typ))
                add_expr(shl(Param(name), val))

        if self.mode_index:
            params.append(param('mode', TYPE_ARM_MODE))
            add_expr(shl(Param('mode'), self.mode_index))

        f = Function(self.mnemo, params)
        
        f += Set(TYPE_U32, x)
        f += Increase(4)

        return f


# Lexing / parsing

from parsy import string, Result, ParseError

def get_arm_parser(opts: Options):
    pos   = 0
    instr = ArmInstruction()
    instr.opts = opts

    mnemo = regex(r'[a-zA-Z0-9_#]+').map(instr.with_mnemonic)

    @parse('cond')
    def cond(_):
        nonlocal pos

        instr.has_condition = True
        pos += 4
    
    @parse('0')
    def bit0(_):
        nonlocal pos

        pos += 1
    
    @parse('1')
    def bit1(_):
        nonlocal pos

        instr.add_bit(pos)
        pos += 1

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

            setattr(instr, f'{word.lower()}_index', pos)
            pos += size

            return

        logger.error(f'Unknown operand "{keyword}".')

    @parse('shifter')
    def shifter(_):
        nonlocal pos

        instr.shifter = (pos, 32 - pos)
        pos = 32

    modif = cond | bit0 | bit1 | shifter | keyword.desc('operand')
    full  = seq( (mnemo << ws), modif.sep_by(ws), end )

    return full.result(instr)


# Architecture

class ArmArchitecture(Architecture):

    @property
    def name(self):
        return 'arm'

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
