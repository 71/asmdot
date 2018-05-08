from common import *  # pylint: disable=W0614

# Helpers

class ArmInstruction:
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

    def __init__(self):
        self.mnemo = ''
        self.full_mnemo = ''
        self.has_condition = False
        self.bits = 0

        self.w_index = 0
        self.i_index = 0
        self.s_index = 0

        self.rn_index = 0
        self.rd_index = 0
        self.shifter_index = 0


    def __str__(self):
        params = []
        body = [ 'uint32_t ins = 0x{:x};'.format(self.bits) ]

        if self.has_condition:
            params.append(param('condition', 'condition', 'cond'))
        if self.w_index:
            params.append(pswitch('write'))

        body.append('*(uint32_t*)(*{}) = ins;'.format(bufname))
        body.append('*{} += 4;'.format(bufname))

        return function(self.mnemo, stmts(*body), 4, *params)


# Lexing / parsing

from parsy import string, Result, ParseError

def parse_arm_instruction(line):
    pos   = 0
    instr = ArmInstruction()

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
            ('W', 1, None), ('S', 1, None), ('I', 1, None), ('L', 1, None), ('N', 1, None), ('R', 1, None), ('H', 1, None),
            ('Rn', 4, None), ('Rd', 4, None), ('Rm', 4, None), ('Rs', 4, None),
            ('RdHi', 4, None), ('RdLo', 4, None), ('CRd', 4, None), ('CRn', 4, None), ('CRm', 4, None),
            ('topimm', 12, None), ('botimm', 4, None), ('simm24', 24, None), ('shiftimm', 5, None)
        ]

        for word, size, attr in keywords:
            if word != keyword:
                continue
            if not attr:
                attr = '{}_index'.format(word.lower())

            setattr(instr, attr, pos)
            pos += size

            return

        print('Unknown operand ', keyword, '.')

    @parse('shifter')
    def shifter(_):
        nonlocal pos

        instr.shifter = (pos, 32 - pos)
        pos = 32

    modif = cond | bit0 | bit1 | shifter | keyword.desc('operand')
    full  = seq( (mnemo << ws), modif.sep_by(ws), end )

    return full.result(instr).parse(line)


# Translate

@translator('arm')
def translate(i, o):
    o.write("""
#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef enum {
    ///
    /// Equal.
    EQ = 0b0000,
    ///
    /// Not equal.
    NE = 0b0001,
    ///
    /// Carry set.
    CS = 0b0010,
    ///
    /// Unsigned higher or same.
    HS = 0b0010,
    ///
    /// Carry clear.
    CC = 0b0011,
    ///
    /// Unsigned lower.
    LO = 0b0011,
    ///
    /// Minus / negative.
    MI = 0b0100,
    ///
    /// Plus / positive or zero.
    PL = 0b0101,
    ///
    /// Overflow.
    VS = 0b0110,
    ///
    /// No overflow.
    VC = 0b0111,
    ///
    /// Unsigned higher.
    HI = 0b1000,
    ///
    /// Unsigned lower or same.
    LS = 0b1001,
    ///
    /// Signed greater than or equal.
    GE = 0b1010,
    ///
    /// Signed less than.
    LT = 0b1011,
    ///
    /// Signed greater than.
    GT = 0b1100,
    ///
    /// Signed less than or equal.
    LE = 0b1101,
    ///
    /// Always (unconditional).
    AL = 0b1110,
    ///
    /// Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).
    UN = 0b1111
} condition;\n\n""")

    instructions = []

    for line in i:
        line = line.strip()

        if not len(line):
            continue

        try:
            instr = parse_arm_instruction(line)
            instructions.append(instr)

            o.write( str(instr) )
        except ParseError as err:
            print('Error: ', err, '.')
            print('Invalid instruction: "', line.strip('\n'), '"')

            break
        else:
            o.write( '\n\n' )
