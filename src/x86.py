from common import *  # pylint: disable=W0614

# Helpers

def emit_opcode(opcode):
    if not isinstance(opcode, int):
        return '*(byte*)((*{})++) = {};'.format(bufname, opcode)
    elif opcode < 255:
        return '*(byte*)((*{})++) = 0x{:02x};'.format(bufname, opcode)
    else:
        if opcode < 255 * 255:
            size = 2
        else:
            size = 3
        
        return '*(int*)((*{}) += {}) = 0x{:04x};'.format(bufname, size, opcode)

def emit_prefix(sra, bits):
    if bits == 16:
        v = emit_opcode('0x66 + prefix_adder(operand)' if sra else '0x66')
        return stmts('#if !NO16BITS_PREFIX', v, '#endif')
    elif bits == 64:
        v = emit_opcode('0x48 + prefix_adder(operand)' if sra else '0x48')
        return stmts('#if !NO64BITS_PREFIX', v, '#endif')


def pregister(name, size):
    return 'register', 'reg{}'.format(size), name


# Lexing / parsing

from parsy import regex, seq, string, ParseError

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
    body = stmts(emit_opcode(opcode))
    
    return function(name, body, None)

@parse(opcodes, mnemo, ws, rsize)
def instr_single_reg(opcode, name, _, sizes):
    sra = True
    fns = []

    for size in sizes:
        name = "{}_r{}".format(name, size)

        if size == 16:
            body = [ emit_prefix(sra, 16) ]
        elif size == 64:
            body = [ emit_prefix(sra, 64) ]
        else:
            body = ['if (operand > 7) {}'.format(emit_opcode(0x41))]

        if sra:
            opcd = '0x{:02x} + operand'.format(opcode)
            body = [ *body, emit_opcode(opcd) ]
        else:
            body = [ *body, emit_opcode(opcode) ]

        fns.append(function(name, stmts(*body), None, pregister('operand', size)))

    return functions(*fns)

instr = instr_single_reg | instr_nop


# Translate

@translator('x86')
def translate(i, o):
    o.write("""
#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 && (r -= 8) == r)

""")

    for line in i:
        line = line.strip()

        if not len(line):
            continue

        try:
            o.write( instr.parse(line) )
        except Exception as err:
            print('Error: ', err, '.')
            print('Invalid instruction: "', line.strip('\n'), '"')

            break
        else:
            o.write( '\n\n' )

    for i, r in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '08', '09', '10', '11', '12', '13', '14', '15']):
        o.write( '#define r_{} 0x{:01x}\n'.format(r, i) )
