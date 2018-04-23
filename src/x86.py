from common import *  # pylint: disable=W0614

# Helpers

def emit_opcode(opcode):
    if not isinstance(opcode, int):
        return '*(byte*)({}++) = {};'.format(bufname, opcode)
    elif opcode < 255:
        return '*(byte*)({}++) = 0x{:02x};'.format(bufname, opcode)
    else:
        if opcode < 255 * 255:
            size = 2
        else:
            size = 3
        
        return '*(int*)({} += {}) = 0x{:04x};'.format(bufname, size, opcode)

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

def t_RSIZE(t):
    r'r\d{1,3}(-\d{2,3})?'
    i = t.value.find('-')

    if i == -1:
        t.value = [ int(t.value[1:]) ]
    else:
        min, max = int(t.value[1:i]), int(t.value[i+1:])
        t.value = []

        for n in [8, 16, 32, 64, 128]:
            if min <= n <= max:
                t.value.append(n)

    return t

def p_nop(p):
    "ins : OPCODE MNEMO"
    body = stmts(emit_opcode(p[1]), ret(1))

    p[0] = function(p[2], body)

def p_single_reg(p):
    "ins : OPCODE MNEMO RSIZE"
    sra = True
    fns = []

    for size in p[3]:
        name = "{}_r{}".format(p[2], size)

        if size == 16:
            body = [ emit_prefix(sra, 16) ]
        elif size == 64:
            body = [ emit_prefix(sra, 64) ]
        else:
            body = []

        if sra:
            opcd = '0x{:02x} + operand'.format(p[1])
            body = [ *body, emit_opcode(opcd), ret(1) ]
        else:
            body = [ *body, emit_opcode(p[1]), ret(2) ]

        fns.append(function(name, stmts(*body), pregister('operand', size)))

    p[0] = functions(*fns)


# Translate

@translator('x86')
def translate(i, o):
    tokens = (*default_tokens, 'RSIZE')  # pylint: disable=W0612

    lexer = make_lexer()
    parser = make_parser()

    o.write("""
#define reg8  byte
#define reg16 byte
#define reg32 byte
#define reg64 byte
#define prefix_adder(r) (r > 7 ? 1 : 0)

""")

    for line in i:
        if line == "":
            continue

        o.write( parser.parse(line, lexer=lexer) )
        o.write( '\n\n' )

    for i, r in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', '08', '09', '10', '11', '12', '13', '14', '15']):
        o.write( '#define r_{} 0x{:01x}\n'.format(r, i) )
