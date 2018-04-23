from common import *  # pylint: disable=W0614

# Helpers

def emit_opcode(opcode):
    if opcode < 255:
        return "*(byte*)({}++) = 0x{:02x};".format(bufname, opcode)
    else:
        if opcode < 255 * 255:
            size = 2
        else:
            size = 3
        
        return "*(int*)({} += {}) = 0x{:02x};".format(bufname, size, opcode)


# Lexing / parsing

def p_nop(p):
    "ins : OPCODE MNEMO END"
    body = stmts(emit_opcode(p[1]), ret(1))

    p[0] = function(p[2], body)

def p_single_reg(p):
    "ins : OPCODE MNEMO 'r' END"
    name = "{}_r{}".format(p[2], p[3])
    body = stmts(emit_opcode(p[1]), ret(2))
    
    p[0] = functions(
        function(name, body),
        function(name, body),
        function(name, body))

lexer = make_lexer()
parser = make_parser()


# Translate

@translator('x86')
def translate(i, o):
    for line in i:
        if line == "":
            continue

        o.write( parser.parse(line, lexer=lexer) )
        o.write( '\n\n' )
