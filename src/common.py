def parse():
    import argparse

    parser = argparse.ArgumentParser(description='Generate assembler source.')

    parser.add_argument('--x86', action='store_true',
                        help='generate x86 sources')
    parser.add_argument('--arm', action='store_true',
                        help='generate arm sources')

    parser.add_argument('-p', '--prefix', action='store_true',
                        help='prefix methods by their architecture')
    parser.add_argument('-nb', '--no-body', action='store_true',
                        help='do not generate bodies')
    parser.add_argument('-r', '--return', choices=['size', 'success', 'void'], default='size',
                        help='change what functions return')

    parser.add_argument('-o', '--output', default='include',
                        help='change the output dir')
    parser.add_argument('-cc', '--calling-convention', default='',
                        help='change the calling convention')
    
    parser.add_argument('-b', '--binder', nargs='*', type=open,
                        help='use the given binder')
    
    return parser.parse_args()

args = parse()

prefix = ""
bufname = "buf"

output_dir = args.output

header = """
// Automatically generated file.
// Please see ../asm/{}.py for more informations.

#define byte unsigned char
#define RET(x) %RET
#define CALLCONV %CC

""".replace('%CC', args.calling_convention)

if getattr(args, 'return') == 'size':
    returntype = 'int'
    header = header.replace('%RET', 'return x')
elif getattr(args, 'return') == 'success':
    returntype = 'bool'
    header = header.replace('%RET', 'return x != 0')
else:
    returntype = 'void'
    header = header.replace('%RET', 'return')

binders = []

if args.binder:
    import os.path
    import sys
    import inspect

    sys.path.append(os.path.join(os.path.dirname(__file__), 'bind'))

    for b in args.binder:
        loc, glob = {}, {}

        exec(b.read(), loc, glob)

        b.close()

        for cln in glob:
            cl = glob[cln]

            if cl.__name__ in ['Binder', 'OutputBinder']:
                continue

            if any(bc.__name__ == 'Binder' for bc in inspect.getmro(cl)):
                b = cl()
                b._opts = args
                binders.append(b)

def io(arch):
    notifiers = []

    for binder in binders:
        n = binder.change_arch(arch)

        if n:
            n.__enter__()
            notifiers.append(n)

    class IO():
        def __enter__(self):
            self.i = open('instructions/{}.txt'.format(arch), 'r')
            self.o = open('{}/{}.h'.format(output_dir, arch), 'w')

            self.o.write(header.format(arch))

            return (self.i, self.o)

        def __exit__(self, type, value, traceback):
            for n in notifiers:
                n.__exit__(type, value, traceback)
            n = []

            self.i.close()
            self.o.close()

    return IO()


def switchp(name):
    return "switch", "bool", name

def stmts(*args):
    return "\n  ".join(args)

def function(name, body, *params):
    for binder in binders:
        binder.define(name, params)

    parameters = ""

    for (kind, ctype, name) in params:
        parameters += "/* {} */ {} {}, ".format(kind, ctype, name)

    sig = "{} CALLCONV {}{}({}void** {})".format(returntype, prefix, name, parameters, bufname)

    if args.no_body:
        return "{};".format(sig)
    else:
        return "{} {{\n  {}\n}}".format(sig, body)

def functions(*args):
    return "\n".join(args)

def ret(size):
    return "RET({});".format(size)


tokens = (
    'OPCODE', 'MNEMO', 'END'
)

def make_lexer():
    import ply.lex as lex
    
    t_ignore = ' \t'
    t_MNEMO = r'[a-zA-Z]+'

    def t_END(t):
        r'\n+'
        t.lexer.lineno += len(t.value)
        return t

    def t_OPCODE(t):
        r'[0-9a-fA-F]+'
        t.value = int(t.value, base=16)
        return t

    def t_error(t):
        pass

    return lex.lex()

lexer = make_lexer()

from ply.yacc import yacc

def p_error(p):
    pass
