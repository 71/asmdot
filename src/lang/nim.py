from asm.emit import *  # pylint: disable=W0614

class NimEmitter(Emitter):

    @property
    def language(self):
        return 'nim'

    @property
    def filename(self):
        return f'asmdot/private/{self.arch}.nim'

    @property
    def test_filename(self):
        return f'test/test{self.arch}.nim'

    def get_operator(self, op: Operator) -> str:
        dic = {
            OP_BITWISE_AND: 'and',
            OP_BITWISE_OR : 'or',
            OP_BITWISE_XOR: 'xor',
            OP_SHL: 'shl',
            OP_SHR: 'shr'
        }

        if op in dic:
            return dic[op]
        else:
            return op.op
    
    def get_builtin_name(self, builtin: Builtin) -> str:
        if builtin is BUILTIN_X86_PREFIX:
            return 'getPrefix'
        else:
            return builtin.name

    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(if ', expr.condition, ': ', expr.consequence, ' else: ', expr.alternative, ')')
        
        elif isinstance(expr, Var):
            self.write(expr.name)
        
        elif isinstance(expr, Call):
            self.write(expr.builtin, '(', join_any(', ', expr.args), ')')
        
        elif isinstance(expr, Literal):
            t = replace_pattern({ r'uint(\d+)': r'u\1', r'int(\d+)': r'i\1', r'.+': 'nop' }, str(expr.type.id))

            if t == 'nop':
                self.write(expr.value)
            else:
                self.write(expr.value, '\'', t)
        
        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value)
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if ', stmt.condition, ':')
            
            with self.indent.further():
                self.write_stmt(stmt.consequence)
            
            if stmt.alternative:
                self.writelinei('else:')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s)
        
        elif isinstance(stmt, Set):
            self.writelinei(f'cast[ptr {stmt.type}](buf)[] = ', stmt.value)
            self.writelinei(f'buf = cast[pointer](cast[uint](buf) + {stmt.type.size})')

        elif isinstance(stmt, Define):
            self.writelinei(f'var {stmt.name} = ', stmt.value)

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        name = fun.name

        if name in ['and']:
            name = name.capitalize()

        self.write(f'proc {name}*(buf: var pointer')

        underlying = []

        for name, typ in fun.params:
            self.write(f', {name}: {typ}')

            if typ.underlying:
                underlying.append((name, typ.underlying))
        
        self.write(') = \n')
        self.indent += 1

        if len(underlying):
            self.write('var\n', indent=True)
            
            with self.indent.further():
                for name, typ in underlying:
                    self.write(f'{name} = {typ} {name}\n', indent=True)
            
            self.write('\n')
        
        for condition in fun.conditions:
            self.write('assert ', condition, '\n', indent=True)

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.write('\n\n')
        self.indent -= 1

    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.write('type ', decl.type, '* {.pure.} = enum ## ', decl.descr, '\n')

            for name, value, descr, _ in decl.members:
                self.write('  ', name, ' = ', value, ' ## ', descr, '\n')
            
            self.write('\n\n')
            
            for name, value, descr, _ in decl.additional_members:
                self.write('template ', name, '*(typ: type ', decl.type, '): ', decl.type, ' =\n')
                self.write('  ## ', descr, '\n')
                self.write('  ', value, '\n\n')

            if decl.flags:
                self.write('proc `+`*(a, b: ', decl.type, '): ', decl.type, ' =\n')
                self.write('  ', decl.type, '(byte(a) + byte(b))\n')
                self.write('proc `and`*(a, b: ', decl.type, '): ', decl.type, ' =\n')
                self.write('  ', decl.type, '(byte(a) and byte(b))\n')
                self.write('proc `or`*(a, b: ', decl.type, '): ', decl.type, ' =\n')
                self.write('  ', decl.type, '(byte(a) or byte(b))\n\n')
        
        elif isinstance(decl, DistinctType):
            self.write('type ', decl.type, '* = distinct ', decl.type.underlying, ' ## ', decl.descr, '\n\n')

            if decl.constants:
                self.write('const\n')

                for name, value in decl.constants:
                    self.write('  ', name, '* = ', decl.type, ' ', value, '\n')

                self.write('\n\n')

        else:
            raise UnsupportedDeclaration(decl)

    def write_test_header(self):
        self.write(f'import unittest, ../asmdot/{self.arch}\n\n')
        self.write(f'suite "test {self.arch} assembler":\n')
        self.indent += 1

        self.writelinei('setup:')

        with self.indent.further():
            self.writelinei('var')

            with self.indent.further():
                self.writelinei('bytes = newSeqOfBytes[byte](100)')
                self.writelinei('buf = addr bytes[0]')
        
        self.writeline()

    def write_test(self, test: TestCase):
        self.writelinei(f'test "{test.name}":')
        self.indent += 1

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return arg.const.name
            if isinstance(arg, ArgEnumMember):
                return arg.member.name
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            args_str = ', '.join([ arg_str(arg) for arg in args ])

            self.writelinei('buf.', func.fullname, '(', args_str, ')')
        
        self.writeline()
        self.writelinei('check buf == "', test.expected_string, '"')
        self.writeline()

        self.indent -= 1
