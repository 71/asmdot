from asmdot import *  # pylint: disable=W0614

@handle_command_line()
class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'asm/{self.arch}.py'

    @property
    def test_filename(self):
        return f'tests/test_{self.arch}.py'


    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'u?int\d+': 'int'
        }, ty.id)

    def get_function_name(self, function: Function) -> str:
        if function.initname in ('and', 'or'):
            return function.initname + '_'
        else:
            return function.initname
    
    def get_operator(self, op: Operator) -> str:
        dic = {
            OP_BITWISE_AND: 'and',
            OP_BITWISE_OR : 'or',
            OP_AND: 'and',
            OP_OR : 'or',
        }

        if op in dic:
            return dic[op]
        else:
            return op.op


    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)
        
        self.indent = Indent('    ')


    def write_header(self):
        self.write('import struct\nfrom enum import Enum, Flag\nfrom typing import NewType\n\n')

    def write_separator(self):
        self.write(f'''
class {self.arch.capitalize()}Assembler:
    """Assembler that targets the {self.arch} architecture."""
    def __init__(self, size: int) -> None:
        assert size > 0

        self.size = size
        self.buf = bytearray(size)
        self.pos = 0

''')
        self.indent += 1

    def write_footer(self):
        self.indent -= 1


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
            self.write(expr.value)
            
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
            if stmt.type.under in [TYPE_U8, TYPE_I8]:
                self.writelinei('self.buf[self.pos] = ', stmt.value)
            else:
                endian = '>' if self.bigendian else '<'
                
                self.writelinei('struct.pack_into("', endian, 'I", self.buf, self.pos, ',
                                stmt.value, ')')

            self.writelinei('self.pos += ', stmt.type.size)

        elif isinstance(stmt, Define):
            self.writelinei(stmt.name, ' = ', stmt.value)

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writei(f'def {fun.name}(self')

        for name, typ, _ in fun.params:
            self.write(f', {name}: {typ}')

        self.writeline(') -> None:')
        self.indent += 1
        self.writelinei('"""', fun.descr, '"""')

        for condition in fun.conditions:
            self.writelinei('assert ', condition, '\n')

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.indent -= 1
        self.writeline()


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            sub = 'Flag' if decl.flags else 'Enum'

            self.write('class ', decl.type, f'(int, {sub}):\n')
            self.indent += 1
            self.write('"""', decl.descr, '"""\n', indent=True)

            for name, value, _, _ in decl.members + decl.additional_members:
                self.write(name, ' = ', value, '\n', indent=True)

            self.write('\n')
            self.indent -= 1

        elif isinstance(decl, DistinctType):
            self.write(decl.type, ' = NewType("', decl.type, '", ', decl.type.underlying, ')\n')

            for name, value in decl.constants:
                self.write('setattr(', decl.type, ', "', name, '", ', decl.type, '(', value, '))\n')
            
            self.write('\n')

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        self.write(f'from asm.{self.arch} import *  # pylint: disable=W0614\n\n')

    def write_test(self, test: TestCase):
        self.write('def ', test.name.replace(' ', '_'), '():\n')
        self.indent += 1

        self.writelinei('asm = ', self.arch.capitalize(), 'Assembler(', len(test.expected), ')')
        self.writeline()

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.type.type}.{arg.const.name}'
            if isinstance(arg, ArgEnumMember):
                return f'{arg.enum.type}.{arg.member.name}'
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            args_str = ', '.join([ arg_str(arg) for arg in args ])

            self.writelinei('asm.', func.name, '(', args_str, ')')

        self.writeline()
        self.writelinei('assert asm.buf == b"', test.expected_string, '"')
        self.writeline()

        self.indent -= 1
