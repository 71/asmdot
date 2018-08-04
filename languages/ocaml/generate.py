from asmdot import *  # pylint: disable=W0614

@handle_command_line()
class OCamlEmitter(Emitter):
    
    @property
    def language(self):
        return 'ocaml'

    @property
    def filename(self):
        return f'src/{self.arch}.ml'

    @property
    def test_filename(self):
        return f'test/test{self.arch}.ml'


    def get_function_name(self, function: Function) -> str:
        return function.fullname
    

    def write_header(self):
        self.write('open Core\n\n')

    def write_separator(self):
        self.writeline()


    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')

        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)

        elif isinstance(expr, Ternary):
            self.write('(if ', expr.condition, ' then ', expr.consequence, ' else ', expr.alternative, ')')

        elif isinstance(expr, Var):
            self.write(expr.name)

        elif isinstance(expr, Call):
            self.write(expr.builtin, ' ', join_any(' ', expr.args))

        elif isinstance(expr, Literal):
            self.write(expr.value)

        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' <- ', stmt.value)
        elif isinstance(stmt, Conditional):
            self.writelinei('if ', stmt.condition, ' then')

            with self.indent.further():
                self.write_stmt(stmt.consequence)

            if stmt.alternative:
                self.writelinei('else')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s)
    
        elif isinstance(stmt, Set):
            call = 'Iobuf.Poke.'

            if stmt.type.under in (TYPE_U8, TYPE_U16, TYPE_U32, TYPE_U64):
                call += 'u'
            
            call += f'int{stmt.type.size * 8}'

            if stmt.type.under not in (TYPE_U8, TYPE_I8):
                call += '_be' if self.bigendian else '_le'
            
            self.writelinei(call, ' buf ', stmt.value, ';')
            self.writelinei('Iobuf.advance buf ', stmt.type.size)

        elif isinstance(stmt, Define):
            self.writelinei('let mutable ', stmt.name, ' = ', stmt.value, ' in')

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        names = 'buf '

        self.writelinei('(** ', fun.descr, ' *)')
        self.writei('val ', fun.name, ' : (_, _) t')

        for name, typ, _ in fun.params:
            names += name + ' '

            self.write(f' -> {typ}')

        self.writeline(' -> unit')

        self.writelinei(f'let {fun.name} {names}=')
        self.indent += 1

        for condition in fun.conditions:
            self.writelinei('assert ', condition, ';')

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.indent -= 1
        self.writei(';;\n\n')


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writelinei('(** ', decl.descr, ' *)')
            self.writelinei('type ', decl.type, ' =')
            self.indent += 1

            for name, value, _, _ in decl.members + decl.additional_members:
                self.writelinei('| ', name)

            self.writeline()
            self.indent -= 1

        elif isinstance(decl, DistinctType):
            self.writelinei('(** ', decl.descr, ' *)')
            self.write('type ', decl.type, ' = ', decl.type.underlying, '\n')

            if decl.constants:
                self.writelinei('module ', decl.type)
                self.indent += 1

                for name, value in decl.constants:
                    self.writelinei('let ', name, ' = ', decl.type, ' ', value, ' ;;')

                self.indent -= 1
                self.writelinei(';;')

            self.writeline()

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        self.writei(f'open OUnit2\n\nlet suite = "{self.arch} suite" >::: [\n')
        self.indent += 1
    
    def write_test_footer(self):
        self.indent -= 1
        self.write(f'];;\n\nlet () = run_test_tt_main suite ;;\n')

    def write_test(self, test: TestCase):
        self.writelinei('"', test.name, '" >:: (fun ctx ->')
        self.indent += 1

        self.writelinei('let buf = Iobuf.create ', len(test.expected), ' in')
        self.writeline()

        arch_module = self.arch.capitalize()

        for func, args in test.calls:
            self.writei(arch_module, '.', func.name, ' buf ')

            for arg in args:
                if isinstance(arg, ArgConstant):
                    self.write(f'{arg.type.type}.{arg.const.name} ')
                elif isinstance(arg, ArgEnumMember):
                    self.write(f'{arg.enum.type}.{arg.member.name} ')
                elif isinstance(arg, ArgInteger):
                    self.write(arg.value)
                else:
                    raise UnsupportedTestArgument(arg)

            self.writeline(';')

        self.writeline()
        self.writelinei('assert_equal ctx (Iobuf.to_string buf) "', test.expected_string, '"')
        self.indent -= 1
        self.writelinei(');')
