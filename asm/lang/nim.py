from asm.emit import *  # pylint: disable=W0614

class NimEmitter(Emitter):

    @property
    def language(self):
        return 'nim'

    @property
    def filename(self):
        if self.bindings:
            return f'{self.arch}.nim'
        else:
            return f'asmdot/private/{self.arch}.nim'

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

    def write_header(self, out: IO[str]):
        if self.bindings:
            out.write('const asmdotlib {.strdefine.} =\n  when defined(windows): "asmdot.dll"\n  else: "asmdot"\n\n')

    def write_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            out.write(f'({expr.l} {expr.op} {expr.r})')
        elif isinstance(expr, Unary):
            out.write(f'{expr.op}{expr.v}')
        elif isinstance(expr, Ternary):
            out.write(f'(if {expr.condition}: {expr.consequence} else: {expr.alternative})')
        elif isinstance(expr, (Var, Param)):
            out.write(expr.name)
        elif isinstance(expr, Call):
            out.write(f'{expr.builtin}({join_any(", ", expr.args)})')
        elif isinstance(expr, Literal):
            t = replace_pattern({ r'uint(\d+)': r'u\1', r'int(\d+)': r'i\1', r'.+': 'nop' }, str(expr.type.id))

            if t == 'nop':
                out.write(f'{expr.value}')
            else:
                out.write(f'{expr.value}\'{t}')
        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Assign):
            self.write(f'{stmt.variable} = {stmt.value}')
        elif isinstance(stmt, Conditional):
            self.write(f'if {stmt.condition}:')
            
            with self.indent.further():
                self.write_stmt(stmt.consequence, out)
            
            if stmt.alternative:
                self.write('else:')

                with self.indent.further():
                    self.write_stmt(stmt.alternative, out)
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s, out)
    
        elif isinstance(stmt, Increase):
            self.write(f'buf = cast[pointer](cast[uint](buf) + {stmt.by})')
        
        elif isinstance(stmt, Set):
            self.write(f'cast[ptr {stmt.type}](buf)[] = {stmt.value}')

        elif isinstance(stmt, Define):
            self.write(f'var {stmt.name} = {stmt.value}')
        
        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function, out: IO[str]):
        self.write(f'proc {fun.name}*(buf: var pointer')

        for name, typ in fun.params:
            self.write(f', {name}: {typ}')
        
        self.write(') ')

        if self.bindings:
            self.write(f'{{.cdecl, importc, dynlib: asmdotlib.}}\n')
            return
        
        self.write('=\n')

        self.indent += 1

        for name, typ in fun.params:
            if typ.underlying:
                self.write(f'var {name} = {typ.underlying} {name}', indent=True, newline=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out)

        self.write('\n\n')
        self.indent -= 1
