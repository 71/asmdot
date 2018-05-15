from asm.emit import *  # pylint: disable=W0614

class NimEmitter(Emitter):

    @property
    def language(self):
        return 'nim'

    @property
    def filename(self):
        return f'{self.arch}.nim'

    def emit_header(self, out: IO[str]):
        if self.arch == 'arm':
            out.write('include private/arm.nim\n\n')
        elif self.arch == 'x86':
            out.write('include private/x86.nim\n\n')
        else:
            raise UnsupportedArchitecture(self.arch)
        
        if self.bindings:
            out.write('const asmdotlib {.strdefine.} =\n  when defined(windows): "asmdot.dll"\n  else: "asmdot"\n\n')

    def emit_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            out.write(f'({expr.l} {expr.op} {expr.r})')
        elif isinstance(expr, Unary):
            out.write(f'{expr.op}{expr.v}')
        elif isinstance(expr, Ternary):
            out.write(f'({expr.condition} ? {expr.consequence} : {expr.alternative})')
        elif isinstance(expr, (Var, Param)):
            out.write(expr.name)
        elif isinstance(expr, Call):
            out.write(f'{expr.builtin}({", ".join(expr.args)})')
        elif isinstance(expr, Literal):
            out.write(str(expr.value))
        else:
            raise UnsupportedExpression(expr)
    
    def emit_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Return):
            self.write('return ', newline=False)
            self.emit_expr(stmt.value, out)
        elif isinstance(stmt, Assign):
            self.write(f'{stmt.variable} = {stmt.value}')
        elif isinstance(stmt, Conditional):
            self.write(f'if {stmt.condition}:')
            
            with self.indent.further():
                self.emit_stmt(stmt.consequence, out)
            
            if stmt.alternative:
                self.write('else:')

                with self.indent.further():
                    self.emit_stmt(stmt.alternative, out)
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.emit_stmt(s, out)
    
        elif isinstance(stmt, Increase):
            if stmt.variable:
                self.write(f'{stmt.variable} += {stmt.by}')
            else:
                self.write(f'buf += {stmt.by}')
        
        elif isinstance(stmt, Set):
            self.write(f'cast[ptr {stmt.type}](buf)[{stmt.offset or ""}] = {stmt.value}')

        elif isinstance(stmt, Define):
            self.write(f'var {stmt.name} = {stmt.value}')
        
        else:
            raise UnsupportedStatement(stmt)

    def emit(self, fun: Function, out: IO[str]):
        out.write(f'proc {fun.name}*(')

        for name, ty in fun.params:
            out.write(f'{name}: {ty}, ')
        
        out.write(f'buf: {"var " if self.mutable_buffer else ""}ptr byte): {self.returntype} ')

        if self.bindings:
            out.write(f'{{.cdecl, importc, dynlib: asmdotlib.}}\n')
            return
        
        out.write('=\n')

        self.indent += 1

        for stmt in fun.body:
            self.emit_stmt(stmt, out)

        out.write('\n\n')
        self.indent -= 1
