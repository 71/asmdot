from asm.emit import *  # pylint: disable=W0614

header = '''use std::mem::transmute;

'''

class RustEmitter(Emitter):

    @property
    def language(self):
        return 'rust'

    @property
    def filename(self):
        return f'src/generated/{self.arch}.rs'
    
    def initialize(self, args: Namespace):
        super().initialize(args)

        if self.bindings:
            raise UnsupportedOption('bindings', 'The Rust emitter cannot generate bindings.')

        self.indent = Indent('    ')
    
    @staticmethod
    def register(parser: ArgumentParser):
        Emitter.register(parser)

    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            'byte': 'u8',
            r'uint(\d+)': r'u\1',
            r'int(\d+)': r'i\1',
            r'reg(\d*)': r'Register\1',
            'condition': 'Condition'
        }, ty.id)
    
    def get_builtin_name(self, builtin: Builtin) -> str:
        if builtin is BUILTIN_X86_PREFIX:
            return 'prefix_adder!'
        else:
            raise NotImplementedError

    def write_header(self, out: IO[str]):
        out.write(header)
    
    def write_footer(self, out: IO[str]):
        pass

    def write_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            out.write(f'({expr.l} {expr.op} {expr.r})')
        elif isinstance(expr, Unary):
            out.write(f'{expr.op}{expr.v}')
        elif isinstance(expr, Ternary):
            out.write(f'(if {expr.condition} {{ {expr.consequence} }} else {{ {expr.alternative} }})')
        elif isinstance(expr, (Var, Param)):
            out.write(expr.name)
        elif isinstance(expr, Call):
            out.write(f'{expr.builtin}({join_any(", ", expr.args)})')
        elif isinstance(expr, Literal):
            out.write(str(expr.value))
        else:
            assert False

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Assign):
            self.write(f'{stmt.variable} = {stmt.value};')
        elif isinstance(stmt, Conditional):
            self.write(f'if {stmt.condition} {{')

            with self.indent.further():
                self.write_stmt(stmt.consequence, out)
            
            if stmt.alternative:
                self.write('} else {')

                with self.indent.further():
                    self.write_stmt(stmt.alternative, out)
            else:
                self.write('}')

        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s, out)

        elif isinstance(stmt, Increase):
            self.write(f'*(&(*buf as usize)) += {stmt.by};')

        elif isinstance(stmt, Set):
            self.write(f'*(*buf as *mut {stmt.type}) = {stmt.value};')

        elif isinstance(stmt, Define):
            self.write(f'let mut {stmt.name}: {stmt.type} = {stmt.value};')

        else:
            assert False

    def write_function(self, fun: Function, out: IO[str]):
        a = 'an' if fun.name[0] in 'aeiouy' else 'a' # words are important, kids

        self.write(f'/// Emits {a} `{fun.name}` instruction.\n', indent=True)
        self.write(f'pub unsafe fn {fun.fullname}(buf: &mut *mut ()', indent=True)

        for name, typ in fun.params:
            self.write(f', {name}: {typ}')

        if self.bindings:
            out.write(');\n')
            return
        
        self.write(') {\n')
        self.indent += 1

        for name, typ in fun.params:
            # Deconstruct distinct types (has no performance penalty).
            if typ.underlying:
                self.write(f'let {typ}(mut {name}) = {name};', indent=True, newline=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out)
        
        self.indent -= 1
        self.write('}\n\n', indent=True)
