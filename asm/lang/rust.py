from asm.emit import *  # pylint: disable=W0614

header = '''#![allow(unused_parens, unused_mut)]
use ::{}::*;

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
            r'uint(\d+)': r'u\1',
            r'int(\d+)': r'i\1',
            r'Reg(\d*)': r'Register\1'
        }, ty.id)
    
    def get_builtin_name(self, builtin: Builtin) -> str:
        if builtin is BUILTIN_X86_PREFIX:
            return 'prefix_adder!'
        else:
            raise NotImplementedError

    def write_header(self, out: IO[str]):
        out.write(header.format(self.arch))
    
    def write_footer(self, out: IO[str]):
        pass

    def write_expr(self, expr: Expression, out: IO[str]):
        if isinstance(expr, Binary):
            out.write(f'({expr.l} {expr.op} {expr.r})')
        elif isinstance(expr, Unary):
            out.write(f'{expr.op}{expr.v}')
        elif isinstance(expr, Ternary):
            out.write(f'(if {expr.condition} {{ {expr.consequence} }} else {{ {expr.alternative} }})')
        elif isinstance(expr, Var):
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
            self.write(f'*(&mut (*buf as usize)) += {stmt.by};')

        elif isinstance(stmt, Set):
            self.write(f'*(*buf as *mut {stmt.type}) = {stmt.value} as _;')

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
            if typ in [TYPE_ARM_COND, TYPE_ARM_MODE, TYPE_BOOL]:
                self.write(f'let mut {name} = {name} as {"u32" if self.arch == "arm" else "u8"};', indent=True, newline=True)
            elif typ.underlying is TYPE_BYTE and self.arch == 'arm':
                self.write(f'let mut {name} = ::std::mem::transmute::<_, u8>({name}) as u32;', indent=True, newline=True)
            else:
                self.write(f'let {typ}(mut {name}) = {name};', indent=True, newline=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out)

        self.indent -= 1
        self.write('}\n\n', indent=True)
    
    def write_decl(self, decl: Declaration, out: IO[str]):
        if isinstance(decl, Enumeration):
            if decl.flags:
                self.write('bitflags! {\n', indent=True)
                self.indent += 1
            
            self.write('/// ', decl.descr, '\n', indent=True)

            if decl.flags:
                self.write('pub struct ', decl.type, ': ', decl.type.under, ' {\n', indent=True)
            else:
                self.write('#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]\n', indent=True)
                self.write('pub enum ', decl.type, ' {\n', indent=True)

            self.indent += 1

            if decl.flags:
                members = decl.members + decl.additional_members
            else:
                members = decl.members

            for name, value, descr in members:
                self.write('/// ', descr, '\n', indent=True)

                if decl.flags:
                    self.write('const ', name, ' = ', value, ';\n', indent=True)
                else:
                    self.write(name, ' = ', value, ',\n', indent=True)

            self.indent -= 1
            self.write('}\n', indent=True)

            if decl.flags:
                self.indent -= 1
                self.write('}\n\n')

                return
            
            self.write('\n')

            if decl.additional_members:
                self.write('impl ', decl.type, ' {\n', indent=True)
                self.indent += 1

                for name, value, descr in decl.additional_members:
                    self.write('/// ', descr, '\n', indent=True)
                    self.write('pub const ', name, ': Self = ', value, ';\n', indent=True)

                self.indent -= 1
                self.write('}\n\n', indent=True)

        elif isinstance(decl, DistinctType):
            self.write('/// ', decl.descr, '\n', indent=True)
            self.write('pub struct ', decl.type, '(pub ', decl.type.underlying, ');\n\n', indent=True)

        else:
            raise UnsupportedDeclaration(decl)
