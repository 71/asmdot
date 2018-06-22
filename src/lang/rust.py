from asm.emit import *  # pylint: disable=W0614

header = '''#![allow(unused_imports, unused_parens, unused_mut)]
use ::{}::*;

use std::io::{{Result, Write}};
use std::mem;

use byteorder::{{WriteBytesExt, LE}};

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

    def write_header(self):
        self.write(header.format(self.arch))
    
    def write_footer(self):
        pass

    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')

        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)

        elif isinstance(expr, Ternary):
            self.write('(if ', expr.condition, ' { ', expr.consequence,
                       ' } else { ', expr.alternative, ' })')

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
            self.writelinei(stmt.variable, ' = ', stmt.value, ';')
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if ', stmt.condition, ' {')

            with self.indent.further():
                self.write_stmt(stmt.consequence)
            
            if stmt.alternative:
                self.writelinei('} else {')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)
            else:
                self.writelinei('}')

        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s)

        elif isinstance(stmt, Set):
            typ = stmt.type.under

            if typ in (TYPE_U8, TYPE_I8):
                self.writelinei('buf.write_', typ, '(', stmt.value, ')?;')
            else:
                self.writelinei('buf.write_', typ, '::<LE>(', stmt.value, ')?;')

        elif isinstance(stmt, Define):
            self.writelinei('let mut ', stmt.name, ': ', stmt.type, ' = ', stmt.value, ';')

        elif not isinstance(stmt, Increase):
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writelinei('/// ', fun.descr)
        self.writei('pub fn ', fun.fullname, '(buf: &mut Write')

        for name, typ in fun.params:
            self.write(f', {name}: {typ}')

        self.write(') -> Result<()> {\n')
        self.indent += 1
        self.writelinei('unsafe {')
        self.indent += 1

        for name, typ in fun.params:
            # Deconstruct distinct types (has no performance penalty).
            if typ in (TYPE_ARM_COND, TYPE_ARM_MODE, TYPE_BOOL):
                self.writelinei(f'let mut {name} = {name} as {"u32" if self.arch == "arm" else "u8"};')
            elif typ.underlying is TYPE_BYTE and self.arch == 'arm':
                self.writelinei(f'let mut {name} = mem::transmute::<_, u8>({name}) as u32;')
            elif typ.underlying is not None:
                self.writelinei(f'let {typ}(mut {name}) = {name};')
        
        for condition in fun.conditions:
            self.writelinei('assert!(', condition, ');')

        for stmt in fun.body:
            self.write_stmt(stmt)
        
        self.indent -= 1
        self.writelinei('}')
        self.writelinei('Ok(())')
        self.indent -= 1
        self.writei('}\n\n')

    def write_decl(self, decl: Declaration):
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

            for name, value, descr, _ in members:
                self.write('/// ', descr, '\n', indent=True)

                if decl.flags:
                    self.write('const ', name, ' = mem::transmute(', value, ');\n', indent=True)
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

                for name, value, descr, _ in decl.additional_members:
                    self.write('/// ', descr, '\n', indent=True)
                    self.write('pub const ', name, ': Self = mem::transmute(', value, ');\n', indent=True)

                self.indent -= 1
                self.write('}\n\n', indent=True)

        elif isinstance(decl, DistinctType):
            self.write('/// ', decl.descr, '\n', indent=True)
            self.write('pub struct ', decl.type, '(pub ', decl.type.underlying, ');\n\n', indent=True)

            if not decl.constants:
                return
            
            self.write('impl ', decl.type, ' {\n', indent=True)
            self.indent += 1

            for name, value in decl.constants:
                self.write('pub const ', name.upper(), ': Self = ', decl.type, '(', value, ');\n', indent=True)
            
            self.indent -= 1
            self.write('}\n\n', indent=True)

        else:
            raise UnsupportedDeclaration(decl)
