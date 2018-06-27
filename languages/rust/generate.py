#!/usr/bin/python3

from asmdot import *  # pylint: disable=W0614

header = '''#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

use ::{}::*;

use std::io::{{Result, Write}};
use std::mem;

use byteorder::{{WriteBytesExt, LE}};

'''

@handle_command_line(False)
class RustEmitter(Emitter):

    @property
    def language(self):
        return 'rust'

    @property
    def filename(self):
        return f'src/generated/{self.arch}.rs'
    
    @property
    def test_filename(self):
        return f'tests/{self.arch}.rs'

    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

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
        self.indent -= 1
        self.writei('}\n\n')
        self.writelinei('/// Implementation of `', self.arch.capitalize(),
                        'Assembler` for all `Write` implementations.')
        self.writelinei('impl<W: Write + ?Sized> ', self.arch.capitalize(), 'Assembler for W {}')

    def write_separator(self):
        self.writelinei('/// Allows any struct that implements `Write` to assemble ',
                        self.arch.capitalize(), ' instructions.')
        self.writelinei('pub trait ', self.arch.capitalize(), 'Assembler: Write {\n')
        self.indent += 1


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
                self.writelinei('self.write_', typ, '(', stmt.value, ')?;')
            else:
                self.writelinei('self.write_', typ, '::<LE>(', stmt.value, ' as _)?;')

        elif isinstance(stmt, Define):
            self.writelinei('let mut ', stmt.name, ': ', stmt.type, ' = ', stmt.value, ';')

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writelinei('/// ', fun.descr)
        self.writelinei('#[inline]')
        self.writei('fn ', fun.fullname, '(&mut self')

        for name, typ, _ in fun.params:
            self.write(f', {name}: {typ}')

        self.write(') -> Result<()> {\n')
        self.indent += 1
        self.writelinei('unsafe {')
        self.indent += 1

        for name, typ, usagety in fun.params:
            # Deconstruct distinct types (has no performance penalty).
            if typ.underlying is not None:
                self.writelinei(f'let mut {name} = Into::<{typ.underlying}>::into({name}) as {usagety};')
            else:
                self.writelinei(f'let mut {name} = {name} as {usagety};')

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
                    self.write('const ', name, ' = transmute_const!(', value, ');\n', indent=True)
                else:
                    self.write(name, ' = ', value, ',\n', indent=True)

            self.indent -= 1
            self.writei('}\n')

            if decl.flags:
                self.indent -= 1
                self.write('}\n\n')
            else:
                self.write('\n')

            self.writei('impl Into<', decl.type.under, '> for ', decl.type, ' {\n')

            with self.indent.further():
                body = 'self.bits()' if decl.flags else f'self as {decl.type.under}'
                self.writei('fn into(self) -> ', decl.type.under, ' { ', body, ' }\n')
            
            self.writei('}\n\n')

            if decl.flags:
                return

            if decl.additional_members:
                self.write('impl ', decl.type, ' {\n', indent=True)
                self.indent += 1

                for name, value, descr, _ in decl.additional_members:
                    self.write('/// ', descr, '\n', indent=True)
                    self.write('pub const ', name, ': Self = transmute_const!(', value, ');\n', indent=True)

                self.indent -= 1
                self.write('}\n\n', indent=True)

        elif isinstance(decl, DistinctType):
            self.writei('/// ', decl.descr, '\n')
            self.writei('pub struct ', decl.type, '(pub ', decl.type.underlying, ');\n\n')

            self.writei('impl Into<', decl.type.under, '> for ', decl.type, ' {\n')

            with self.indent.further():
                self.writei('fn into(self) -> ', decl.type.under, ' { self.0 }\n')
            
            self.writei('}\n\n')

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


    def write_test_header(self):
        self.write(f'extern crate asm;\n\n')
        self.write(f'use asm::{self.arch}::*;\n\n')

    def write_test(self, test: TestCase):
        self.writeline('#[test]')
        self.writeline('fn ', test.name.replace(' ', '_'), '() {')

        self.indent += 1

        self.writelinei('let mut buf = Vec::new();')
        self.writeline()

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.type.type}::{arg.const.name}'
            elif isinstance(arg, ArgEnumMember):
                return f'{arg.enum.type}::{arg.member.name}'
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            args_str = ', '.join([ arg_str(arg) for arg in args ])

            self.writelinei('assert!(buf.', func.fullname, '(', args_str, ').is_ok());')
        
        self.writeline()
        self.writelinei('assert_eq!(buf, b"', test.expected_string, '");')
        self.indent -= 1
        self.writelinei('}')
