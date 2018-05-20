from asm.emit import *  # pylint: disable=W0614

class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'{self.arch}.py'
    
    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'u?int\d+': 'int'
        }, ty.id)

    def initialize(self, args: Namespace):
        super().initialize(args)
        
        self.indent = Indent('    ')

    def write_header(self, out: IO[str]):
        self.write('import struct\nfrom enum import Enum, Flag\nfrom typing import NewType\n\n')

    def write_expr(self, expr: Expression, out: IO[str]):
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

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Assign):
            self.write(stmt.variable, ' = ', stmt.value)
        elif isinstance(stmt, Conditional):
            self.write('if ', stmt.condition, ':')

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
            self.write('self.pos += ', stmt.by)
        
        elif isinstance(stmt, Set):
            if stmt.type.under in [TYPE_U8, TYPE_I8]:
                self.write('self.buf[self.pos] = ', stmt.value)
            else:
                self.write('struct.pack_into("<I", self.buf, self.pos, ', stmt.value, ')')

        elif isinstance(stmt, Define):
            self.write(stmt.name, ' = ', stmt.value)

        else:
            raise UnsupportedStatement(stmt)
    
    def write_separator(self, out: IO[str]):
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

    def write_function(self, fun: Function, out: IO[str]):
        name = fun.fullname

        if name in ['and']:
            name += '_'

        self.write(f'def {name}(self', indent=True)

        for name, typ in fun.params:
            self.write(f', {name}: {typ}')

        self.write(') -> None:\n')
        self.indent += 1
        self.write(f'"""{fun.descr}"""\n', indent=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out)

        self.indent -= 1
        self.write('\n')
    
    def write_decl(self, decl: Declaration, out: IO[str]):
        if isinstance(decl, Enumeration):
            sub = 'Flag' if decl.flags else 'Enum'

            self.write('class ', decl.type, f'(int, {sub}):\n')
            self.indent += 1
            self.write('"""', decl.descr, '"""\n', indent=True)

            for name, value, _ in decl.members + decl.additional_members:
                self.write(name, ' = ', value, '\n', indent=True)
            
            self.write('\n')
            self.indent -= 1

        elif isinstance(decl, DistinctType):
            self.write(decl.type, ' = NewType("', decl.type, '", ', decl.type.underlying, ')\n')

            for name, value in decl.constants:
                self.write('setattr(', decl.type, ', "', name, '", ', decl.type, '(', value, '))\n')
                #self.write(decl.type, '.', name, ' = ', decl.type, '(', value, ')\n')
            
            self.write('\n')

        else:
            raise UnsupportedDeclaration(decl)
