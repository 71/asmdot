from asmdot import *  # pylint: disable=W0614

@handle_command_line()
class HaskellEmitter(Emitter):
    is_first_statement: bool = False

    @property
    def language(self):
        return 'haskell'

    @property
    def filename(self):
        return f'src/Asm/Internal/{self.arch.capitalize()}.hs'

    @property
    def test_filename(self):
        return f'test/Asm/{self.arch.capitalize()}Spec.hs'


    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('    ')


    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            r'bool':        r'Bool',
            r'uint(\d+)':   r'Word\1',
            r'int(\d+)':    r'Int\1',
            r'Reg(\d*)':    r'Register\1'
        }, ty.id)

    def get_operator(self, op: Operator) -> str:
        dic = {
            OP_BITWISE_AND: '.&.',
            OP_BITWISE_OR : '.|.',
            OP_BITWISE_XOR: '`xor`',
            OP_SHL: '`shiftL`',
            OP_SHR: '`shiftR`'
        }

        if op in dic:
            return dic[op]
        else:
            return op.op
    
    def get_function_name(self, function: Function) -> str:
        if function.fullname in ('div'):
            return function.fullname + '_'
        else:
            return function.fullname


    def write_header(self):
        self.write('module Asm.Internal.', self.arch.capitalize(), ' where\n\n')
        self.indent += 1

        self.writei('import Control.Exception (assert)\n')
        self.writei('import Data.Bits\n')
        self.writei('import Data.ByteString.Builder\n')
        self.writei('import Data.Int\n')
        self.writei('import Data.Semigroup (Semigroup((<>)))\n')
        self.writei('import Data.Word\n\n')
    
    def write_footer(self):
        self.indent -= 1


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
        deindent = True

        if self.is_first_statement:
            self.is_first_statement = False
            deindent = False
        else:
            self.writelinei('<>')
            self.indent += 1

        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value)
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if ', stmt.condition, ' then')

            with self.indent.further():
                self.is_first_statement = True
                self.write_stmt(stmt.consequence)
                self.is_first_statement = False

            self.writelinei('else')

            with self.indent.further():
                self.is_first_statement = True

                if stmt.alternative:
                    self.write_stmt(stmt.alternative)
                else:
                    self.writelinei('mempty')
                
                self.is_first_statement = False
                
        
        elif isinstance(stmt, Block):
            self.is_first_statement = True

            for s in stmt.statements:
                self.write_stmt(s)

            self.is_first_statement = False
    
        elif isinstance(stmt, Set):
            typ = stmt.type.under
            endian = 'BE ' if self.bigendian else 'LE '

            if typ is TYPE_I8:              self.writei('int8 ')
            elif typ is TYPE_U8:            self.writei('word8 ')
            elif typ.id.startswith('u'):    self.writei('word', typ.size * 8, endian)
            else:                           self.writei('int', typ.size * 8, endian)

            self.writeline(stmt.value)

        elif isinstance(stmt, Define):
            self.writelinei('let ', stmt.name, ' = ', stmt.value, ' in')

        else:
            raise UnsupportedStatement(stmt)
        
        if deindent:
            self.indent -= 1

    def write_function(self, fun: Function):
        self.is_first_statement = True
        self.writei(fun.name, ' :: ')

        for _, typ, _ in fun.params:
            self.write(f'{typ} -> ')
        
        self.write('Builder\n')
        self.writei(fun.name, ' ', ' '.join([ name for name, _, _ in fun.params ]), ' =\n')
        self.indent += 1

        for name, typ, _ in fun.params:
            # Deconstruct distinct types.
            if typ.underlying is not None:
                self.writelinei(f'let {name} = fromIntegral {name} in')
            else:
                self.writelinei(f'let {name} = fromIntegral {name} in')

        for condition in fun.conditions:
            self.writei('assert ', condition, '\n')

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.write('\n\n')
        self.indent -= 1


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writei('-- | ', decl.descr, '\n')
            self.writei('data ', decl.type, ' =\n')
            self.indent += 1

            prefix = '  '

            for _, _, descr, fullname in decl.members + decl.additional_members:
                self.writei(prefix, fullname, ' -- ^ ', descr, '\n')

                if prefix == '  ':
                    prefix = '| '

            self.writei('  deriving (Eq, Show)\n\n')
            self.indent -= 1
            self.writei('instance Enum ', decl.type, ' where\n')

            for _, value, _, fullname in decl.members + decl.additional_members:
                self.writei('  fromEnum ', fullname, ' = ', value, '\n')
            
            self.write('\n')
            
            for _, value, _, fullname in decl.members + decl.additional_members:
                self.writei('  toEnum ', value, ' = ', fullname, '\n')
            
            self.write('\n\n')
        
        elif isinstance(decl, DistinctType):
            self.writei('-- | ', decl.descr, '\n')
            self.writei('newtype ', decl.type, ' = ', decl.type, ' ', decl.type.underlying, '\n\n')

            if decl.constants:
                self.writei(', '.join([ name for name, _ in decl.constants ]), ' :: ', decl.type, '\n')

                for name, value in decl.constants:
                    self.writei(name, ' = ', decl.type, ' ', value, '\n')

                self.write('\n\n')

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        self.write(f'import Asm.{self.arch.capitalize()}\nimport Test.Hspec\n\n')
        self.write(f'{self.arch}Spec = do\n')
        self.indent += 1
    
    def write_test_footer(self):
        self.indent -= 1

    def write_test(self, test: TestCase):
        self.writei('it "', test.name, '" $\n')
        self.indent += 1

        self.writelinei('pending')
        self.writeline()

        self.indent -= 1
