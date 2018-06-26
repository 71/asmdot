from asm.emit import *  # pylint: disable=W0614

class HaskellEmitter(Emitter):

    @property
    def language(self):
        return 'haskell'

    @property
    def filename(self):
        return f'src/Asm/Internal/{self.arch.capitalize()}.hs'

    @property
    def test_filename(self):
        return f'test/Asm/{self.arch.capitalize()}Spec.hs'


    def initialize(self, args: Namespace):
        Emitter.initialize(self, args)

        self.indent = Indent('    ')


    def get_operator(self, op: Operator) -> str:
        dic = {
            OP_BITWISE_AND: '.&.',
            OP_BITWISE_OR : '.|.',
            OP_BITWISE_XOR: '`xor`'
        }

        if op in dic:
            return dic[op]
        else:
            return op.op


    def write_header(self):
        self.write('module Asm.Internal.', self.arch.capitalize(), ' where\n\n')
        self.write('import Data.IORef\n')
        self.write('import Foreign.Ptr\n')
        self.write('import System.IO.Unsafe (unsafePerformIO)\n\n')
        
        self.indent += 1
    
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
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value)
        
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
            self.writelinei('poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr ', stmt.type, ') ', stmt.value)
            self.writelinei('writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) ', stmt.type.size, ')')

        elif isinstance(stmt, Define):
            self.writelinei('let ', stmt.name, ' = ', stmt.value, ' in')

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.write(fun.fullname, ' :: IORef (Ptr ())')

        for _, typ, _ in fun.params:
            self.write(f' -> {typ}')
        
        self.write(' -> IO ()\n')
        self.write(fun.fullname, ' bufref ', ' '.join([ name for name, _, _ in fun.params ]), ' = do\n')
        self.indent += 1

        for condition in fun.conditions:
            self.write('assert ', condition, '\n', indent=True)

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.write('\n\n')
        self.indent -= 1


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.write('-- | ', decl.descr, '\n')
            self.write('data ', decl.type, ' =\n')

            prefix = '      '

            for _, _, descr, fullname in decl.members + decl.additional_members:
                self.write(prefix, fullname, ' -- ^ ', descr, '\n')

                if prefix == '      ':
                    prefix = '    | '

            self.write('  deriving (Eq, Show)\n\n')
            self.write('instance Enum ', decl.type, ' where\n')

            for _, value, _, fullname in decl.members + decl.additional_members:
                self.write('  fromEnum ', fullname, ' = ', value, '\n')
            
            self.write('\n')
            
            for _, value, _, fullname in decl.members + decl.additional_members:
                self.write('  toEnum ', value, ' = ', fullname, '\n')
            
            self.write('\n\n')
        
        elif isinstance(decl, DistinctType):
            self.write('-- | ', decl.descr, '\n')
            self.write('newtype ', decl.type, ' = ', decl.type, ' ', decl.type.underlying, '\n\n')

            if decl.constants:
                self.write(', '.join([ name for name, _ in decl.constants ]), ' :: ', decl.type, '\n')

                for name, value in decl.constants:
                    self.write(name, ' = ', decl.type, ' ', value, '\n')

                self.write('\n\n')

        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        self.write(f'import Asm.{self.arch.capitalize()}\nimport Test.Hspec\n\n')
        self.write(f'{self.arch}Spec = do\n')
        self.indent += 1
    
    def write_footer(self):
        self.indent -= 1

    def write_test(self, test: TestCase):
        self.writei('it "', test.name, '" $\n')
        self.indent += 1

        self.writelinei('pending')
        self.writeline()

        self.indent -= 1
