from asm.emit import *  # pylint: disable=W0614

class HaskellEmitter(Emitter):

    @property
    def language(self):
        return 'haskell'

    @property
    def filename(self):
        return f'src/Asm/Internal/{self.arch.capitalize()}.hs'

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
    
    def write_header(self, out: IO[str]):
        self.write('module Asm.Internal.', self.arch.capitalize(), ' where\n\n')
        self.write('import Data.IORef\n')
        self.write('import Foreign.Ptr\n')
        self.write('import System.IO.Unsafe (unsafePerformIO)\n\n')

    def write_expr(self, expr: Expression, out: IO[str]):
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

    def write_stmt(self, stmt: Statement, out: IO[str]):
        if isinstance(stmt, Assign):
            self.write(stmt.variable, ' = ', stmt.value)
        
        elif isinstance(stmt, Conditional):
            self.write('if ', stmt.condition, ' then')

            with self.indent.further():
                self.write_stmt(stmt.consequence, out)

            if stmt.alternative:
                self.write('else')

                with self.indent.further():
                    self.write_stmt(stmt.alternative, out)
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s, out)
    
        elif isinstance(stmt, Increase):
            self.write('writeIORef bufref (plusPtr (unsafePerformIO $ readIORef bufref) ', stmt.by, ')')
        
        elif isinstance(stmt, Set):
            self.write('poke (castPtr (unsafePerformIO $ readIORef bufref) :: Ptr ', stmt.type, ') ', stmt.value)

        elif isinstance(stmt, Define):
            self.write('let ', stmt.name, ' = ', stmt.value, ' in')

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function, out: IO[str]):
        self.write(fun.fullname, ' :: IORef (Ptr ())')

        for _, typ in fun.params:
            self.write(f' -> {typ}')
        
        self.write(' -> IO ()\n')
        self.write(fun.fullname, ' bufref ', ' '.join([ name for name, _ in fun.params ]), ' = do\n')
        self.indent += 1

        for condition in fun.conditions:
            self.write('assert ', condition, '\n', indent=True)

        for stmt in fun.body:
            self.write_stmt(stmt, out)

        self.write('\n\n')
        self.indent -= 1

    def write_decl(self, decl: Declaration, out: IO[str]):
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
