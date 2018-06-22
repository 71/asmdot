from typing import Any, Callable, Optional, NamedTuple, NewType, List, Sequence, Tuple, Union
from typing import no_type_check


class IrType:
    id: str
    size: int
    underlying: Optional[Any]

    def __init__(self, id: str, sizeOrUnderlying: Union[int, Any]) -> None:
        self.id = id
        
        if isinstance(sizeOrUnderlying, int):
            self.size = sizeOrUnderlying
            self.underlying = None
        else:
            self.size = sizeOrUnderlying.size
            self.underlying = sizeOrUnderlying
    
    def __iter__(self):
        yield self.id
        yield self.size
        yield self.underlying
    
    def __str__(self) -> str: return self.id
    def __repr__(self) -> str: return self.id

    @property
    def under(self) -> 'IrType':
        """Returns this type's underlying type, if any. Otherwise, returns this type directly."""
        if self.underlying:
            return self.underlying
        return self

# By convention, types get their names after their Nim counterpart,
# because Nim types are descriptive enough and similar to other languages.
# Rust also has interesting names, but unfortunately it has '()' instead of 'void',
# and substituting regexes are less easy to do (r'u?int\d+' in Nim, vs r'[iu]\d+' in Rust).

TYPE_VOID = IrType('void', 0)
TYPE_BOOL = IrType('bool', 1)
TYPE_I8   = IrType('int8', 1)
TYPE_I16  = IrType('int16', 2)
TYPE_I32  = IrType('int32', 4)
TYPE_I64  = IrType('int64', 8)
TYPE_U8   = IrType('uint8', 1)
TYPE_U16  = IrType('uint16', 2)
TYPE_U32  = IrType('uint32', 4)
TYPE_U64  = IrType('uint64', 8)
TYPE_BYTE = TYPE_U8

TYPE_ARM_REG  = IrType('Reg',       TYPE_BYTE)
TYPE_ARM_COND = IrType('Condition', TYPE_BYTE)
TYPE_ARM_MODE = IrType('Mode',      TYPE_BYTE)
TYPE_ARM_SHIFT  = IrType('Shift',          TYPE_BYTE)
TYPE_ARM_FIELD  = IrType('FieldMask',      TYPE_BYTE)
TYPE_ARM_IFLAGS = IrType('InterruptFlags', TYPE_BYTE)
TYPE_ARM_COPROC = IrType('Coprocessor',    TYPE_BYTE)
TYPE_ARM_ROTATION = IrType('Rotation',     TYPE_BYTE)
TYPE_ARM_ADDRESSING = IrType('Addressing', TYPE_BYTE)
TYPE_ARM_OFFSETMODE = IrType('OffsetMode', TYPE_BYTE)

TYPE_X86_R8   = IrType('Reg8',   TYPE_BYTE)
TYPE_X86_R16  = IrType('Reg16',  TYPE_BYTE)
TYPE_X86_R32  = IrType('Reg32',  TYPE_BYTE)
TYPE_X86_R64  = IrType('Reg64',  TYPE_BYTE)
TYPE_X86_R128 = IrType('Reg128', TYPE_BYTE)


class Operator(NamedTuple):
    op: str
    
    def __str__(self) -> str: return self.op
    def __repr__(self) -> str: return self.__str__()

# Operators get their names from C, however, since they're similar in C, C++, C#, Rust,...

OP_ADD = Operator('+')
OP_SUB = Operator('-')
OP_MUL = Operator('*')
OP_DIV = Operator('/')
OP_SHL = Operator('<<')
OP_SHR = Operator('>>')
OP_LT  = Operator('<')
OP_LE  = Operator('<=')
OP_GT  = Operator('>')
OP_GE  = Operator('>=')
OP_EQ  = Operator('==')
OP_NE  = Operator('!=')
OP_AND = Operator('&&')
OP_OR  = Operator('||')
OP_NOT = Operator('!')
OP_XOR = Operator('^')
OP_BITWISE_AND = Operator('&')
OP_BITWISE_OR  = Operator('|')
OP_BITWISE_XOR = Operator('^')


class Builtin(NamedTuple):
    name: str
    
    def __str__(self) -> str: return self.name
    def __repr__(self) -> str: return self.__str__()

# Built-ins get arbitrary names.

BUILTIN_X86_PREFIX = Builtin('get_prefix')


Expression = Union['Binary', 'Unary', 'Call', 'Ternary', 'Literal', 'Var']
ExpressionVisitor = Callable[[Expression], Expression]

class Binary(NamedTuple):
    """A binary (or infix) expression."""
    op: Operator
    l: Any
    r: Any

    def visit(self, f: ExpressionVisitor) -> 'Binary':
        return Binary(self.op, f(self.l), f(self.r))

class Unary(NamedTuple):
    """An unary (or prefix) expression."""
    op: Operator
    v: Any

    def visit(self, f: ExpressionVisitor) -> 'Unary':
        return Unary(self.op, f(self.v))

class Call(NamedTuple):
    """A function-call expression."""
    builtin: Builtin
    args: List[Any]

    def visit(self, f: ExpressionVisitor) -> 'Call':
        return Call(self.builtin, [ f(arg) for arg in self.args ])

class Ternary(NamedTuple):
    """A ternary (or conditional) expression."""
    condition: Any
    consequence: Any
    alternative: Any

    def visit(self, f: ExpressionVisitor) -> 'Ternary':
        return Ternary(f(self.condition), f(self.consequence), f(self.alternative))
    
class Literal(NamedTuple):
    """A literal expression."""
    value: Any
    type: IrType

    def visit(self, f: ExpressionVisitor) -> 'Literal':
        return Literal(self.value, self.type)

class Var(NamedTuple):
    """A variable or parameter reference expression."""
    name: str
    isParameter: bool = True

    def visit(self, f: ExpressionVisitor) -> 'Var':
        return Var(self.name, self.isParameter)


Statement = Union['Assign', 'Conditional', 'Block', 'Increase', 'Define', 'Set']
StatementVisitor = Callable[[Statement], None]

class Assign(NamedTuple):
    """Statement that sets the given variable to the given expression."""
    variable: str
    value: Expression

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Assign':
        return Assign(self.variable, g(self.value))

class Conditional(NamedTuple):
    """Statement that only executes another statement if the condition is true.
       Additionally, it can optionally execute another statement otherwise."""
    condition: Expression
    consequence: Any
    alternative: Any = None

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Conditional':
        return Conditional(g(self.condition), f(self.consequence), f(self.alternative))

class Block(NamedTuple):
    """Block of statements."""
    statements: List[Any] = list()

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Block':
        return Block([ f(stmt) for stmt in self.statements ])
    
class Increase(NamedTuple):
    """Statement that increases the index at which bytes are written by the given number of
       bytes."""
    by: int = 1

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Increase':
        return Increase(self.by)

class Set(NamedTuple):
    """Statement that sets the current value to the given expression."""
    type: IrType
    value: Expression

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Set':
        return Set(self.type, g(self.value))

class Define(NamedTuple):
    """Statement that creates a new variable with the given name and initial value."""
    type: IrType
    name: str
    value: Expression

    def visit(self, f: StatementVisitor, g: ExpressionVisitor) -> 'Define':
        return Define(self.type, self.name, g(self.value))


Parameter = NamedTuple('Parameter', [('name', str), ('type', IrType)])

class Function:
    """
    A function that represents an instruction.
    Note: The first parameter (namely, the buffer) is not given among the `params` attribute.
    """
    def __init__(self, name: str, params: Sequence[Parameter], fullname: Optional[str] = None, conditions: Optional[List[Expression]] = None) -> None:
        self.params = params
        self.name = name
        self.conditions = conditions or []

        self.fullname = fullname or name

        self.body : List[Statement] = []
        self.descr = f"Emits {'an' if name[0] in 'aeiouy' else 'a'} '{name}' instruction."

    @no_type_check
    def __iadd__(self, stmts):
        if any([ isinstance(stmts, k) for k in statementClasses ]):
            self.body.append(stmts)
        else:
            self.body.extend(stmts)
        
        return self
    
    def has_valid_increases():
        balance = 0

        def visit_stmt(x: Statement) -> Statement:
            nonlocal balance

            if isinstance(x, Set):
                balance += x.type.size
            elif isinstance(x, Increase):
                balance -= x.by
            
            return x.visit(visit_stmt, lambda _: _)
        
        for stmt in self.body:
            visit_stmt(stmt)
        
        return balance == 0


# Little hack courtesy of https://ceasarjames.wordpress.com/2012/03/19/how-to-use-default-arguments-with-namedtuple
class EnumerationMember:
    """A member of an enumeration."""
    name: str
    value: int
    descr: str
    fullname: str

    def __init__(self, name: str, value: int, descr: str, fullname: str = '*') -> None:
        self.name = name
        self.value = value
        self.descr = descr
        self.fullname = fullname.replace('*', name)
    
    def __iter__(self):
        yield self.name
        yield self.value
        yield self.descr
        yield self.fullname

class Enumeration(NamedTuple):
    """An enumeration."""
    type: IrType
    flags: bool
    descr: str
    members: List[EnumerationMember]
    additional_members: List[EnumerationMember] = []

class Constant(NamedTuple):
    """A constant."""
    name: str
    value: int

class DistinctType(NamedTuple):
    """A distinct type."""
    type: IrType
    descr: str
    constants: List[Constant] = []

Declaration = Union[Enumeration, Function, DistinctType]

# Utils

statementClasses = [ Assign, Conditional, Block, Increase, Set, Define ]
expressionClasses = [ Binary, Unary, Ternary, Call, Literal, Var ]

zero = Literal(0, TYPE_BYTE)
one  = Literal(1, TYPE_BYTE)

def param(name: str, ty: IrType) -> Parameter:
    """Returns a parameter."""
    return Parameter(name, ty)

def pswitch(name: str) -> Parameter:
    """Returns a boolean switch parameter, given its name."""
    return param(name, TYPE_BOOL)

def value_or_zero(condition: Expression, value: Expression) -> Expression:
    """Expression that returns the given value if the condition istrue, or zero otherwise."""
    return Ternary(condition, value, zero)
