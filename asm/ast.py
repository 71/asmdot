from inspect import isgenerator
from typing import Any, Optional, NamedTuple, NewType, List, Sequence, Tuple, Union, no_type_check
from .options import Options

# Language

class IrType:
    def __init__(self, id: str) -> None:
        self.original = self.id = id
    
    def __str__(self) -> str:
        return self.original
    
    def __repr__(self): return self.__str__()

TYPE_BOOL = IrType('bool')
TYPE_BYTE = IrType('byte')
TYPE_I8   = IrType('int8')
TYPE_I16  = IrType('int16')
TYPE_I32  = IrType('int32')
TYPE_I64  = IrType('int64')
TYPE_U16  = IrType('uint16')
TYPE_U32  = IrType('uint32')
TYPE_U64  = IrType('uint64')

class Operator:
    def __init__(self, op: str) -> None:
        self.op = op
    
    def __str__(self) -> str:
        return self.op
    
    def __repr__(self): return self.__str__()

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
OP_BITWISE_AND = Operator('&')
OP_BITWISE_OR  = Operator('|')
OP_BITWISE_XOR = Operator('^')

class Builtin:
    def __init__(self, name: str) -> None:
        self.name = name
    
    def __str__(self) -> str:
        return self.name
    
    def __repr__(self): return self.__str__()

BUILTIN_X86_PREFIX = Builtin('get_prefix')


Expression = Union['Binary', 'Unary', 'Call', 'Ternary', 'Literal', 'Var', 'Param']

class Binary(NamedTuple):
    op: Operator
    l: Any
    r: Any

class Unary(NamedTuple):
    op: Operator
    v: Any

class Call(NamedTuple):
    builtin: Builtin
    args: List[Any]

class Ternary(NamedTuple):
    condition: Any
    consequence: Any
    alternative: Any

class Literal(NamedTuple):
    value: Any

class Var(NamedTuple):
    name: str

class Param(NamedTuple):
    name: str


Statement = Union['Return', 'Assign', 'Conditional', 'Block', 'Increase', 'Define', 'Set']

class Return(NamedTuple):
    """Statement that returns a value (the size of written data if an int is returned, whether data was emitted if a bool is returned, or nothing otherwise."""
    value: Expression

class Assign(NamedTuple):
    """Statement that sets the given variable to the given expression."""
    variable: str
    value: Expression

class Conditional(NamedTuple):
    """Statement that only executes another statement if the condition is true. Additionally, it can optionally execute another statement otherwise."""
    condition: Expression
    consequence: Any
    alternative: Any = None

class Block(NamedTuple):
    """Block of statements."""
    statements: List[Any] = list()

class Increase(NamedTuple):
    """Statement that increases the index at which bytes are written by the given number of bytes.
       If @variable is not `None`, the given variable is incremented instead."""
    by: int = 1
    variable: Optional[str] = None

class Set(NamedTuple):
    """Statement that sets the current value to the given expression."""
    type: IrType
    value: Expression
    offset: Expression = Literal(0)

class Define(NamedTuple):
    """Statement that creates a new variable with the given name and initial value."""
    type: IrType
    name: str
    value: Expression


Parameter = NamedTuple('Parameter', [('name', str), ('type', IrType)])

class Function:
    def __init__(self, opts: Options, name: str, params: Sequence[Parameter], fullname: Optional[str] = None, body: Optional[List[Statement]] = None) -> None:
        self.params = params
        self.name = self.overloaded_name = name
        self.body = body or []
        self.fullname = fullname or name

        if opts.prefix:
            self.fullname = f'{opts.arch}_{self.fullname}'

    @no_type_check
    def __iadd__(self, stmts):
        if any([ isinstance(stmts, k) for k in statementClasses ]):
            self.body.append(stmts)
        else:
            self.body.extend(stmts)
        
        return self


# Utils

statementClasses = [ Return, Assign, Conditional, Block, Increase, Set, Define ]
expressionClasses = [ Binary, Unary, Ternary, Call, Literal, Var, Param ]

zero = Literal(0)
one  = Literal(1)

def param(name: str, ty: IrType) -> Parameter:
    """Returns a parameter."""
    return Parameter(name, ty)

def pswitch(name: str) -> Parameter:
    """Returns a boolean switch parameter, given its name."""
    return param(name, TYPE_BOOL)

def value_or_zero(condition: Expression, value: Expression) -> Expression:
    """Expression that returns the given value if the condition istrue, or zero otherwise."""
    return Ternary(condition, value, zero)
