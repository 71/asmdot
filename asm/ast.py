from inspect import isgenerator
from typing import Any, Optional, NamedTuple, NewType, List, Sequence, Tuple, Union, no_type_check


class IrType(NamedTuple):
    id: str
    underlying: Optional[Any] = None
    
    def __str__(self) -> str:
        return self.id
    
    def __repr__(self): return self.__str__()

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

TYPE_VOID = IrType('void')
TYPE_BOOL = IrType('bool')
TYPE_I8   = IrType('int8')
TYPE_I16  = IrType('int16')
TYPE_I32  = IrType('int32')
TYPE_I64  = IrType('int64')
TYPE_U8   = IrType('uint8')
TYPE_U16  = IrType('uint16')
TYPE_U32  = IrType('uint32')
TYPE_U64  = IrType('uint64')
TYPE_BYTE = TYPE_U8

TYPE_ARM_REG  = IrType('Reg',       TYPE_BYTE)
TYPE_ARM_COND = IrType('Condition', TYPE_BYTE)
TYPE_ARM_MODE = IrType('Mode',      TYPE_BYTE)
TYPE_ARM_SHIFT  = IrType('Shift',          TYPE_BYTE)
TYPE_ARM_FIELD  = IrType('FieldMask',      TYPE_BYTE)
TYPE_ARM_IFLAGS = IrType('InterruptFlags', TYPE_BYTE)
TYPE_ARM_ROTATION = IrType('Rotation', TYPE_BYTE)

TYPE_X86_R8   = IrType('Reg8',   TYPE_BYTE)
TYPE_X86_R16  = IrType('Reg16',  TYPE_BYTE)
TYPE_X86_R32  = IrType('Reg32',  TYPE_BYTE)
TYPE_X86_R64  = IrType('Reg64',  TYPE_BYTE)
TYPE_X86_R128 = IrType('Reg128', TYPE_BYTE)


class Operator(NamedTuple):
    op: str
    
    def __str__(self) -> str:
        return self.op
    
    def __repr__(self): return self.__str__()

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
OP_BITWISE_AND = Operator('&')
OP_BITWISE_OR  = Operator('|')
OP_BITWISE_XOR = Operator('^')


class Builtin(NamedTuple):
    name: str
    
    def __str__(self) -> str:
        return self.name
    
    def __repr__(self): return self.__str__()

# Built-ins get arbitrary names.

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
    type: IrType

class Var(NamedTuple):
    name: str

class Param(NamedTuple):
    name: str


Statement = Union['Assign', 'Conditional', 'Block', 'Increase', 'Define', 'Set']

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

class Set(NamedTuple):
    """Statement that sets the current value to the given expression."""
    type: IrType
    value: Expression

class Define(NamedTuple):
    """Statement that creates a new variable with the given name and initial value."""
    type: IrType
    name: str
    value: Expression


Parameter = NamedTuple('Parameter', [('name', str), ('type', IrType)])

class Function:
    def __init__(self, name: str, params: Sequence[Parameter], fullname: Optional[str] = None, body: Optional[List[Statement]] = None) -> None:
        self.params = params
        self.name = name
        self.body = body or []
        self.fullname = fullname or name

    @no_type_check
    def __iadd__(self, stmts):
        if any([ isinstance(stmts, k) for k in statementClasses ]):
            self.body.append(stmts)
        else:
            self.body.extend(stmts)
        
        return self


# Utils

statementClasses = [ Assign, Conditional, Block, Increase, Set, Define ]
expressionClasses = [ Binary, Unary, Ternary, Call, Literal, Var, Param ]

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
