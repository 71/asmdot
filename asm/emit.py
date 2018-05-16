from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from typing import Any, Callable, Dict, IO, no_type_check
from .ast import * # pylint: disable=W0614
from .options import Options

class Emitter(ABC, Options):
    """An AST to source code emitter."""

    @property
    @abstractmethod
    def language(self) -> str:
        """Returns the identifier of the target language."""
        pass
    
    @property
    @abstractmethod
    def filename(self) -> str:
        """Returns the name of the generated file for the current architecture."""
        pass

    @staticmethod
    def register(parser: ArgumentParser) -> None:
        """Registers the emitter, allowing it to add command-line parameters."""
        pass
    
    def initialize(self, args: Namespace) -> None:
        """Initializes the emitter using the provided command-line arguments."""
        super().initialize_options(args, self.arch)

    def get_type_name(self, ty: IrType) -> str:
        """Returns the name of the given type."""
        return ty.original
    
    def get_operator(self, op: Operator) -> str:
        """Returns the string representation of the given operator."""
        return op.op
    
    def get_builtin_name(self, builtin: Builtin) -> str:
        """Returns the name of the given builtin."""
        return builtin.name
    
    def __init__(self, args: Namespace, arch: str) -> None:
        """Initializes the emitter for the given architecture. This constructor shall not be overriden."""
        self.arch = arch
        self.indent = Indent()
        self.initialize_options(args, arch)

    def write_header(self, out: IO[str]) -> None:
        """Emits the header of the file to a stream."""
        pass
    
    def write_footer(self, out: IO[str]) -> None:
        """Emits the footer of the file to a stream."""
        pass

    @abstractmethod
    def write_expr(self, expr: Expression, out: IO[str]) -> None:
        """Emits an expression to a stream.
           Additionally, the `str` function will be modified to use this method for every `Expression` class."""
        raise NotImplementedError

    @abstractmethod
    def write_stmt(self, stmt: Statement, out: IO[str]) -> None:
        """Emits a statement to a stream.
           Additionally, the `str` function will be modified to use this method for every `Statement` class."""
        raise NotImplementedError
    
    @abstractmethod
    def write_function(self, fun: Function, out: IO[str]) -> None:
        """Emits a function to a stream."""
        raise NotImplementedError

    def write(self, *args, indent: Optional[bool] = None, newline: Optional[bool] = None) -> None:
        """Writes the given arguments to the stream named 'out' or 'output' in the current scope.
           When invoked via the 'write_stmt' function, indentation and the newline are added by default."""
        import inspect

        up = inspect.stack()[1][0]
        out: IO[str] = up.f_locals['out'] if 'out' in up.f_locals else up.f_locals['output']

        if indent is None:
            indent = up.f_code.co_name == 'write_stmt'

        if indent:
            out.write(str(self.indent))

        for arg in args:
            out.write(str(arg))
        
        if newline is None:
            newline = up.f_code.co_name == 'write_stmt'
        
        if newline:
            out.write('\n')
    
@no_type_check
def replace_pattern(patterns: Dict[str, str], string: str) -> str:
    """Replaces the string by the first template matching the corresponding key."""
    import re

    if not hasattr(replace_pattern, 'memoized'):
        replace_pattern.memoized = {}

    for pattern in patterns:
        if pattern in replace_pattern.memoized:
            pat = replace_pattern.memoized[pattern]
        else:
            pat = re.compile(pattern)
            replace_pattern.memoized[pattern] = pat

        newstring, n = pat.subn(patterns[pattern], string, count=1)

        if n == 1:
            return newstring
    
    return string

def prefix(opts: Any, string: str) -> str:
    """Prefixes the given string by `opts.arch` if `opts.prefix` is `True`."""
    if hasattr(opts, 'prefix') and opts.prefix:
        assert hasattr(opts, 'arch')

        return f'{opts.arch}_{string}'

    return string

class Indent:
    """Helper class that manages the indentation when writing a string."""

    def __init__(self, indent_str: str = '  ', lvl: int = 0) -> None:
        self._str = indent_str
        self._lvl = lvl
    
    def __iadd__(self, i: int) -> 'Indent':
        """Adds the given level of indentation to the current one."""
        self._lvl += i

        return self
    
    def __isub__(self, i: int) -> 'Indent':
        """Removes the given level of indentation from the current one."""
        self._lvl -= i

        return self
    
    def __add__(self, i: int):
        """Returns a new indentation object with a greater indentation level."""
        return Indent(self._str, self._lvl + i)

    def __sub__(self, i: int):
        """Returns a new indentation object with a lower indentation level."""
        return Indent(self._str, self._lvl - i)
    
    def further(self, i: int = 1):
        """Returns an object that can be __enter__'d and __exit__'d with the `with` syntax.
           Inside the created block, the indentation level is increased by the given integer."""
        class FurtherWrapper:
            @classmethod
            def __enter__(s, *_):
                self._lvl += i
            @classmethod
            def __exit__(s, *_):
                self._lvl -= i
        
        return FurtherWrapper()
    
    def write(self, io: IO[str], *args) -> None:
        """Writes the indent to a text stream."""
        io.write(self._str * self._lvl)

        for arg in args:
            io.write(str(arg))

    def __call__(self, fmt: str, *args) -> str:
        """Returns the given string, indented and terminated with a line feed. Additionally, other arguments can be given in order to format the string."""
        return str(self) + (fmt.format(*args) if len(args) else fmt) + '\n'

    def __str__(self) -> str:
        """Returns the string representation of the indentation level, which is `'  ' * indent_level`."""
        return self._str * self._lvl

class UnsupportedArchitecture(Exception):
    arch: str

    def __str__(self):
        return f'Architecture {self.arch} is not supported.'

class UnsupportedExpression(Exception):
    expr: Expression

    def __str__(self):
        return f'Expression of type {self.expr.__class__.__name__} is not supported.'

class UnsupportedStatement(Exception):
    stmt: Statement

    def __str__(self):
        return f'Statement of type {self.stmt.__class__.__name__} is not supported.'

class UnsupportedOption(Exception):
    option: str
    explain: str

    def __str__(self):
        return f'Option "{self.option}" is not supported: {self.explain}'
