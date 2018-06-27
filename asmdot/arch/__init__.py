from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from parsy import regex, eof, seq, Parser
from typing import Callable, IO, Iterator, List

from ..ast import Declaration, Function, TestCase, TestCaseCall
from ..helpers import relative
from ..options import Options
from .testsource import TestSource


Declarations = Iterator[Declaration]
Functions    = Iterator[Function]

class Architecture(ABC, Options):
    """An architecture parser."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the architecture."""
        pass


    @staticmethod
    def register(parser: ArgumentParser) -> None:
        """Registers the architecture, allowing it to add command-line parameters."""
        pass
    
    def initialize(self, args: Namespace) -> None:
        """Initializes the architecture using the provided command-line arguments."""
        super().initialize_options(args, self.name)


    @property
    @abstractmethod
    def tests(self) -> TestSource:
        """Returns the tests for the architecture."""
        pass
    
    @property
    def declarations(self) -> Declarations:
        """Returns an iterator over all non-instruction declarations for the architecture."""
        pass
    
    @property
    @abstractmethod
    def functions(self) -> Functions:
        """Returns an iterator over all functions for the architecture."""
        pass


def open_data(self, filename: str = 'data.txt') -> IO[str]:
    """Returns the data file associated to this architecture."""
    return open(relative(filename), 'r')

def translate(filename: str = 'data.txt'):
    """Transforms the given method so that it matches the `functions` signature."""
    def decorator(f: Callable[[Architecture, IO[str]], Functions]):
        def wrapper(arch: Architecture) -> Functions:
            with open_data(filename) as input:
                return f(arch, input)
        
        return property(wrapper)
    
    return decorator


# Lexer / parser built-ins

ws  = regex(r'[ \t]+').desc('whitespace')
ows = regex(r'[ \t]*').desc('whitespace')
end = (regex(r'\n+') | eof).desc('end of line')

def parse(*args):
    """Creates a parser that maps the given parse to the designated function."""
    if len(args) == 0:
        raise ValueError('At least one parser required.')

    parsers = []

    for arg in args:
        if isinstance(arg, str):
            parsers.append(regex(arg))
        elif isinstance(arg, Parser):
            parsers.append(arg)
        else:
            raise ValueError('Invalid parser provided.')

    if len(args) == 1:
        return parsers[0].map
    else:
        return seq(*parsers).combine
