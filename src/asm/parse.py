from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from parsy import regex, eof, seq, Parser
from typing import IO, Iterator, List
from .ast import Declaration, Function, TestCase, TestCaseCall
from .options import Options

Declarations = Iterator[Declaration]
Functions    = Iterator[Function]

class Architecture(ABC, Options):
    """An architecture parser."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the architecture."""
        pass
    
    @property
    def declarations(self) -> Declarations:
        """Returns an iterator over all non-instruction declarations for the architecture."""
        pass
    
    @staticmethod
    def register(parser: ArgumentParser) -> None:
        """Registers the architecture, allowing it to add command-line parameters."""
        pass
    
    def initialize(self, args: Namespace) -> None:
        """Initializes the architecture using the provided command-line arguments."""
        super().initialize_options(args, self.name)
    
    @abstractmethod
    def translate(self, input: IO[str]) -> Functions:
        """Translates an input file into a stream of `Function`s."""
        pass


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
