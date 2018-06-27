from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from parsy import regex, eof, seq, Parser
from typing import Callable, IO, Iterator, List

from ..ast import Declaration, Function, TestCase, TestCaseCall
from ..helpers import relative, parse, ws, end
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
    