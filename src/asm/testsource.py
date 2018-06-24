from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from parsy import string
from typing import Iterator, List
from .ast import Declaration, DistinctType, Enumeration, Function, IrType, all_types
from .ast import TestCase, TestCaseArgument, TestCaseCall, ArgConstant, ArgEnumMember, ArgInteger
from .options import Options
from .parse import parse

TestCases = Iterator[TestCase]

class TestSource(ABC, Options):
    """A source of tests for an architecture."""
    declarations: List[Declaration]
    functions: List[Function]

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the architecture for which tests will be produced."""
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
    def test_cases(self) -> TestCases:
        """Returns an iterator over all test cases for the architecture."""
        pass


    def make_argument(self, repr: str) -> TestCaseArgument:
        """Creates a `TestCaseArgument`, given its string representation.
        
           Supported syntax:
             Enum::Member
             Enum.Member
             10'u8
             0xff'u16
             0b111'reg32
           """

        @parse('\'', r'[\w\d]+')
        def literal_type(_, typ_: str) -> IrType:
            typ = typ_.lower()

            for ty in all_types:
                if ty.id.lower() == typ:
                    return ty
            
            raise KeyError()

        @parse(r'\w+', r'(\.|\:\:)', r'\w+')
        def enum_member(enum_: str, _, member_: str) -> ArgEnumMember:
            enum = enum_.lower()
            member = member_.lower()

            for e in self.declarations:
                if isinstance(e, Enumeration) and e.type.id.lower() == enum:
                    for m in e.members + e.additional_members:
                        if m.name.lower() != member and m.fullname.lower() != member:
                            continue
                        
                        return ArgEnumMember(e, m)
                elif isinstance(e, DistinctType) and e.type.id.lower() == enum:
                    for c in e.constants:
                        if c.name.lower() != member:
                            continue
                        
                        return ArgConstant(e, c)
            
            raise KeyError()
        
        @parse(r'\d+')
        def dec_literal(n: str) -> int:
            return int(n)

        @parse('0b', r'[abcdefABCDEF0123456789]')
        def hex_literal(_, n: str) -> int:
            return int(n, base=16)

        @parse('0x', r'[01]')
        def bin_literal(_, n: str) -> int:
            return int(n, base=2)
        
        @parse(dec_literal | hex_literal | bin_literal, literal_type)
        def literal(n: int, typ: IrType) -> ArgInteger:
            return ArgInteger(typ, n)

        return (enum_member | literal).parse(repr)

    def make_call(self, name: str, *args) -> TestCaseCall:
        """Creates a `TestCaseCall`, given the full name of the function to invoke and its arguments."""
        for fn in self.functions:
            if fn.fullname != name:
                continue
            
            return TestCaseCall(fn, [ self.make_argument(arg) for arg in args ])
        
        raise KeyError()
