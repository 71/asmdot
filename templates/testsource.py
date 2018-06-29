from asmdot.arch import *  # pylint: disable=W0614

class ExampleTestSource(TestSource):
    """Example `TestSource` that can be used to easily get started creating tests for all
       languages."""

    @property
    def name(self) -> str:
        # Return the name of the architecture for which the tests are provided.
        # It /must/ match the name provided by the `Architecture`.
        return 'example'

    @property
    def test_cases(self) -> TestCases:
        # Return test cases that can be used in all languages to compare
        # calls, and the generated machine code.

        yield TestCase('short description of the test (spaces are allowed)', [
            self.make_call('full_instr_name', "42'int8", "0xff'int32", "0b1111'reg32"),
            self.make_call('other_full_instr_name', "Enum::Member", "Enum.OtherMember")
        ], bytearray(b'\x04\x02'))
