from asm.testsource import *  # pylint: disable=W0614

class MipsTestSource(TestSource):

    @property
    def name(self) -> str:
        return 'mips'

    @property
    def test_cases(self) -> TestCases:
        yield TestCase('should assemble single addi instruction', [
            self.make_call('addi', 'Reg::T1', 'Reg::T2', '0\'uint8')
        ], bytearray(b'\x00\x00\x49\x21'))
