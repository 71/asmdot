from ..testsource import *  # pylint: disable=W0614

class X86TestSource(TestSource):

    @property
    def name(self) -> str:
        return 'x86'

    @property
    def test_cases(self) -> TestCases:
        yield TestCase('should assemble single ret instruction', [
            self.make_call('ret')
        ], bytearray(b'\xC3'))
