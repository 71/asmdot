from asm.testsource import *  # pylint: disable=W0614

class ArmTestSource(TestSource):

    @property
    def name(self) -> str:
        return 'arm'

    @property
    def test_cases(self) -> TestCases:
        yield TestCase('should encode single cps instruction', [
            self.make_call('cps', 'Mode::USR')
        ], bytearray(b'\x10\x00\x02\xf1'))
