from asm.ast import *    # pylint: disable=W0614
from asm.parse import *  # pylint: disable=W0614

class ExampleArchitecture(Architecture):
    """Example `Architecture` that can be used to easily get started creating a new
       architecture parser."""

    @property
    def name(self) -> str:
        # Return the identifier of the architecture,
        # which will also be used to lookup the instructions file.

        return 'example' # File 'data/example.txt' will be loaded.


    @property
    def declarations(self) -> Iterator[Declaration]:
        # Yield declarations (DistinctType or Enumeration) that will be used by the
        # generated functions.

        TYPE_EXAMPLE = IrType('ExampleName', TYPE_BYTE)

        yield DistinctType(TYPE_EXAMPLE, 'Documentation of the distinct type.', [
            Constant('CONSTANT_NAME', 0),
        ])


        # Flags enum (can be OR'd, AND'd, XOR'd, etc).
        yield Enumeration(TYPE_EXAMPLE, True, 'Documentation...', [], [])

        # Non-flags enum (cannot be OR'd, AND'd, XOR'd, etc).
        yield Enumeration(TYPE_EXAMPLE, False, 'Documentation...', [], [])

        yield Enumeration(TYPE_EXAMPLE, False, 'Documentation...', [
            # First array argument defines all the core enum members in increasing value.
            EnumerationMember('EQ', 0x0, 'Documentation of the first member...'),
            EnumerationMember('NE', 0x1, 'Documentation of the second member...'),

            # Some languages do not support multiple enum values that have the same name,
            # even if the enum they belong to is different, and likewise with constants.
            # Thus, ASM. encourages you to provide a unique, longer name that can be chosen
            # by such languages by specifying a 4th argument.
            EnumerationMember('AL', 0xE, 'Documentation...', '*Always')
                # Will either have the name 'AL' or 'ExampleNameAlways' depending on the language.

        ], [
            # Second array argument defines all additional members that have previously given
            # values, but that are still good to have around.
            EnumerationMember('Equal', 0x0, 'Documentation...'),
            EnumerationMember('NotEqual', 0x1, 'Documentation...')

        ])


    def translate(self, input: IO[str]):
        # Parse the input however you like!
        #
        # Parsy (https://github.com/python-parsy/parsy) is recommended for parsing.
        # Furthermore, some utilities are provided to make parsing easier.

        @parse(r'\d*\.\d+')
        def floating_point(n: str) -> float:
            return float(n)

        @parse(floating_point, '=', floating_point)
        def comparison(a: float, _, b: float) -> bool:
            return a == b
        
        plus = string('+')

        @parse(floating_point.sep_by(plus) << ws)
        def floats_sum(floats: List[float]) -> float:
            return sum(floats)

        for line in input:
            line = line.strip()

            if not len(line):
                continue
        
            try:
                parsed = (floats_sum | comparison).parse(line)

                yield Function('Function name', [], 'FullName (when overloading is not supported)', [])

            except ParseError as err:
                logger.error(f'Invalid instruction: "{line}".')
                logger.exception(err)
