type
  Reg* = distinct byte

  Condition* {.pure.} = enum
    EQ = 0b0000

  Mode* {.pure.} = enum
    USR = 0b00000

include private/arm
