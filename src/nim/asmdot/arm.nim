type
  Reg* = distinct byte

  Condition* {.pure.} = enum ## Condition for an ARM instruction to be executed.
    EQ = 0b0000, ## Equal.
    NE = 0b0001, ## Not equal.
    HS = 0b0010, ## Unsigned higher or same.
    LO = 0b0011, ## Unsigned lower.
    MI = 0b0100, ## Minus / negative.
    PL = 0b0101, ## Plus / positive or zero.
    VS = 0b0110, ## Overflow.
    VC = 0b0111, ## No overflow.
    HI = 0b1000, ## Unsigned higher.
    LS = 0b1001, ## Unsigned lower or same.
    GE = 0b1010, ## Signed greater than or equal.
    LT = 0b1011, ## Signed less than.
    GT = 0b1100, ## Signed greater than.
    LE = 0b1101, ## Signed less than or equal.
    AL = 0b1110, ## Always (unconditional).
    UN = 0b1111  ## Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).

  Mode* {.pure.} = enum ## Processor mode.
    USR = 0b10000 ## User mode.
    FIQ = 0b10001 ## FIQ (high-speed data transfer) mode.
    IRQ = 0b10010 ## IRQ (general-purpose interrupt handling) mode.
    SVC = 0b10011 ## Supervisor mode.
    ABT = 0b10111 ## Abort mode.
    UND = 0b11011 ## Undefined mode.
    SYS = 0b11111 ## System (privileged) mode.

  Shift* {.pure.} = enum ## Kind of a shift.
    LSL = 0b00, ## Logical shift left.
    LSR = 0b01, ## Logical shift right.
    ASR = 0b10, ## Arithmetic shift right.
    ROR = 0b11  ## Rotate right.

  Rotation* {.pure.} = enum ## Kind of a right rotation.
    NOP   = 0b00, ## Do not rotate.
    ROR8  = 0b01, ## Rotate 8 bits to the right.
    ROR16 = 0b10, ## Rotate 16 bits to the right.
    ROR24 = 0b11  ## Rotate 24 bits to the right.
    
  Field* {.pure.} = enum ## Field mask bits.
    C = 0b0001, ## Control field mask bit.
    X = 0b0010, ## Extension field mask bit.
    S = 0b0100, ## Status field mask bit.
    F = 0b1000  ## Flags field mask bit.

  InterruptFlags* {.pure.} = enum ## Interrupt flags.
    F = 0b001, ## FIQ interrupt bit.
    I = 0b010, ## IRQ interrupt bit.
    A = 0b100  ## Imprecise data abort bit.

template mkFlags(typ: typedesc): untyped =
  proc `or`*(a, b: typ): typ {.inline.} = typ(byte(a) or byte(b))
  proc `and`*(a, b: typ): typ {.inline.} = typ(byte(a) and byte(b))

mkFlags Field
mkFlags InterruptFlags

template CS*(condition: type Condition): Condition =
  ## Carry set.
  HS

template CC*(condition: type Condition): Condition =
  ## Carry clear.
  LO

template RRX*(shift: type Shift): Shift =
  ## Shifted right by one bit.
  ROR


include private/arm
