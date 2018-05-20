type Reg8* = distinct uint8 ## An x86 8-bits register.

type Reg16* = distinct uint8 ## An x86 16-bits register.

type Reg32* = distinct uint8 ## An x86 32-bits register.

type Reg64* = distinct uint8 ## An x86 64-bits register.

type Reg128* = distinct uint8 ## An x86 128-bits register.

proc inc*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc inc*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc dec*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc dec*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc push*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc push*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg64) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (72'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pushf*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 156'u8
  buf = cast[pointer](cast[uint](buf) + 1)


proc popf*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 157'u8
  buf = cast[pointer](cast[uint](buf) + 1)


proc ret*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 195'u8
  buf = cast[pointer](cast[uint](buf) + 1)


