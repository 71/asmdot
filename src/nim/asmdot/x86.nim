include private/x86.nim

proc inc*(buf: var ptr byte, operand: reg16) =
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[] = 0x40 + operand
  buf += 1


proc inc*(buf: var ptr byte, operand: reg32) =
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[] = 0x40 + operand
  buf += 1


proc dec*(buf: var ptr byte, operand: reg16) =
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[] = 0x48 + operand
  buf += 1


proc dec*(buf: var ptr byte, operand: reg32) =
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[] = 0x48 + operand
  buf += 1


proc push*(buf: var ptr byte, operand: reg16) =
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[] = 0x50 + operand
  buf += 1


proc push*(buf: var ptr byte, operand: reg32) =
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[] = 0x50 + operand
  buf += 1


proc pop*(buf: var ptr byte, operand: reg16) =
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[] = 0x58 + operand
  buf += 1


proc pop*(buf: var ptr byte, operand: reg32) =
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[] = 0x58 + operand
  buf += 1


proc pop*(buf: var ptr byte, operand: reg64) =
  cast[ptr byte](buf)[] = 0x48 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[] = 0x58 + operand
  buf += 1


proc pushf*(buf: var ptr byte) =
  cast[ptr byte](buf)[] = 156
  buf += 1


proc popf*(buf: var ptr byte) =
  cast[ptr byte](buf)[] = 157
  buf += 1


proc ret*(buf: var ptr byte) =
  cast[ptr byte](buf)[] = 195
  buf += 1


