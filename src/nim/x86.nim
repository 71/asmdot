include private/x86.nim

proc inc*(operand: reg16, buf: var ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[offset] = 0x40 + operand
  buf += 1
  return offset

proc inc*(operand: reg32, buf: var ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[offset] = 0x40 + operand
  buf += 1
  return offset

proc dec*(operand: reg16, buf: var ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[offset] = 0x48 + operand
  buf += 1
  return offset

proc dec*(operand: reg32, buf: var ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[offset] = 0x48 + operand
  buf += 1
  return offset

proc push*(operand: reg16, buf: var ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[offset] = 0x50 + operand
  buf += 1
  return offset

proc push*(operand: reg32, buf: var ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[offset] = 0x50 + operand
  buf += 1
  return offset

proc pop*(operand: reg16, buf: var ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  buf += 1
  return offset

proc pop*(operand: reg32, buf: var ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    buf += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  buf += 1
  return offset

proc pop*(operand: reg64, buf: var ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x48 + prefix_adder(operand)
  buf += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  buf += 1
  return offset

proc pushf*(buf: var ptr byte): int =
  cast[ptr byte](buf)[] = 156
  buf += 1
  return 1

proc popf*(buf: var ptr byte): int =
  cast[ptr byte](buf)[] = 157
  buf += 1
  return 1

proc ret*(buf: var ptr byte): int =
  cast[ptr byte](buf)[] = 195
  buf += 1
  return 1

