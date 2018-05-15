include private/x86.nim

proc inc*(operand: reg16, buf: ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  offset += 1
  cast[ptr byte](buf)[offset] = 0x40 + operand
  offset += 1
  return offset

proc inc*(operand: reg32, buf: ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    offset += 1
  cast[ptr byte](buf)[offset] = 0x40 + operand
  offset += 1
  return offset

proc dec*(operand: reg16, buf: ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  offset += 1
  cast[ptr byte](buf)[offset] = 0x48 + operand
  offset += 1
  return offset

proc dec*(operand: reg32, buf: ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    offset += 1
  cast[ptr byte](buf)[offset] = 0x48 + operand
  offset += 1
  return offset

proc push*(operand: reg16, buf: ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  offset += 1
  cast[ptr byte](buf)[offset] = 0x50 + operand
  offset += 1
  return offset

proc push*(operand: reg32, buf: ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    offset += 1
  cast[ptr byte](buf)[offset] = 0x50 + operand
  offset += 1
  return offset

proc pop*(operand: reg16, buf: ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x66 + prefix_adder(operand)
  offset += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  offset += 1
  return offset

proc pop*(operand: reg32, buf: ptr byte): int =
  var offset = 0
  if (operand > 7):
    cast[ptr byte](buf)[] = 65
    offset += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  offset += 1
  return offset

proc pop*(operand: reg64, buf: ptr byte): int =
  var offset = 0
  cast[ptr byte](buf)[] = 0x48 + prefix_adder(operand)
  offset += 1
  cast[ptr byte](buf)[offset] = 0x58 + operand
  offset += 1
  return offset

proc pushf*(buf: ptr byte): int =
  cast[ptr byte](buf)[] = 156
  return 1

proc popf*(buf: ptr byte): int =
  cast[ptr byte](buf)[] = 157
  return 1

proc ret*(buf: ptr byte): int =
  cast[ptr byte](buf)[] = 195
  return 1

