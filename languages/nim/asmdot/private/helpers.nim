import macros

macro makeWrite(name: untyped, ty: typedesc, size: static[int], inverse: static[bool]): untyped =
  let
    buf = newIdentNode("buf")
    value = newIdentNode("value")
  var
    stmts = newNimNode(nnkStmtList, name)

  if inverse:
    for shift in countdown(0, size - 8, 8):
      let shiftNode = newIntLitNode(shift)

      stmts.add quote do:
        `buf`.add (byte)(`value` shr `shiftNode`)
  else:
    for shift in countup(0, size - 8, 8):
      let shiftNode = newIntLitNode(shift)

      stmts.add quote do:
        `buf`.add (byte)(`value` shr `shiftNode`)
  
  result = quote do:
    proc `name`*(`buf`: var seq[byte], `value`: `ty`) {. inline .} =
      `stmts`


makeWrite writeBE, int16, 16, cpuEndian != bigEndian
makeWrite writeBE, int32, 32, cpuEndian != bigEndian
makeWrite writeBE, int64, 64, cpuEndian != bigEndian
makeWrite writeBE, uint16, 16, cpuEndian != bigEndian
makeWrite writeBE, uint32, 32, cpuEndian != bigEndian
makeWrite writeBE, uint64, 64, cpuEndian != bigEndian

makeWrite writeLE, int16, 16, cpuEndian != littleEndian
makeWrite writeLE, int32, 32, cpuEndian != littleEndian
makeWrite writeLE, int64, 64, cpuEndian != littleEndian
makeWrite writeLE, uint16, 16, cpuEndian != littleEndian
makeWrite writeLE, uint32, 32, cpuEndian != littleEndian
makeWrite writeLE, uint64, 64, cpuEndian != littleEndian

proc add*(buf: var seq[byte], value: int8) {.inline.} =
  buf.add cast[uint8](value)
