import unittest, ../asmdot/mips

suite "test mips assembler":
  setup:
    var
      bytes = newSeqOfBytes[byte](100)
      buf = addr bytes[0]

  test "should assemble single addi instruction":
    buf.addi(T1, T2, 0)

    check buf == "\x21\xcd\x00\x00"

