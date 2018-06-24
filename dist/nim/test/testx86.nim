import unittest, ../asmdot/x86

suite "test x86 assembler":
  setup:
    var
      bytes = newSeqOfBytes[byte](100)
      buf = addr bytes[0]

  test "should assemble single ret instruction":
    buf.ret()

    check buf == "\xc3"

