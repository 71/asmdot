import unittest, ../asmdot/arm

suite "test arm assembler":
  setup:
    var
      bytes = newSeqOfBytes[byte](100)
      buf = addr bytes[0]

  test "should encode single cps instruction":
    buf.cps(USR)

    check buf == "\x10\x00\x02\xf1"

