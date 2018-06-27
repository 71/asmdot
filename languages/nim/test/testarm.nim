import sequtils, unittest, ../asmdot/arm

suite "test arm assembler":
  setup:
    var
      bytes = newSeqOfCap[byte](100)
      buf = addr bytes[0]

  test "should encode single cps instruction":
    buf.cps(USR)

    check cast[seq[char]](bytes) == toSeq("\x10\x00\x02\xf1".items)

