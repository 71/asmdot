import sequtils, unittest, ../asmdot/arm

suite "test arm assembler":
  setup:
    var
      buf = newSeqOfCap[byte](100)

  test "should encode single cps instruction":
    buf.cps(USR)

    check cast[seq[char]](buf) == toSeq("\x10\x00\x02\xf1".items)

