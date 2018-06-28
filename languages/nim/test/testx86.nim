import sequtils, unittest, ../asmdot/x86

suite "test x86 assembler":
  setup:
    var
      buf = newSeqOfCap[byte](100)

  test "should assemble single ret instruction":
    buf.ret()

    check cast[seq[char]](buf) == toSeq("\xc3".items)

