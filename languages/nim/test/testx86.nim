import sequtils, unittest, ../asmdot/x86

suite "test x86 assembler":
  setup:
    var
      bytes = newSeqOfCap[byte](100)
      buf = addr bytes[0]

  test "should assemble single ret instruction":
    buf.ret()

    check cast[seq[char]](bytes) == toSeq("\xc3".items)

