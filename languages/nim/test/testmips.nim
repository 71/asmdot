import sequtils, unittest, ../asmdot/mips

suite "test mips assembler":
  setup:
    var
      buf = newSeqOfCap[byte](100)

  test "should assemble single addi instruction":
    buf.addi(T1, T2, 0)

    check cast[seq[char]](buf) == toSeq("\x00\x00\x49\x21".items)

