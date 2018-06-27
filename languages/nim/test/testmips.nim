import sequtils, unittest, ../asmdot/mips

suite "test mips assembler":
  setup:
    var
      bytes = newSeqOfCap[byte](100)
      buf = addr bytes[0]

  test "should assemble single addi instruction":
    buf.addi(T1, T2, 0)

    check cast[seq[char]](bytes) == toSeq("\x00\x00\x49\x21".items)

