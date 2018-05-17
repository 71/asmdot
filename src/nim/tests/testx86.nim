import unittest, ../asmdot/x86

suite "x86 tests":

  test "simple":
    var
      bytes = newSeqUninitialized[byte](10)
      buf = pointer(addr bytes[0])
    
    buf.inc(eax)
    buf.ret()

    check bytes[0] == 0x40
    check bytes[1] == 0xc3
