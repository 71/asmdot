import unittest, ../asmdot, ../asmdot/arm, ../asmdot/x86

suite "x86 tests":

  test "simple":
    var
      bytes = newSeqUninitialized[byte](10)
      buf = pointer(addr bytes[0])
    
    buf.inc(eax)
    buf.ret()

    check bytes[0] == 0x40
    check bytes[1] == 0xc3

suite "arm tests":
  
  test "simple":
    var
      bytes = newSeqUninitialized[byte](10)
      buf = pointer(addr bytes[0])
    
    buf.cps(USR)
    
    check cast[ptr uint32](addr bytes[0])[] == 0xF1020010'u32
