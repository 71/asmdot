type Reg* = distinct uint8 ## A Mips register.

const
  Zero* = Reg 0
  AT* = Reg 1
  V0* = Reg 2
  V1* = Reg 3
  A0* = Reg 4
  A1* = Reg 5
  A2* = Reg 6
  A3* = Reg 7
  T0* = Reg 8
  T1* = Reg 9
  T2* = Reg 10
  T3* = Reg 11
  T4* = Reg 12
  T5* = Reg 13
  T6* = Reg 14
  T7* = Reg 15
  S0* = Reg 16
  S1* = Reg 17
  S2* = Reg 18
  S3* = Reg 19
  S4* = Reg 20
  S5* = Reg 21
  S6* = Reg 22
  S7* = Reg 23
  T8* = Reg 24
  T9* = Reg 25
  K0* = Reg 26
  K1* = Reg 27
  GP* = Reg 28
  SP* = Reg 29
  FP* = Reg 30
  RA* = Reg 31


proc sll*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((0'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc movci*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((1'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc srl*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((2'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sra*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((3'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sllv*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((4'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc srlv*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((6'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc srav*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((7'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc jr*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((8'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc jalr*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((9'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc movz*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((10'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc movn*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((11'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc syscall*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((12'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc breakpoint*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((13'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sync*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((15'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mfhi*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((16'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mthi*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((17'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mflo*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((18'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mfhi*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((19'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsllv*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((20'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsrlv*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((22'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsrav*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((23'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mult*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((24'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc multu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((25'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Div*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((26'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc divu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((27'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dmult*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((28'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dmultu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((29'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ddiv*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((30'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ddivu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((31'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc add*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((32'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc addu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((33'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sub*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((34'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc subu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((35'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc And*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((36'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Or*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((37'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Xor*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((38'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc nor*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((39'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc slt*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((42'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sltu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((43'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dadd*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((44'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc daddu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((45'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsub*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((46'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsubu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((47'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tge*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((48'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tgeu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((49'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tlt*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((50'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tltu*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((51'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc teq*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((52'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tne*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((54'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsll*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((56'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dslr*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((58'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsra*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((59'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mhc0*(buf: var ptr byte, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  cast[ptr uint32](buf)[] = ((((1073741824'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc btlz*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bgez*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bltzl*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bgezl*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sllv*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tgei*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc jalr*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tlti*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tltiu*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc teqi*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tnei*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bltzal*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bgezal*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bltzall*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bgezall*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc dsllv*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc synci*(buf: var ptr byte, rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  cast[ptr uint32](buf)[] = ((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc addi*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((536870912'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc addiu*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((603979776'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc andi*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((805306368'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc beq*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((268435456'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc blez*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((402653184'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bne*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((335544320'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc lw*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2348810240'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc lbu*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2415919104'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc lhu*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2483027968'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc lui*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((1006632960'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ori*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((872415232'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sb*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2684354560'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sh*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2751463424'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc slti*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((671088640'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sltiu*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((738197504'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sw*(buf: var ptr byte, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  cast[ptr uint32](buf)[] = (((2885681152'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc j*(buf: var ptr byte, address: uint32) = 
  cast[ptr uint32](buf)[] = (134217728'u32 or ((address shr 2'u32) and 67108863'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc jal*(buf: var ptr byte, address: uint32) = 
  cast[ptr uint32](buf)[] = (201326592'u32 or ((address shr 2'u32) and 67108863'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


