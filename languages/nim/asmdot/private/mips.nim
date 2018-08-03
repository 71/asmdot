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


proc sll*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((0'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc movci*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((1'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc srl*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((2'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc sra*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((3'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc sllv*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((4'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc srlv*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((6'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc srav*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((7'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc jr*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((8'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc jalr*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((9'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc movz*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((10'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc movn*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((11'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc syscall*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((12'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc breakpoint*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((13'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc sync*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((15'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc mfhi*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((16'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc mthi*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((17'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc mflo*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((18'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsllv*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((20'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsrlv*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((22'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsrav*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((23'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc mult*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((24'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc multu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((25'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc Div*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((26'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc divu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((27'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dmult*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((28'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dmultu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((29'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc ddiv*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((30'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc ddivu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((31'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc add*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((32'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc addu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((33'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc sub*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((34'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc subu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((35'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc And*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((36'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc Or*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((37'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc Xor*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((38'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc nor*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((39'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc slt*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((42'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc sltu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((43'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dadd*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((44'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc daddu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((45'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsub*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((46'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsubu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((47'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc tge*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((48'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc tgeu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((49'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc tlt*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((50'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc tltu*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((51'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc teq*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((52'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc tne*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((54'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsll*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((56'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dslr*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((58'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc dsra*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((59'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc mhc0*(buf: var seq[byte], rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint32 rd
    rs = uint32 rs
    rt = uint32 rt
    shift = uint32 shift

  buf.writeLE cast[uint32](((((1073741824'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((rd and 31'u32) shl 11'u32)) or ((shift and 31'u32) shl 6'u32)))


proc btlz*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bgez*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bltzl*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bgezl*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc sllv*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc tgei*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc jalr*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc tlti*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc tltiu*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc teqi*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc tnei*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bltzal*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bgezal*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bltzall*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc bgezall*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc dsllv*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc synci*(buf: var seq[byte], rs: Reg, target: uint16) = 
  var
    rs = uint32 rs
    target = uint32 target

  buf.writeLE cast[uint32](((67108864'u32 or ((rs and 31'u32) shl 16'u32)) or ((target shr 2'u32) and 65535'u32)))


proc addi*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((536870912'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc addiu*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((603979776'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc andi*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((805306368'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc beq*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((268435456'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2)))


proc blez*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((402653184'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2)))


proc bne*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((335544320'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or ((imm and 65535'u32) shr 2)))


proc lw*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2348810240'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc lbu*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2415919104'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc lhu*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2483027968'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc lui*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((1006632960'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc ori*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((872415232'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc sb*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2684354560'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc sh*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2751463424'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc slti*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((671088640'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc sltiu*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((738197504'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc sw*(buf: var seq[byte], rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint32 rs
    rt = uint32 rt
    imm = uint32 imm

  buf.writeLE cast[uint32]((((2885681152'u32 or ((rs and 31'u32) shl 21'u32)) or ((rt and 31'u32) shl 16'u32)) or (imm and 65535'u32)))


proc j*(buf: var seq[byte], address: uint32) = 
  buf.writeLE cast[uint32]((134217728'u32 or ((address shr 2'u32) and 67108863'u32)))


proc jal*(buf: var seq[byte], address: uint32) = 
  buf.writeLE cast[uint32]((201326592'u32 or ((address shr 2'u32) and 67108863'u32)))


proc assemble*(buf: var seq[byte], opcode: string, params: varargs[Any]): bool =
  return false
