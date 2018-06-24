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


proc add*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((32'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc addu*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((33'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc And*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((36'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc div*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((26'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc divu*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((27'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc jr*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((8'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mfhi*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((16'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mflo*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((18'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mhc0*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((1073741824'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mult*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((24'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc multu*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((25'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc nor*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((39'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc xor*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((38'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc or*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((37'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc slt*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((42'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sltu*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((43'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sll*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((0'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc srl*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((2'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sra*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((3'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sub*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((34'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc subu*(buf: var pointer, rd: Reg, rs: Reg, rt: Reg, shift: uint8) = 
  var
    rd = uint8 rd
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = ((((35'u32 or (rs shl 21)) or (rt shl 16)) or (rd shl 11)) or (shift shl 6))
  buf = cast[pointer](cast[uint](buf) + 4)


proc addi*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((536870912'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc addiu*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((603979776'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc andi*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((805306368'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc beq*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((268435456'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc blez*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((402653184'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc bne*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((335544320'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc lbu*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((2415919104'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc lhu*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((2483027968'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc lui*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((1006632960'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc ori*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((872415232'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc sb*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((2684354560'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc sh*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((2751463424'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc slti*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((671088640'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc sltiu*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((738197504'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc sw*(buf: var pointer, rs: Reg, rt: Reg, imm: uint16) = 
  var
    rs = uint8 rs
    rt = uint8 rt

  cast[ptr uint32](buf)[] = (((2885681152'u32 or (rs shl 21)) or (rt shl 16)) or imm)
  buf = cast[pointer](cast[uint](buf) + 4)


proc j*(buf: var pointer, addr: uint32) = 
  cast[ptr uint32](buf)[] = (2885681152'u32 or (67108863 and (addr shl 2)))
  buf = cast[pointer](cast[uint](buf) + 4)


proc jal*(buf: var pointer, addr: uint32) = 
  cast[ptr uint32](buf)[] = (2885681152'u32 or (67108863 and (addr shl 2)))
  buf = cast[pointer](cast[uint](buf) + 4)


