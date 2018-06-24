type Reg* = distinct uint8 ## Mips register

const
  zero* = Reg 0
  at* = Reg 1
  v0* = Reg 2
  v1* = Reg 3
  a0* = Reg 4
  a1* = Reg 5
  a2* = Reg 6
  a3* = Reg 7
  t0* = Reg 8
  t1* = Reg 9
  t2* = Reg 10
  t3* = Reg 11
  t4* = Reg 12
  t5* = Reg 13
  t6* = Reg 14
  t7* = Reg 15
  s0* = Reg 16
  s1* = Reg 17
  s2* = Reg 18
  s3* = Reg 19
  s4* = Reg 20
  s5* = Reg 21
  s6* = Reg 22
  s7* = Reg 23
  t8* = Reg 24
  t9* = Reg 25
  k0* = Reg 26
  k1* = Reg 27
  gp* = Reg 28
  sp* = Reg 29
  fp* = Reg 30
  ra* = Reg 31


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


