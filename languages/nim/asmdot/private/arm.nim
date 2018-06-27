type Reg* = distinct uint8 ## An ARM register.

const
  r0* = Reg 0
  r1* = Reg 1
  r2* = Reg 2
  r3* = Reg 3
  r4* = Reg 4
  r5* = Reg 5
  r6* = Reg 6
  r7* = Reg 7
  r8* = Reg 8
  r9* = Reg 9
  r10* = Reg 10
  r11* = Reg 11
  r12* = Reg 12
  r13* = Reg 13
  r14* = Reg 14
  r15* = Reg 15
  a1* = Reg 0
  a2* = Reg 1
  a3* = Reg 2
  a4* = Reg 3
  v1* = Reg 4
  v2* = Reg 5
  v3* = Reg 6
  v4* = Reg 7
  v5* = Reg 8
  v6* = Reg 9
  v7* = Reg 10
  v8* = Reg 11
  ip* = Reg 12
  sp* = Reg 13
  lr* = Reg 14
  pc* = Reg 15
  wr* = Reg 7
  sb* = Reg 9
  sl* = Reg 10
  fp* = Reg 11


type RegList* {.pure.} = enum ## A list of ARM registers, where each register corresponds to a single bit.
  R0 = 0 ## Register #1.
  R1 = 1 ## Register #2.
  R2 = 2 ## Register #3.
  R3 = 3 ## Register #4.
  R4 = 4 ## Register #5.
  R5 = 5 ## Register #6.
  R6 = 6 ## Register #7.
  R7 = 7 ## Register #8.
  R8 = 8 ## Register #9.
  R9 = 9 ## Register #10.
  R10 = 10 ## Register #11.
  R11 = 11 ## Register #12.
  R12 = 12 ## Register #13.
  R13 = 13 ## Register #14.
  R14 = 14 ## Register #15.
  R15 = 15 ## Register #16.


template A1*(typ: type RegList): RegList =
  ## Register A1.
  0

template A2*(typ: type RegList): RegList =
  ## Register A2.
  1

template A3*(typ: type RegList): RegList =
  ## Register A3.
  2

template A4*(typ: type RegList): RegList =
  ## Register A4.
  3

template V1*(typ: type RegList): RegList =
  ## Register V1.
  4

template V2*(typ: type RegList): RegList =
  ## Register V2.
  5

template V3*(typ: type RegList): RegList =
  ## Register V3.
  6

template V4*(typ: type RegList): RegList =
  ## Register V4.
  7

template V5*(typ: type RegList): RegList =
  ## Register V5.
  8

template V6*(typ: type RegList): RegList =
  ## Register V6.
  9

template V7*(typ: type RegList): RegList =
  ## Register V7.
  10

template V8*(typ: type RegList): RegList =
  ## Register V8.
  11

template IP*(typ: type RegList): RegList =
  ## Register IP.
  12

template SP*(typ: type RegList): RegList =
  ## Register SP.
  13

template LR*(typ: type RegList): RegList =
  ## Register LR.
  14

template PC*(typ: type RegList): RegList =
  ## Register PC.
  15

template WR*(typ: type RegList): RegList =
  ## Register WR.
  7

template SB*(typ: type RegList): RegList =
  ## Register SB.
  9

template SL*(typ: type RegList): RegList =
  ## Register SL.
  10

template FP*(typ: type RegList): RegList =
  ## Register FP.
  11

proc `+`*(a, b: RegList): RegList =
  RegList(byte(a) + byte(b))
proc `and`*(a, b: RegList): RegList =
  RegList(byte(a) and byte(b))
proc `or`*(a, b: RegList): RegList =
  RegList(byte(a) or byte(b))

type Coprocessor* = distinct uint8 ## An ARM coprocessor.

const
  cp0* = Coprocessor 0
  cp1* = Coprocessor 1
  cp2* = Coprocessor 2
  cp3* = Coprocessor 3
  cp4* = Coprocessor 4
  cp5* = Coprocessor 5
  cp6* = Coprocessor 6
  cp7* = Coprocessor 7
  cp8* = Coprocessor 8
  cp9* = Coprocessor 9
  cp10* = Coprocessor 10
  cp11* = Coprocessor 11
  cp12* = Coprocessor 12
  cp13* = Coprocessor 13
  cp14* = Coprocessor 14
  cp15* = Coprocessor 15


type Condition* {.pure.} = enum ## Condition for an ARM instruction to be executed.
  EQ = 0 ## Equal.
  NE = 1 ## Not equal.
  HS = 2 ## Unsigned higher or same.
  LO = 3 ## Unsigned lower.
  MI = 4 ## Minus / negative.
  PL = 5 ## Plus / positive or zero.
  VS = 6 ## Overflow.
  VC = 7 ## No overflow.
  HI = 8 ## Unsigned higher.
  LS = 9 ## Unsigned lower or same.
  GE = 10 ## Signed greater than or equal.
  LT = 11 ## Signed less than.
  GT = 12 ## Signed greater than.
  LE = 13 ## Signed less than or equal.
  AL = 14 ## Always (unconditional).
  UN = 15 ## Unpredictable (ARMv4 or lower).


template CS*(typ: type Condition): Condition =
  ## Carry set.
  2

template CC*(typ: type Condition): Condition =
  ## Carry clear.
  3

type Mode* {.pure.} = enum ## Processor mode.
  USR = 16 ## User mode.
  FIQ = 17 ## FIQ (high-speed data transfer) mode.
  IRQ = 18 ## IRQ (general-purpose interrupt handling) mode.
  SVC = 19 ## Supervisor mode.
  ABT = 23 ## Abort mode.
  UND = 27 ## Undefined mode.
  SYS = 31 ## System (privileged) mode.


type Shift* {.pure.} = enum ## Kind of a shift.
  LSL = 0 ## Logical shift left.
  LSR = 1 ## Logical shift right.
  ASR = 2 ## Arithmetic shift right.
  ROR = 3 ## Rotate right.


template RRX*(typ: type Shift): Shift =
  ## Shifted right by one bit.
  3

type Rotation* {.pure.} = enum ## Kind of a right rotation.
  NOP = 0 ## Do not rotate.
  ROR8 = 1 ## Rotate 8 bits to the right.
  ROR16 = 2 ## Rotate 16 bits to the right.
  ROR24 = 3 ## Rotate 24 bits to the right.


type FieldMask* {.pure.} = enum ## Field mask bits.
  C = 1 ## Control field mask bit.
  X = 2 ## Extension field mask bit.
  S = 4 ## Status field mask bit.
  F = 8 ## Flags field mask bit.


proc `+`*(a, b: FieldMask): FieldMask =
  FieldMask(byte(a) + byte(b))
proc `and`*(a, b: FieldMask): FieldMask =
  FieldMask(byte(a) and byte(b))
proc `or`*(a, b: FieldMask): FieldMask =
  FieldMask(byte(a) or byte(b))

type InterruptFlags* {.pure.} = enum ## Interrupt flags.
  F = 1 ## FIQ interrupt bit.
  I = 2 ## IRQ interrupt bit.
  A = 4 ## Imprecise data abort bit.


proc `+`*(a, b: InterruptFlags): InterruptFlags =
  InterruptFlags(byte(a) + byte(b))
proc `and`*(a, b: InterruptFlags): InterruptFlags =
  InterruptFlags(byte(a) and byte(b))
proc `or`*(a, b: InterruptFlags): InterruptFlags =
  InterruptFlags(byte(a) or byte(b))

type Addressing* {.pure.} = enum ## Addressing type.
  PostIndexed = 0 ## Post-indexed addressing.
  PreIndexed = 1 ## Pre-indexed addressing (or offset addressing if `write` is false).


template Offset*(typ: type Addressing): Addressing =
  ## Offset addressing (or pre-indexed addressing if `write` is true).
  1

type OffsetMode* {.pure.} = enum ## Offset adding or subtracting mode.
  Subtract = 0 ## Subtract offset from the base.
  Add = 1 ## Add offset to the base.


proc adc*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((10485760'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc add*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((8388608'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc And*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((0'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc eor*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((2097152'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc orr*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((25165824'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc rsb*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((6291456'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc rsc*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((14680064'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sbc*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((12582912'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sub*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((4194304'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bkpt*(buf: var ptr byte, immed: uint16) = 
  cast[ptr uint32](buf)[] = ((3776970864'u32 or ((immed and 65520'u16) shl 8'u32)) or ((immed and 15'u16) shl 0'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc b*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (167772160'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bic*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((29360128'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc blx*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (19922736'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bx*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (19922704'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc bxj*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (19922720'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc blxun*(buf: var ptr byte) = 
  cast[ptr uint32](buf)[] = 4194304000'u32
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc clz*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((24055568'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cmn*(buf: var ptr byte, cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  cast[ptr uint32](buf)[] = ((24117248'u32 or cond) or (rn shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cmp*(buf: var ptr byte, cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  cast[ptr uint32](buf)[] = ((22020096'u32 or cond) or (rn shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cpy*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((27262976'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cps*(buf: var ptr byte, mode: Mode) = 
  var
    mode = uint32 mode

  cast[ptr uint32](buf)[] = (4043440128'u32 or (mode shl 0'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cpsie*(buf: var ptr byte, iflags: InterruptFlags) = 
  var
    iflags = uint32 iflags

  cast[ptr uint32](buf)[] = (4043833344'u32 or (iflags shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cpsid*(buf: var ptr byte, iflags: InterruptFlags) = 
  var
    iflags = uint32 iflags

  cast[ptr uint32](buf)[] = (4044095488'u32 or (iflags shl 6'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cpsie_mode*(buf: var ptr byte, iflags: InterruptFlags, mode: Mode) = 
  var
    iflags = uint32 iflags
    mode = uint32 mode

  cast[ptr uint32](buf)[] = ((4043964416'u32 or (iflags shl 6'u32)) or (mode shl 0'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cpsid_mode*(buf: var ptr byte, iflags: InterruptFlags, mode: Mode) = 
  var
    iflags = uint32 iflags
    mode = uint32 mode

  cast[ptr uint32](buf)[] = ((4044226560'u32 or (iflags shl 6'u32)) or (mode shl 0'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldc*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    cpnum = uint32 cpnum
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((202375168'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (cpnum shl 8'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldm*(buf: var ptr byte, cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, copy_spsr: bool) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode
    registers = uint32 registers
    write = uint32 write
    copy_spsr = uint32 copy_spsr

  assert ((copy_spsr == 1'u32) xor (write == (registers and 32768'u16)))
  cast[ptr uint32](buf)[] = ((((((((135266304'u32 or cond) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)) or (addressing_mode shl 23'u32)) or registers) or (copy_spsr shl 21'u32)) or (write shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldr*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((68157440'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrb*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((72351744'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrbt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  cast[ptr uint32](buf)[] = ((((74448896'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrd*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((208'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrex*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((26218399'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrh*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((1048752'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrsb*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((1048784'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrsh*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((1048816'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ldrt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  cast[ptr uint32](buf)[] = ((((70254592'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cdp*(buf: var ptr byte, cond: Condition, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    cpnum = uint32 cpnum

  cast[ptr uint32](buf)[] = ((234881024'u32 or cond) or (cpnum shl 8'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mcr*(buf: var ptr byte, cond: Condition, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    cpnum = uint32 cpnum

  cast[ptr uint32](buf)[] = (((234881040'u32 or cond) or (rd shl 12'u32)) or (cpnum shl 8'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mrc*(buf: var ptr byte, cond: Condition, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    cpnum = uint32 cpnum

  cast[ptr uint32](buf)[] = (((235929616'u32 or cond) or (rd shl 12'u32)) or (cpnum shl 8'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mcrr*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    cpnum = uint32 cpnum

  cast[ptr uint32](buf)[] = ((((205520896'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (cpnum shl 8'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mla*(buf: var ptr byte, cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((((2097296'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 12'u32)) or (rd shl 16'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mov*(buf: var ptr byte, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = ((((27262976'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mrrc*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    cpnum = uint32 cpnum

  cast[ptr uint32](buf)[] = ((((206569472'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (cpnum shl 8'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mrs*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((17760256'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mul*(buf: var ptr byte, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = ((((144'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 16'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc mvn*(buf: var ptr byte, cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = ((((31457280'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 12'u32)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc msr_imm*(buf: var ptr byte, cond: Condition, fieldmask: FieldMask) = 
  var
    cond = uint32 cond
    fieldmask = uint32 fieldmask

  cast[ptr uint32](buf)[] = ((52490240'u32 or cond) or (fieldmask shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc msr_reg*(buf: var ptr byte, cond: Condition, fieldmask: FieldMask) = 
  var
    cond = uint32 cond
    fieldmask = uint32 fieldmask

  cast[ptr uint32](buf)[] = ((18935808'u32 or cond) or (fieldmask shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc pkhbt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((109051920'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc pkhtb*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((109051984'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc pld*(buf: var ptr byte, rn: Reg, offset_mode: OffsetMode) = 
  var
    rn = uint32 rn
    offset_mode = uint32 offset_mode

  cast[ptr uint32](buf)[] = ((4115722240'u32 or (rn shl 16'u32)) or (offset_mode shl 23'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qadd*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777296'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764304'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764432'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qaddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764336'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qdadd*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((20971600'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qdsub*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((23068752'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qsub*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((18874448'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qsub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764400'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qsub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764528'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc qsubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((102764368'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc rev*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((113184560'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc rev16*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((113184688'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc revsh*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((117378992'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc rfe*(buf: var ptr byte, write: bool, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    write = uint32 write
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((4161800704'u32 or (write shl 21'u8)) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715728'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715856'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc saddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715760'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sel*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((109055920'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc setendbe*(buf: var ptr byte) = 
  cast[ptr uint32](buf)[] = 4043375104'u32
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc setendle*(buf: var ptr byte) = 
  cast[ptr uint32](buf)[] = 4043374592'u32
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103812880'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103813008'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shaddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103812912'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shsub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103812976'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shsub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103813104'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc shsubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((103812944'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlabb*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777344'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlabt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777376'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlatb*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777408'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlatt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777440'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlad*(buf: var ptr byte, cond: Condition, exchange: bool, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((((117440528'u32 or cond) or (exchange shl 5'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlal*(buf: var ptr byte, cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((14680208'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlalbb*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (20971648'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlalbt*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (20971680'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlaltb*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (20971712'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlaltt*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (20971744'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlald*(buf: var ptr byte, cond: Condition, exchange: bool) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange

  cast[ptr uint32](buf)[] = ((121634832'u32 or cond) or (exchange shl 5'u8))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlawb*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((18874496'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlawt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((18874560'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlsd*(buf: var ptr byte, cond: Condition, exchange: bool, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((((117440592'u32 or cond) or (exchange shl 5'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smlsld*(buf: var ptr byte, cond: Condition, exchange: bool) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange

  cast[ptr uint32](buf)[] = ((121634896'u32 or cond) or (exchange shl 5'u8))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smmla*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((122683408'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smmls*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((122683600'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smmul*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((122744848'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smuad*(buf: var ptr byte, cond: Condition, exchange: bool, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((117501968'u32 or cond) or (exchange shl 5'u8)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smulbb*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((23068800'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smulbt*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((23068832'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smultb*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((23068864'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smultt*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((23068896'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smull*(buf: var ptr byte, cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((12583056'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smulwb*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((18874528'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smulwt*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((18874592'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc smusd*(buf: var ptr byte, cond: Condition, exchange: bool, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((117502032'u32 or cond) or (exchange shl 5'u8)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc srs*(buf: var ptr byte, write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    write = uint32 write
    mode = uint32 mode
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((4165797120'u32 or (write shl 21'u8)) or (mode shl 0'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ssat*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((105906192'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ssat16*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((111152944'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ssub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715824'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ssub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715952'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc ssubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((101715792'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc stc*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    cpnum = uint32 cpnum
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((201326592'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (cpnum shl 8'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc stm*(buf: var ptr byte, cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, user_mode: bool) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode
    registers = uint32 registers
    write = uint32 write
    user_mode = uint32 user_mode

  assert ((user_mode == 0) or (write == 0))
  cast[ptr uint32](buf)[] = ((((((((134217728'u32 or cond) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)) or (addressing_mode shl 23'u32)) or registers) or (user_mode shl 21'u32)) or (write shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc str*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((67108864'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strb*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((71303168'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strbt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  cast[ptr uint32](buf)[] = ((((73400320'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strd*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((240'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strex*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((25169808'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strh*(buf: var ptr byte, cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  cast[ptr uint32](buf)[] = ((((((176'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc strt*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  cast[ptr uint32](buf)[] = ((((69206016'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc swi*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (251658240'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc swp*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((16777360'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc swpb*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((20971664'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxtab*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((111149168'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxtab16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((109052016'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxtah*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((112197744'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxtb*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((112132208'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxtb16*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((110035056'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sxth*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((113180784'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc teq*(buf: var ptr byte, cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  cast[ptr uint32](buf)[] = ((19922944'u32 or cond) or (rn shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc tst*(buf: var ptr byte, cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  cast[ptr uint32](buf)[] = ((17825792'u32 or cond) or (rn shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910032'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910160'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uaddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910064'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007184'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007312'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhaddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007216'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhsub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007280'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhsub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007408'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uhsubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((108007248'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc umaal*(buf: var ptr byte, cond: Condition) = 
  var
    cond = uint32 cond

  cast[ptr uint32](buf)[] = (4194448'u32 or cond)
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc umlal*(buf: var ptr byte, cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((10485904'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc umull*(buf: var ptr byte, cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  cast[ptr uint32](buf)[] = (((8388752'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqadd16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958608'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqadd8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958736'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqaddsubx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958640'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqsub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958704'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqsub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958832'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uqsubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((106958672'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usad8*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((125890576'u32 or cond) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usada8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((125829136'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usat*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((115343376'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usat16*(buf: var ptr byte, cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  cast[ptr uint32](buf)[] = ((115347248'u32 or cond) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usub16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910128'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usub8*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910256'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc usubaddx*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  cast[ptr uint32](buf)[] = (((105910096'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxtab*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((115343472'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxtab16*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((113246320'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxtah*(buf: var ptr byte, cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = ((((116392048'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxtb*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((116326512'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxtb16*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((114229360'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc uxth*(buf: var ptr byte, cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  cast[ptr uint32](buf)[] = (((117375088'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32))
  buf = cast[ptr byte](cast[uint](buf) + 4)


