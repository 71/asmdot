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


proc adc*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((10485760'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc add*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((8388608'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc And*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((0'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc eor*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((2097152'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc orr*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((25165824'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc rsb*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((6291456'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc rsc*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((14680064'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc sbc*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((12582912'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc sub*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((4194304'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc bkpt*(buf: var seq[byte], immed: uint16) = 
  buf.writeLE cast[uint32](((3776970864'u32 or ((immed and 65520'u16) shl 8'u32)) or ((immed and 15'u16) shl 0'u32)))


proc b*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((167772160'u32 or cond))


proc bic*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((29360128'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc blx*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((19922736'u32 or cond))


proc bx*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((19922704'u32 or cond))


proc bxj*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((19922720'u32 or cond))


proc blxun*(buf: var seq[byte]) = 
  buf.writeLE cast[uint32](4194304000'u32)


proc clz*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((24055568'u32 or cond) or (rd shl 12'u32)))


proc cmn*(buf: var seq[byte], cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  buf.writeLE cast[uint32](((24117248'u32 or cond) or (rn shl 16'u32)))


proc cmp*(buf: var seq[byte], cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  buf.writeLE cast[uint32](((22020096'u32 or cond) or (rn shl 16'u32)))


proc cpy*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((27262976'u32 or cond) or (rd shl 12'u32)))


proc cps*(buf: var seq[byte], mode: Mode) = 
  var
    mode = uint32 mode

  buf.writeLE cast[uint32]((4043440128'u32 or (mode shl 0'u32)))


proc cpsie*(buf: var seq[byte], iflags: InterruptFlags) = 
  var
    iflags = uint32 iflags

  buf.writeLE cast[uint32]((4043833344'u32 or (iflags shl 6'u32)))


proc cpsid*(buf: var seq[byte], iflags: InterruptFlags) = 
  var
    iflags = uint32 iflags

  buf.writeLE cast[uint32]((4044095488'u32 or (iflags shl 6'u32)))


proc cpsie_mode*(buf: var seq[byte], iflags: InterruptFlags, mode: Mode) = 
  var
    iflags = uint32 iflags
    mode = uint32 mode

  buf.writeLE cast[uint32](((4043964416'u32 or (iflags shl 6'u32)) or (mode shl 0'u32)))


proc cpsid_mode*(buf: var seq[byte], iflags: InterruptFlags, mode: Mode) = 
  var
    iflags = uint32 iflags
    mode = uint32 mode

  buf.writeLE cast[uint32](((4044226560'u32 or (iflags shl 6'u32)) or (mode shl 0'u32)))


proc ldc*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    cpnum = uint32 cpnum
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((202375168'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (cpnum shl 8'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldm*(buf: var seq[byte], cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, copy_spsr: bool) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode
    registers = uint32 registers
    write = uint32 write
    copy_spsr = uint32 copy_spsr

  assert ((copy_spsr == 1'u32) xor (write == (registers and 32768'u16)))
  buf.writeLE cast[uint32](((((((((135266304'u32 or cond) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)) or (addressing_mode shl 23'u32)) or registers) or (copy_spsr shl 21'u32)) or (write shl 10'u32)))


proc ldr*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((68157440'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrb*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((72351744'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrbt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  buf.writeLE cast[uint32](((((74448896'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32)))


proc ldrd*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((208'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrex*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((26218399'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc ldrh*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((1048752'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrsb*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((1048784'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrsh*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((1048816'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ldrt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  buf.writeLE cast[uint32](((((70254592'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32)))


proc cdp*(buf: var seq[byte], cond: Condition, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    cpnum = uint32 cpnum

  buf.writeLE cast[uint32](((234881024'u32 or cond) or (cpnum shl 8'u32)))


proc mcr*(buf: var seq[byte], cond: Condition, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    cpnum = uint32 cpnum

  buf.writeLE cast[uint32]((((234881040'u32 or cond) or (rd shl 12'u32)) or (cpnum shl 8'u32)))


proc mrc*(buf: var seq[byte], cond: Condition, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    cpnum = uint32 cpnum

  buf.writeLE cast[uint32]((((235929616'u32 or cond) or (rd shl 12'u32)) or (cpnum shl 8'u32)))


proc mcrr*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    cpnum = uint32 cpnum

  buf.writeLE cast[uint32](((((205520896'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (cpnum shl 8'u32)))


proc mla*(buf: var seq[byte], cond: Condition, update_cprs: bool, rn: Reg, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rn = uint32 rn
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((((2097296'u32 or cond) or (update_cprs shl 20'u8)) or (rn shl 12'u32)) or (rd shl 16'u32)) or (update_condition shl 20'u32)))


proc mov*(buf: var seq[byte], cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32](((((27262976'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc mrrc*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, cpnum: Coprocessor) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    cpnum = uint32 cpnum

  buf.writeLE cast[uint32](((((206569472'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (cpnum shl 8'u32)))


proc mrs*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((17760256'u32 or cond) or (rd shl 12'u32)))


proc mul*(buf: var seq[byte], cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32](((((144'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 16'u32)) or (update_condition shl 20'u32)))


proc mvn*(buf: var seq[byte], cond: Condition, update_cprs: bool, rd: Reg, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    rd = uint32 rd
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32](((((31457280'u32 or cond) or (update_cprs shl 20'u8)) or (rd shl 12'u32)) or (update_condition shl 20'u32)))


proc msr_imm*(buf: var seq[byte], cond: Condition, fieldmask: FieldMask) = 
  var
    cond = uint32 cond
    fieldmask = uint32 fieldmask

  buf.writeLE cast[uint32](((52490240'u32 or cond) or (fieldmask shl 16'u32)))


proc msr_reg*(buf: var seq[byte], cond: Condition, fieldmask: FieldMask) = 
  var
    cond = uint32 cond
    fieldmask = uint32 fieldmask

  buf.writeLE cast[uint32](((18935808'u32 or cond) or (fieldmask shl 16'u32)))


proc pkhbt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((109051920'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc pkhtb*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((109051984'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc pld*(buf: var seq[byte], rn: Reg, offset_mode: OffsetMode) = 
  var
    rn = uint32 rn
    offset_mode = uint32 offset_mode

  buf.writeLE cast[uint32](((4115722240'u32 or (rn shl 16'u32)) or (offset_mode shl 23'u32)))


proc qadd*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777296'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764304'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764432'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qaddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764336'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qdadd*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((20971600'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qdsub*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((23068752'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qsub*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((18874448'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qsub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764400'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qsub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764528'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc qsubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((102764368'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc rev*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((113184560'u32 or cond) or (rd shl 12'u32)))


proc rev16*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((113184688'u32 or cond) or (rd shl 12'u32)))


proc revsh*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((117378992'u32 or cond) or (rd shl 12'u32)))


proc rfe*(buf: var seq[byte], write: bool, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    write = uint32 write
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((4161800704'u32 or (write shl 21'u8)) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc sadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715728'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc sadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715856'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc saddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715760'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc sel*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((109055920'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc setendbe*(buf: var seq[byte]) = 
  buf.writeLE cast[uint32](4043375104'u32)


proc setendle*(buf: var seq[byte]) = 
  buf.writeLE cast[uint32](4043374592'u32)


proc shadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103812880'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc shadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103813008'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc shaddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103812912'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc shsub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103812976'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc shsub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103813104'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc shsubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((103812944'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc smlabb*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777344'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlabt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777376'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlatb*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777408'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlatt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777440'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlad*(buf: var seq[byte], cond: Condition, exchange: bool, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32](((((117440528'u32 or cond) or (exchange shl 5'u8)) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlal*(buf: var seq[byte], cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((14680208'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32)))


proc smlalbb*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((20971648'u32 or cond))


proc smlalbt*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((20971680'u32 or cond))


proc smlaltb*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((20971712'u32 or cond))


proc smlaltt*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((20971744'u32 or cond))


proc smlald*(buf: var seq[byte], cond: Condition, exchange: bool) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange

  buf.writeLE cast[uint32](((121634832'u32 or cond) or (exchange shl 5'u8)))


proc smlawb*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((18874496'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlawt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((18874560'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlsd*(buf: var seq[byte], cond: Condition, exchange: bool, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32](((((117440592'u32 or cond) or (exchange shl 5'u8)) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smlsld*(buf: var seq[byte], cond: Condition, exchange: bool) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange

  buf.writeLE cast[uint32](((121634896'u32 or cond) or (exchange shl 5'u8)))


proc smmla*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((122683408'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smmls*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((122683600'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc smmul*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((122744848'u32 or cond) or (rd shl 16'u32)))


proc smuad*(buf: var seq[byte], cond: Condition, exchange: bool, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rd = uint32 rd

  buf.writeLE cast[uint32]((((117501968'u32 or cond) or (exchange shl 5'u8)) or (rd shl 16'u32)))


proc smulbb*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((23068800'u32 or cond) or (rd shl 16'u32)))


proc smulbt*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((23068832'u32 or cond) or (rd shl 16'u32)))


proc smultb*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((23068864'u32 or cond) or (rd shl 16'u32)))


proc smultt*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((23068896'u32 or cond) or (rd shl 16'u32)))


proc smull*(buf: var seq[byte], cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((12583056'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32)))


proc smulwb*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((18874528'u32 or cond) or (rd shl 16'u32)))


proc smulwt*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((18874592'u32 or cond) or (rd shl 16'u32)))


proc smusd*(buf: var seq[byte], cond: Condition, exchange: bool, rd: Reg) = 
  var
    cond = uint32 cond
    exchange = uint32 exchange
    rd = uint32 rd

  buf.writeLE cast[uint32]((((117502032'u32 or cond) or (exchange shl 5'u8)) or (rd shl 16'u32)))


proc srs*(buf: var seq[byte], write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    write = uint32 write
    mode = uint32 mode
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((4165797120'u32 or (write shl 21'u8)) or (mode shl 0'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc ssat*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((105906192'u32 or cond) or (rd shl 12'u32)))


proc ssat16*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((111152944'u32 or cond) or (rd shl 12'u32)))


proc ssub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715824'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc ssub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715952'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc ssubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((101715792'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc stc*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    cpnum = uint32 cpnum
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((201326592'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (cpnum shl 8'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc stm*(buf: var seq[byte], cond: Condition, rn: Reg, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, user_mode: bool) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode
    registers = uint32 registers
    write = uint32 write
    user_mode = uint32 user_mode

  assert ((user_mode == 0'u32) or (write == 0'u32))
  buf.writeLE cast[uint32](((((((((134217728'u32 or cond) or (rn shl 16'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)) or (addressing_mode shl 23'u32)) or registers) or (user_mode shl 21'u32)) or (write shl 10'u32)))


proc str*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((67108864'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc strb*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((71303168'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc strbt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  buf.writeLE cast[uint32](((((73400320'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32)))


proc strd*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((240'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc strex*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((25169808'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc strh*(buf: var seq[byte], cond: Condition, write: bool, rn: Reg, rd: Reg, offset_mode: OffsetMode, addressing_mode: Addressing) = 
  var
    cond = uint32 cond
    write = uint32 write
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode
    addressing_mode = uint32 addressing_mode

  buf.writeLE cast[uint32](((((((176'u32 or cond) or (write shl 21'u8)) or (rn shl 16'u32)) or (rd shl 12'u32)) or (addressing_mode shl 23'u32)) or (offset_mode shl 11'u32)))


proc strt*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, offset_mode: OffsetMode) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    offset_mode = uint32 offset_mode

  buf.writeLE cast[uint32](((((69206016'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (offset_mode shl 23'u32)))


proc swi*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((251658240'u32 or cond))


proc swp*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((16777360'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc swpb*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((20971664'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc sxtab*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((111149168'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc sxtab16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((109052016'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc sxtah*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((112197744'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc sxtb*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((112132208'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc sxtb16*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((110035056'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc sxth*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((113180784'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc teq*(buf: var seq[byte], cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  buf.writeLE cast[uint32](((19922944'u32 or cond) or (rn shl 16'u32)))


proc tst*(buf: var seq[byte], cond: Condition, rn: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn

  buf.writeLE cast[uint32](((17825792'u32 or cond) or (rn shl 16'u32)))


proc uadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910032'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910160'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uaddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910064'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007184'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007312'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhaddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007216'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhsub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007280'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhsub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007408'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uhsubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((108007248'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc umaal*(buf: var seq[byte], cond: Condition) = 
  var
    cond = uint32 cond

  buf.writeLE cast[uint32]((4194448'u32 or cond))


proc umlal*(buf: var seq[byte], cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((10485904'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32)))


proc umull*(buf: var seq[byte], cond: Condition, update_cprs: bool, update_condition: bool) = 
  var
    cond = uint32 cond
    update_cprs = uint32 update_cprs
    update_condition = uint32 update_condition

  buf.writeLE cast[uint32]((((8388752'u32 or cond) or (update_cprs shl 20'u8)) or (update_condition shl 20'u32)))


proc uqadd16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958608'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uqadd8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958736'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uqaddsubx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958640'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uqsub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958704'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uqsub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958832'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uqsubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((106958672'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc usad8*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((125890576'u32 or cond) or (rd shl 16'u32)))


proc usada8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((125829136'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32)))


proc usat*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((115343376'u32 or cond) or (rd shl 12'u32)))


proc usat16*(buf: var seq[byte], cond: Condition, rd: Reg) = 
  var
    cond = uint32 cond
    rd = uint32 rd

  buf.writeLE cast[uint32](((115347248'u32 or cond) or (rd shl 12'u32)))


proc usub16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910128'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc usub8*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910256'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc usubaddx*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd

  buf.writeLE cast[uint32]((((105910096'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)))


proc uxtab*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((115343472'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc uxtab16*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((113246320'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc uxtah*(buf: var seq[byte], cond: Condition, rn: Reg, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rn = uint32 rn
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32](((((116392048'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc uxtb*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((116326512'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc uxtb16*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((114229360'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc uxth*(buf: var seq[byte], cond: Condition, rd: Reg, rotate: Rotation) = 
  var
    cond = uint32 cond
    rd = uint32 rd
    rotate = uint32 rotate

  buf.writeLE cast[uint32]((((117375088'u32 or cond) or (rd shl 12'u32)) or (rotate shl 10'u32)))


proc assemble*(buf: var seq[byte], opcode: string, params: varargs[Any]): bool =
  return false
