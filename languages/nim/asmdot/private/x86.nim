type Reg8* = distinct uint8 ## An x86 8-bits register.

const
  al* = Reg8 0
  cl* = Reg8 1
  dl* = Reg8 2
  bl* = Reg8 3
  spl* = Reg8 4
  bpl* = Reg8 5
  sil* = Reg8 6
  dil* = Reg8 7
  r8b* = Reg8 8
  r9b* = Reg8 9
  r10b* = Reg8 10
  r11b* = Reg8 11
  r12b* = Reg8 12
  r13b* = Reg8 13
  r14b* = Reg8 14
  r15b* = Reg8 15


type Reg16* = distinct uint8 ## An x86 16-bits register.

const
  ax* = Reg16 0
  cx* = Reg16 1
  dx* = Reg16 2
  bx* = Reg16 3
  sp* = Reg16 4
  bp* = Reg16 5
  si* = Reg16 6
  di* = Reg16 7
  r8w* = Reg16 8
  r9w* = Reg16 9
  r10w* = Reg16 10
  r11w* = Reg16 11
  r12w* = Reg16 12
  r13w* = Reg16 13
  r14w* = Reg16 14
  r15w* = Reg16 15


type Reg32* = distinct uint8 ## An x86 32-bits register.

const
  eax* = Reg32 0
  ecx* = Reg32 1
  edx* = Reg32 2
  ebx* = Reg32 3
  esp* = Reg32 4
  ebp* = Reg32 5
  esi* = Reg32 6
  edi* = Reg32 7
  r8d* = Reg32 8
  r9d* = Reg32 9
  r10d* = Reg32 10
  r11d* = Reg32 11
  r12d* = Reg32 12
  r13d* = Reg32 13
  r14d* = Reg32 14
  r15d* = Reg32 15


type Reg64* = distinct uint8 ## An x86 64-bits register.

const
  rax* = Reg64 0
  rcx* = Reg64 1
  rdx* = Reg64 2
  rbx* = Reg64 3
  rsp* = Reg64 4
  rbp* = Reg64 5
  rsi* = Reg64 6
  rdi* = Reg64 7
  r8* = Reg64 8
  r9* = Reg64 9
  r10* = Reg64 10
  r11* = Reg64 11
  r12* = Reg64 12
  r13* = Reg64 13
  r14* = Reg64 14
  r15* = Reg64 15


type Reg128* = distinct uint8 ## An x86 128-bits register.

proc pushf*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 156'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc popf*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 157'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc ret*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 195'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc clc*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 248'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc stc*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 249'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc cli*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 250'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sti*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 251'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc cld*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 252'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc std*(buf: var ptr byte) = 
  cast[ptr uint8](buf)[] = 253'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jo*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 112'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jno*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 113'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jb*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 114'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnae*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 114'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jc*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 114'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnb*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 115'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jae*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 115'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnc*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 115'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jz*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 116'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc je*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 116'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnz*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 117'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jne*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 117'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jbe*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 118'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jna*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 118'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnbe*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 119'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc ja*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 119'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc js*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 120'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jns*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 121'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jp*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 122'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jpe*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 122'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnp*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 123'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jpo*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 123'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jl*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 124'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnge*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 124'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnl*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 125'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jge*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 125'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jle*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 126'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jng*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 126'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jnle*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 127'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc jg*(buf: var ptr byte, operand: int8) = 
  cast[ptr uint8](buf)[] = 127'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = operand
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc inc*(buf: var ptr byte, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc inc*(buf: var ptr byte, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc dec*(buf: var ptr byte, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc dec*(buf: var ptr byte, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc push*(buf: var ptr byte, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc push*(buf: var ptr byte, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc pop*(buf: var ptr byte, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc pop*(buf: var ptr byte, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc pop*(buf: var ptr byte, operand: Reg64) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (72'u8 + getPrefix(operand))
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc add*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Or*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc adc*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sbb*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc And*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sub*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Xor*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc cmp*(buf: var ptr byte, reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 128'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc add*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc add*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc add*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc add*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Or*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc Or*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Or*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc Or*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc adc*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc adc*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc adc*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc adc*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sbb*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc sbb*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sbb*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc sbb*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc And*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc And*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc And*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc And*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sub*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc sub*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc sub*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc sub*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Xor*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc Xor*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc Xor*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc Xor*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cmp*(buf: var ptr byte, reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc cmp*(buf: var ptr byte, reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc cmp*(buf: var ptr byte, reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int16](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 2)


proc cmp*(buf: var ptr byte, reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  cast[ptr uint8](buf)[] = 129'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int32](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 4)


proc add*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc add*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 0'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Or*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Or*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 1'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc adc*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc adc*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 2'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sbb*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sbb*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 3'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc And*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc And*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 4'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sub*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc sub*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 5'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Xor*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc Xor*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 6'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc cmp*(buf: var ptr byte, reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 102'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


proc cmp*(buf: var ptr byte, reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  cast[ptr uint8](buf)[] = 131'u8
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (reg + 7'u8)
  buf = cast[ptr byte](cast[uint](buf) + 1)
  cast[ptr int8](buf)[] = value
  buf = cast[ptr byte](cast[uint](buf) + 1)


