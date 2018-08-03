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

proc pushf*(buf: var seq[byte]) = 
  buf.add 156'u8


proc popf*(buf: var seq[byte]) = 
  buf.add 157'u8


proc ret*(buf: var seq[byte]) = 
  buf.add 195'u8


proc clc*(buf: var seq[byte]) = 
  buf.add 248'u8


proc stc*(buf: var seq[byte]) = 
  buf.add 249'u8


proc cli*(buf: var seq[byte]) = 
  buf.add 250'u8


proc sti*(buf: var seq[byte]) = 
  buf.add 251'u8


proc cld*(buf: var seq[byte]) = 
  buf.add 252'u8


proc std*(buf: var seq[byte]) = 
  buf.add 253'u8


proc jo*(buf: var seq[byte], operand: int8) = 
  buf.add 112'u8
  buf.add operand


proc jno*(buf: var seq[byte], operand: int8) = 
  buf.add 113'u8
  buf.add operand


proc jb*(buf: var seq[byte], operand: int8) = 
  buf.add 114'u8
  buf.add operand


proc jnae*(buf: var seq[byte], operand: int8) = 
  buf.add 114'u8
  buf.add operand


proc jc*(buf: var seq[byte], operand: int8) = 
  buf.add 114'u8
  buf.add operand


proc jnb*(buf: var seq[byte], operand: int8) = 
  buf.add 115'u8
  buf.add operand


proc jae*(buf: var seq[byte], operand: int8) = 
  buf.add 115'u8
  buf.add operand


proc jnc*(buf: var seq[byte], operand: int8) = 
  buf.add 115'u8
  buf.add operand


proc jz*(buf: var seq[byte], operand: int8) = 
  buf.add 116'u8
  buf.add operand


proc je*(buf: var seq[byte], operand: int8) = 
  buf.add 116'u8
  buf.add operand


proc jnz*(buf: var seq[byte], operand: int8) = 
  buf.add 117'u8
  buf.add operand


proc jne*(buf: var seq[byte], operand: int8) = 
  buf.add 117'u8
  buf.add operand


proc jbe*(buf: var seq[byte], operand: int8) = 
  buf.add 118'u8
  buf.add operand


proc jna*(buf: var seq[byte], operand: int8) = 
  buf.add 118'u8
  buf.add operand


proc jnbe*(buf: var seq[byte], operand: int8) = 
  buf.add 119'u8
  buf.add operand


proc ja*(buf: var seq[byte], operand: int8) = 
  buf.add 119'u8
  buf.add operand


proc js*(buf: var seq[byte], operand: int8) = 
  buf.add 120'u8
  buf.add operand


proc jns*(buf: var seq[byte], operand: int8) = 
  buf.add 121'u8
  buf.add operand


proc jp*(buf: var seq[byte], operand: int8) = 
  buf.add 122'u8
  buf.add operand


proc jpe*(buf: var seq[byte], operand: int8) = 
  buf.add 122'u8
  buf.add operand


proc jnp*(buf: var seq[byte], operand: int8) = 
  buf.add 123'u8
  buf.add operand


proc jpo*(buf: var seq[byte], operand: int8) = 
  buf.add 123'u8
  buf.add operand


proc jl*(buf: var seq[byte], operand: int8) = 
  buf.add 124'u8
  buf.add operand


proc jnge*(buf: var seq[byte], operand: int8) = 
  buf.add 124'u8
  buf.add operand


proc jnl*(buf: var seq[byte], operand: int8) = 
  buf.add 125'u8
  buf.add operand


proc jge*(buf: var seq[byte], operand: int8) = 
  buf.add 125'u8
  buf.add operand


proc jle*(buf: var seq[byte], operand: int8) = 
  buf.add 126'u8
  buf.add operand


proc jng*(buf: var seq[byte], operand: int8) = 
  buf.add 126'u8
  buf.add operand


proc jnle*(buf: var seq[byte], operand: int8) = 
  buf.add 127'u8
  buf.add operand


proc jg*(buf: var seq[byte], operand: int8) = 
  buf.add 127'u8
  buf.add operand


proc inc*(buf: var seq[byte], operand: Reg16) = 
  var
    operand = uint8 operand

  buf.add (102'u8 + getPrefix(operand))
  buf.add (64'u8 + operand)


proc inc*(buf: var seq[byte], operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    buf.add 65'u8
  buf.add (64'u8 + operand)


proc dec*(buf: var seq[byte], operand: Reg16) = 
  var
    operand = uint8 operand

  buf.add (102'u8 + getPrefix(operand))
  buf.add (72'u8 + operand)


proc dec*(buf: var seq[byte], operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    buf.add 65'u8
  buf.add (72'u8 + operand)


proc push*(buf: var seq[byte], operand: Reg16) = 
  var
    operand = uint8 operand

  buf.add (102'u8 + getPrefix(operand))
  buf.add (80'u8 + operand)


proc push*(buf: var seq[byte], operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    buf.add 65'u8
  buf.add (80'u8 + operand)


proc pop*(buf: var seq[byte], operand: Reg16) = 
  var
    operand = uint8 operand

  buf.add (102'u8 + getPrefix(operand))
  buf.add (88'u8 + operand)


proc pop*(buf: var seq[byte], operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    buf.add 65'u8
  buf.add (88'u8 + operand)


proc pop*(buf: var seq[byte], operand: Reg64) = 
  var
    operand = uint8 operand

  buf.add (72'u8 + getPrefix(operand))
  buf.add (88'u8 + operand)


proc add*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 0'u8)
  buf.add value


proc Or*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 1'u8)
  buf.add value


proc adc*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 2'u8)
  buf.add value


proc sbb*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 3'u8)
  buf.add value


proc And*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 4'u8)
  buf.add value


proc sub*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 5'u8)
  buf.add value


proc Xor*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 6'u8)
  buf.add value


proc cmp*(buf: var seq[byte], reg: Reg8, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 128'u8
  buf.add (reg + 7'u8)
  buf.add value


proc add*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 0'u8)
  buf.writeLE cast[int16](value)


proc add*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 0'u8)
  buf.writeLE cast[int32](value)


proc add*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 0'u8)
  buf.writeLE cast[int16](value)


proc add*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 0'u8)
  buf.writeLE cast[int32](value)


proc Or*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 1'u8)
  buf.writeLE cast[int16](value)


proc Or*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 1'u8)
  buf.writeLE cast[int32](value)


proc Or*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 1'u8)
  buf.writeLE cast[int16](value)


proc Or*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 1'u8)
  buf.writeLE cast[int32](value)


proc adc*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 2'u8)
  buf.writeLE cast[int16](value)


proc adc*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 2'u8)
  buf.writeLE cast[int32](value)


proc adc*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 2'u8)
  buf.writeLE cast[int16](value)


proc adc*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 2'u8)
  buf.writeLE cast[int32](value)


proc sbb*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 3'u8)
  buf.writeLE cast[int16](value)


proc sbb*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 3'u8)
  buf.writeLE cast[int32](value)


proc sbb*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 3'u8)
  buf.writeLE cast[int16](value)


proc sbb*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 3'u8)
  buf.writeLE cast[int32](value)


proc And*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 4'u8)
  buf.writeLE cast[int16](value)


proc And*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 4'u8)
  buf.writeLE cast[int32](value)


proc And*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 4'u8)
  buf.writeLE cast[int16](value)


proc And*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 4'u8)
  buf.writeLE cast[int32](value)


proc sub*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 5'u8)
  buf.writeLE cast[int16](value)


proc sub*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 5'u8)
  buf.writeLE cast[int32](value)


proc sub*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 5'u8)
  buf.writeLE cast[int16](value)


proc sub*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 5'u8)
  buf.writeLE cast[int32](value)


proc Xor*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 6'u8)
  buf.writeLE cast[int16](value)


proc Xor*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 6'u8)
  buf.writeLE cast[int32](value)


proc Xor*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 6'u8)
  buf.writeLE cast[int16](value)


proc Xor*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 6'u8)
  buf.writeLE cast[int32](value)


proc cmp*(buf: var seq[byte], reg: Reg16, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 7'u8)
  buf.writeLE cast[int16](value)


proc cmp*(buf: var seq[byte], reg: Reg16, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 102'u8
  buf.add 129'u8
  buf.add (reg + 7'u8)
  buf.writeLE cast[int32](value)


proc cmp*(buf: var seq[byte], reg: Reg32, value: int16) = 
  var
    reg = uint8 reg
    value = int16 value

  buf.add 129'u8
  buf.add (reg + 7'u8)
  buf.writeLE cast[int16](value)


proc cmp*(buf: var seq[byte], reg: Reg32, value: int32) = 
  var
    reg = uint8 reg
    value = int32 value

  buf.add 129'u8
  buf.add (reg + 7'u8)
  buf.writeLE cast[int32](value)


proc add*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 0'u8)
  buf.add value


proc add*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 0'u8)
  buf.add value


proc Or*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 1'u8)
  buf.add value


proc Or*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 1'u8)
  buf.add value


proc adc*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 2'u8)
  buf.add value


proc adc*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 2'u8)
  buf.add value


proc sbb*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 3'u8)
  buf.add value


proc sbb*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 3'u8)
  buf.add value


proc And*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 4'u8)
  buf.add value


proc And*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 4'u8)
  buf.add value


proc sub*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 5'u8)
  buf.add value


proc sub*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 5'u8)
  buf.add value


proc Xor*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 6'u8)
  buf.add value


proc Xor*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 6'u8)
  buf.add value


proc cmp*(buf: var seq[byte], reg: Reg16, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 102'u8
  buf.add 131'u8
  buf.add (reg + 7'u8)
  buf.add value


proc cmp*(buf: var seq[byte], reg: Reg32, value: int8) = 
  var
    reg = uint8 reg
    value = int8 value

  buf.add 131'u8
  buf.add (reg + 7'u8)
  buf.add value


proc assemble*(buf: var seq[byte], opcode: string, params: varargs[Any]): bool =
  return false
