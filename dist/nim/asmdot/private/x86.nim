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

proc inc*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc inc*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (64'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc dec*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc dec*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (72'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc push*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc push*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (80'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg16) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (102'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg32) = 
  var
    operand = uint8 operand

  if (operand > 7'u8):
    cast[ptr uint8](buf)[] = 65'u8
    buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pop*(buf: var pointer, operand: Reg64) = 
  var
    operand = uint8 operand

  cast[ptr uint8](buf)[] = (72'u8 + getPrefix(operand))
  buf = cast[pointer](cast[uint](buf) + 1)
  cast[ptr uint8](buf)[] = (88'u8 + operand)
  buf = cast[pointer](cast[uint](buf) + 1)


proc pushf*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 156'u8
  buf = cast[pointer](cast[uint](buf) + 1)


proc popf*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 157'u8
  buf = cast[pointer](cast[uint](buf) + 1)


proc ret*(buf: var pointer) = 
  cast[ptr uint8](buf)[] = 195'u8
  buf = cast[pointer](cast[uint](buf) + 1)


