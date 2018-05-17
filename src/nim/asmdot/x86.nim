import macros

type
  Reg8*   = distinct byte
  Reg16*  = distinct byte
  Reg32*  = distinct byte
  Reg64*  = distinct byte
  Reg128* = distinct byte

template borrowProc(name: untyped): untyped =
  proc name*(a, b: Reg8): Reg8 {.borrow.}
  proc name*(a, b: Reg16): Reg16 {.borrow.}
  proc name*(a, b: Reg32): Reg32 {.borrow.}
  proc name*(a, b: Reg64): Reg64 {.borrow.}
  proc name*(a, b: Reg128): Reg128 {.borrow.}

borrowProc `+`
borrowProc `-`
borrowProc `*`
borrowProc `and`
borrowProc `or`
borrowProc `xor`

template getPrefix(r: untyped): byte =
  if byte(r) > byte(7):
    r = r - type(r)(8)
    1
  else:
    0

include private/x86

macro mkRegisters(ty: typedesc, names: varargs[untyped]): untyped =
  result = newNimNode(nnkStmtList)

  for i, name in names.pairs:
    result.add quote do:
      const `name`* = `ty`(`i`)

mkRegisters Reg8,  al, cl, dl, bl, spl, bpl, sil, dil,     r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b
mkRegisters Reg16, ax, cx, dx, bx, sp,  bp,  si,  di,      r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w
mkRegisters Reg32, eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d
mkRegisters Reg64, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8,  r9,  r10,  r11,  r12,  r13,  r14,  r15
