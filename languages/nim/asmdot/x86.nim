import typeinfo, private/helpers, macros

# Built-ins

template getPrefix(r: untyped): byte =
  if byte(r) > byte(7):
    r = r - type(r)(8)
    1
  else:
    0


# Import generated code + add operators to registers.

include private/x86

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
