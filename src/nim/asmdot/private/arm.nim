proc adc*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((1280'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc add*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((256'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc and*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((0'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc eor*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((1024'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc orr*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((384'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc rsb*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((1536'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc rsc*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((1792'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sbc*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((768'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sub*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((512'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc bkpt*(buf: var pointer) =
  cast[ptr int32](buf)[] = 234882183'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc b*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (80'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc bic*(buf: var pointer, cond: Condition, i: bool, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((896'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc blx*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (218100864'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc bx*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (150992000'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc bxj*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (83883136'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc blxun*(buf: var pointer) =
  cast[ptr int32](buf)[] = 95'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc cdp*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (112'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc clz*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((150009472'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cmn*(buf: var pointer, cond: Condition, i: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((3712'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cmp*(buf: var pointer, cond: Condition, i: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((2688'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cpy*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((1408'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cps*(buf: var pointer, mode: Mode) =
  var mode = uint8 mode
  cast[ptr int32](buf)[] = (16527'u32 or (mode shl 24'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cpsie*(buf: var pointer) =
  cast[ptr int32](buf)[] = 4239'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc cpsid*(buf: var pointer) =
  cast[ptr int32](buf)[] = 12431'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc cpsie_mode*(buf: var pointer, mode: Mode) =
  var mode = uint8 mode
  cast[ptr int32](buf)[] = (20623'u32 or (mode shl 21'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc cpsid_mode*(buf: var pointer, mode: Mode) =
  var mode = uint8 mode
  cast[ptr int32](buf)[] = (28815'u32 or (mode shl 21'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldc*(buf: var pointer, cond: Condition, write: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((560'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldm1*(buf: var pointer, cond: Condition, write: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((528'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldm2*(buf: var pointer, cond: Condition, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = ((656'u32 or cond) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldm3*(buf: var pointer, cond: Condition, write: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((17040'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldr*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((544'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 64'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrb*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((672'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 64'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrbt*(buf: var pointer, cond: Condition, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((1824'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 11'u32)) or (rd shl 15'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrd*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((2883584'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrex*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((4193257856'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrh*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((3408384'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrsb*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((2884096'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrsh*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((3932672'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ldrt*(buf: var pointer, cond: Condition, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((1568'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 11'u32)) or (rd shl 15'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mcr*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((131184'u32 or cond) or (rd shl 13'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mcrr*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((560'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mla*(buf: var pointer, cond: Condition, s: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((150995968'u32 or cond) or (if s: 2048'u32 else: 0'u8)) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mov*(buf: var pointer, cond: Condition, i: bool, s: bool, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((1408'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mrc*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((131440'u32 or cond) or (rd shl 13'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mrrc*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((2608'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mrs*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((61568'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mul*(buf: var pointer, cond: Condition, s: bool, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((150994944'u32 or cond) or (if s: 2048'u32 else: 0'u8)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc mvn*(buf: var pointer, cond: Condition, i: bool, s: bool, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((1920'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (if s: 2048'u32 else: 0'u8)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc msr_imm*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (62656'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc msr_reg*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (62592'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc pkhbt*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((134218080'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc pkhtb*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((167772512'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc pld*(buf: var pointer, i: bool, rn: Reg) =
  var rn = uint8 rn
  cast[ptr int32](buf)[] = ((492975'u32 or (if i: 64'u32 else: 0'u8)) or (rn shl 11'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qadd*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((167772288'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149947488'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166724704'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qaddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217056352'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qdadd*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((167772800'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qdsub*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((167773824'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qsub*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((167773312'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qsub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250610784'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qsub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267388000'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc qsubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183501920'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc rev*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((217120096'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc rev16*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((233897312'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc revsh*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((233897824'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc rfe*(buf: var pointer, write: bool, rn: Reg) =
  var rn = uint8 rn
  cast[ptr int32](buf)[] = ((1311263'u32 or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149948512'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166725728'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc saddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217057376'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sel*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((233832800'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc setendbe*(buf: var pointer) =
  cast[ptr int32](buf)[] = 4227215'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc setendle*(buf: var pointer) =
  cast[ptr int32](buf)[] = 32911'u32
  buf = cast[pointer](cast[uint](buf) + 4)


proc shadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149949536'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc shadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166726752'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc shaddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217058400'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc shsub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250612832'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc shsub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267390048'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc shsubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183503968'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlabb*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((16777344'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlabt*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((83886208'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlatb*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((50331776'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlatt*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((117440640'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlad*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((67109088'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlal*(buf: var pointer, cond: Condition, s: bool) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = ((150996736'u32 or cond) or (if s: 2048'u32 else: 0'u8))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlalbb*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (16777856'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlalbt*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (83886720'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlaltb*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (50332288'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlaltt*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (117441152'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlald*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (67109600'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlawb*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((16778368'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlawt*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((50332800'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlsd*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((100663520'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smlsld*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (100664032'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc smmla*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((134220512'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smmls*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((184552160'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smmul*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((135203552'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smuad*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((68092128'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smulbb*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((16778880'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smulbt*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((83887744'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smultb*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((50333312'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smultt*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((117442176'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smull*(buf: var pointer, cond: Condition, s: bool) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = ((301991424'u32 or cond) or (if s: 4096'u32 else: 0'u8))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smulwb*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((83887232'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smulwt*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((117441664'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc smusd*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((101646560'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc srs*(buf: var pointer, write: bool, mode: Mode) =
  var mode = uint8 mode
  cast[ptr int32](buf)[] = ((2632863'u32 or (if write: 256'u32 else: 0'u8)) or (mode shl 26'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ssat*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((133728'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ssat16*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((13567328'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ssub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250611808'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ssub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267389024'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc ssubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183502944'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc stc*(buf: var pointer, cond: Condition, write: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((48'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc stm1*(buf: var pointer, cond: Condition, write: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((16'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc stm2*(buf: var pointer, cond: Condition, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = ((144'u32 or cond) or (rn shl 10'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc str*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((32'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 64'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strb*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((160'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 64'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strbt*(buf: var pointer, cond: Condition, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((800'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 11'u32)) or (rd shl 15'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strd*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((3932160'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strex*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((83362176'u32 or cond) or (rn shl 11'u32)) or (rd shl 15'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strh*(buf: var pointer, cond: Condition, write: bool, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((((3407872'u32 or cond) or (if write: 256'u32 else: 0'u8)) or (if i: 128'u32 else: 0'u8)) or (rn shl 10'u32)) or (rd shl 14'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc strt*(buf: var pointer, cond: Condition, i: bool, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((((544'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 11'u32)) or (rd shl 15'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc swi*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (240'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc swp*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((150995072'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc swpb*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((150995584'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxtab*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58721632'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxtab16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58720608'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxtah*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58723680'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxtb*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58783072'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxtb16*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58782048'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc sxth*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58785120'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc teq*(buf: var pointer, cond: Condition, i: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((3200'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc tst*(buf: var pointer, cond: Condition, i: bool, rn: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  cast[ptr int32](buf)[] = (((2176'u32 or cond) or (if i: 64'u32 else: 0'u8)) or (rn shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149949024'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166726240'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uaddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217057888'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149950048'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166727264'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhaddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217058912'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhsub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250613344'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhsub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267390560'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uhsubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183504480'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc umaal*(buf: var pointer, cond: Condition) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = (150995456'u32 or cond)
  buf = cast[pointer](cast[uint](buf) + 4)


proc umlal*(buf: var pointer, cond: Condition, s: bool) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = ((150996224'u32 or cond) or (if s: 2048'u32 else: 0'u8))
  buf = cast[pointer](cast[uint](buf) + 4)


proc umull*(buf: var pointer, cond: Condition, s: bool) =
  var cond = uint8 cond
  cast[ptr int32](buf)[] = ((150995200'u32 or cond) or (if s: 2048'u32 else: 0'u8))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqadd16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((149948000'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqadd8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((166725216'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqaddsubx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((217056864'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqsub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250611296'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqsub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267388512'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uqsubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183502432'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usad8*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((135201248'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usada8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((134218208'u32 or cond) or (rn shl 16'u32)) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usat*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((67424'u32 or cond) or (rd shl 11'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usat16*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((13567840'u32 or cond) or (rd shl 12'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usub16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((250612320'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usub8*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((267389536'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc usubaddx*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((183503456'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxtab*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58722144'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxtab16*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58721120'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxtah*(buf: var pointer, cond: Condition, rn: Reg, rd: Reg) =
  var cond = uint8 cond
  var rn = uint8 rn
  var rd = uint8 rd
  cast[ptr int32](buf)[] = (((58724192'u32 or cond) or (rn shl 12'u32)) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxtb*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58783584'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxtb16*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58782560'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


proc uxth*(buf: var pointer, cond: Condition, rd: Reg) =
  var cond = uint8 cond
  var rd = uint8 rd
  cast[ptr int32](buf)[] = ((58785632'u32 or cond) or (rd shl 16'u32))
  buf = cast[pointer](cast[uint](buf) + 4)


