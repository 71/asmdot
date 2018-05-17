include private/arm.nim

proc adc*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((1280 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc add*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((256 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc and*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((0 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc eor*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((1024 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc orr*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((384 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc rsb*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((1536 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc rsc*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((1792 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc sbc*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((768 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc sub*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((512 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc bkpt*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 234882183
  buf += 4


proc b*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (80 | cond)
  buf += 4


proc bic*(buf: var ptr byte, cond: condition, i: bool, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((896 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  buf += 4


proc blx*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (218100864 | cond)
  buf += 4


proc bx*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (150992000 | cond)
  buf += 4


proc bxj*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (83883136 | cond)
  buf += 4


proc blxun*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 95
  buf += 4


proc cdp*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (112 | cond)
  buf += 4


proc clz*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((150009472 | cond) | (rd << 16))
  buf += 4


proc cmn*(buf: var ptr byte, cond: condition, i: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((3712 | cond) | (i ? 64 : 0)) | (rn << 12))
  buf += 4


proc cmp*(buf: var ptr byte, cond: condition, i: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((2688 | cond) | (i ? 64 : 0)) | (rn << 12))
  buf += 4


proc cpy*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((1408 | cond) | (rd << 16))
  buf += 4


proc cps*(buf: var ptr byte, mode: Mode) =
  cast[ptr int32](buf)[] = (16527 | (mode << 24))
  buf += 4


proc cpsie*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 4239
  buf += 4


proc cpsid*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 12431
  buf += 4


proc cpsie_mode*(buf: var ptr byte, mode: Mode) =
  cast[ptr int32](buf)[] = (20623 | (mode << 21))
  buf += 4


proc cpsid_mode*(buf: var ptr byte, mode: Mode) =
  cast[ptr int32](buf)[] = (28815 | (mode << 21))
  buf += 4


proc ldc*(buf: var ptr byte, cond: condition, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((560 | cond) | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc ldm1*(buf: var ptr byte, cond: condition, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((528 | cond) | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc ldm2*(buf: var ptr byte, cond: condition, rn: reg) =
  cast[ptr int32](buf)[] = ((656 | cond) | (rn << 10))
  buf += 4


proc ldm3*(buf: var ptr byte, cond: condition, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((17040 | cond) | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc ldr*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((544 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrb*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((672 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrbt*(buf: var ptr byte, cond: condition, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = ((((1824 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  buf += 4


proc ldrd*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((2883584 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrex*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((4193257856 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc ldrh*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((3408384 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrsb*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((2884096 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrsh*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((3932672 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc ldrt*(buf: var ptr byte, cond: condition, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = ((((1568 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  buf += 4


proc mcr*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((131184 | cond) | (rd << 13))
  buf += 4


proc mcrr*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((560 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc mla*(buf: var ptr byte, cond: condition, s: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = ((((150995968 | cond) | (s ? 2048 : 0)) | (rn << 16)) | (rd << 12))
  buf += 4


proc mov*(buf: var ptr byte, cond: condition, i: bool, s: bool, rd: reg) =
  cast[ptr int32](buf)[] = ((((1408 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16))
  buf += 4


proc mrc*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((131440 | cond) | (rd << 13))
  buf += 4


proc mrrc*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((2608 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc mrs*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((61568 | cond) | (rd << 16))
  buf += 4


proc mul*(buf: var ptr byte, cond: condition, s: bool, rd: reg) =
  cast[ptr int32](buf)[] = (((150994944 | cond) | (s ? 2048 : 0)) | (rd << 12))
  buf += 4


proc mvn*(buf: var ptr byte, cond: condition, i: bool, s: bool, rd: reg) =
  cast[ptr int32](buf)[] = ((((1920 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16))
  buf += 4


proc msr_imm*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (62656 | cond)
  buf += 4


proc msr_reg*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (62592 | cond)
  buf += 4


proc pkhbt*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((134218080 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc pkhtb*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((167772512 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc pld*(buf: var ptr byte, i: bool, rn: reg) =
  cast[ptr int32](buf)[] = ((492975 | (i ? 64 : 0)) | (rn << 11))
  buf += 4


proc qadd*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((167772288 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149947488 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166724704 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qaddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217056352 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qdadd*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((167772800 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qdsub*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((167773824 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qsub*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((167773312 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qsub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250610784 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qsub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267388000 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc qsubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183501920 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc rev*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((217120096 | cond) | (rd << 16))
  buf += 4


proc rev16*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((233897312 | cond) | (rd << 16))
  buf += 4


proc revsh*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((233897824 | cond) | (rd << 16))
  buf += 4


proc rfe*(buf: var ptr byte, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = ((1311263 | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc sadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149948512 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166725728 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc saddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217057376 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sel*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((233832800 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc setendbe*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 4227215
  buf += 4


proc setendle*(buf: var ptr byte) =
  cast[ptr int32](buf)[] = 32911
  buf += 4


proc shadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149949536 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc shadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166726752 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc shaddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217058400 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc shsub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250612832 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc shsub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267390048 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc shsubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183503968 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc smlabb*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((16777344 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlabt*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((83886208 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlatb*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((50331776 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlatt*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((117440640 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlad*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((67109088 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlal*(buf: var ptr byte, cond: condition, s: bool) =
  cast[ptr int32](buf)[] = ((150996736 | cond) | (s ? 2048 : 0))
  buf += 4


proc smlalbb*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (16777856 | cond)
  buf += 4


proc smlalbt*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (83886720 | cond)
  buf += 4


proc smlaltb*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (50332288 | cond)
  buf += 4


proc smlaltt*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (117441152 | cond)
  buf += 4


proc smlald*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (67109600 | cond)
  buf += 4


proc smlawb*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((16778368 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlawt*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((50332800 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlsd*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((100663520 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smlsld*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (100664032 | cond)
  buf += 4


proc smmla*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((134220512 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smmls*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((184552160 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc smmul*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((135203552 | cond) | (rd << 12))
  buf += 4


proc smuad*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((68092128 | cond) | (rd << 12))
  buf += 4


proc smulbb*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((16778880 | cond) | (rd << 12))
  buf += 4


proc smulbt*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((83887744 | cond) | (rd << 12))
  buf += 4


proc smultb*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((50333312 | cond) | (rd << 12))
  buf += 4


proc smultt*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((117442176 | cond) | (rd << 12))
  buf += 4


proc smull*(buf: var ptr byte, cond: condition, s: bool) =
  cast[ptr int32](buf)[] = ((301991424 | cond) | (s ? 4096 : 0))
  buf += 4


proc smulwb*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((83887232 | cond) | (rd << 12))
  buf += 4


proc smulwt*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((117441664 | cond) | (rd << 12))
  buf += 4


proc smusd*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((101646560 | cond) | (rd << 12))
  buf += 4


proc srs*(buf: var ptr byte, write: bool, mode: Mode) =
  cast[ptr int32](buf)[] = ((2632863 | (write ? 256 : 0)) | (mode << 26))
  buf += 4


proc ssat*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((133728 | cond) | (rd << 12))
  buf += 4


proc ssat16*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((13567328 | cond) | (rd << 12))
  buf += 4


proc ssub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250611808 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc ssub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267389024 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc ssubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183502944 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc stc*(buf: var ptr byte, cond: condition, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((48 | cond) | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc stm1*(buf: var ptr byte, cond: condition, write: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((16 | cond) | (write ? 256 : 0)) | (rn << 10))
  buf += 4


proc stm2*(buf: var ptr byte, cond: condition, rn: reg) =
  cast[ptr int32](buf)[] = ((144 | cond) | (rn << 10))
  buf += 4


proc str*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((32 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc strb*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((160 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc strbt*(buf: var ptr byte, cond: condition, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = ((((800 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  buf += 4


proc strd*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((3932160 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc strex*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((83362176 | cond) | (rn << 11)) | (rd << 15))
  buf += 4


proc strh*(buf: var ptr byte, cond: condition, write: bool, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((((3407872 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  buf += 4


proc strt*(buf: var ptr byte, cond: condition, i: bool, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = ((((544 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  buf += 4


proc swi*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (240 | cond)
  buf += 4


proc swp*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((150995072 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc swpb*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((150995584 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sxtab*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58721632 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sxtab16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58720608 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sxtah*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58723680 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc sxtb*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58783072 | cond) | (rd << 16))
  buf += 4


proc sxtb16*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58782048 | cond) | (rd << 16))
  buf += 4


proc sxth*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58785120 | cond) | (rd << 16))
  buf += 4


proc teq*(buf: var ptr byte, cond: condition, i: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((3200 | cond) | (i ? 64 : 0)) | (rn << 12))
  buf += 4


proc tst*(buf: var ptr byte, cond: condition, i: bool, rn: reg) =
  cast[ptr int32](buf)[] = (((2176 | cond) | (i ? 64 : 0)) | (rn << 12))
  buf += 4


proc uadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149949024 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166726240 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uaddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217057888 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149950048 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166727264 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhaddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217058912 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhsub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250613344 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhsub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267390560 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uhsubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183504480 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc umaal*(buf: var ptr byte, cond: condition) =
  cast[ptr int32](buf)[] = (150995456 | cond)
  buf += 4


proc umlal*(buf: var ptr byte, cond: condition, s: bool) =
  cast[ptr int32](buf)[] = ((150996224 | cond) | (s ? 2048 : 0))
  buf += 4


proc umull*(buf: var ptr byte, cond: condition, s: bool) =
  cast[ptr int32](buf)[] = ((150995200 | cond) | (s ? 2048 : 0))
  buf += 4


proc uqadd16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((149948000 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uqadd8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((166725216 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uqaddsubx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((217056864 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uqsub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250611296 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uqsub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267388512 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uqsubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183502432 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc usad8*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((135201248 | cond) | (rd << 12))
  buf += 4


proc usada8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((134218208 | cond) | (rn << 16)) | (rd << 12))
  buf += 4


proc usat*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((67424 | cond) | (rd << 11))
  buf += 4


proc usat16*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((13567840 | cond) | (rd << 12))
  buf += 4


proc usub16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((250612320 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc usub8*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((267389536 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc usubaddx*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((183503456 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uxtab*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58722144 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uxtab16*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58721120 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uxtah*(buf: var ptr byte, cond: condition, rn: reg, rd: reg) =
  cast[ptr int32](buf)[] = (((58724192 | cond) | (rn << 12)) | (rd << 16))
  buf += 4


proc uxtb*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58783584 | cond) | (rd << 16))
  buf += 4


proc uxtb16*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58782560 | cond) | (rd << 16))
  buf += 4


proc uxth*(buf: var ptr byte, cond: condition, rd: reg) =
  cast[ptr int32](buf)[] = ((58785632 | cond) | (rd << 16))
  buf += 4


