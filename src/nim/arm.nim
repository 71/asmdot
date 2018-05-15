include private/arm.nim

proc adc*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((1280 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc add*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((256 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc and*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((0 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc eor*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((1024 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc orr*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((384 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc rsb*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((1536 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc rsc*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((1792 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc sbc*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((768 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc sub*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((512 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc bkpt*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 234882183
  return 4

proc b*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (80 | cond)
  return 4

proc bic*(cond: condition, i: bool, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((896 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16))
  return 4

proc blx*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (218100864 | cond)
  return 4

proc bx*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (150992000 | cond)
  return 4

proc bxj*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (83883136 | cond)
  return 4

proc blxun*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 95
  return 4

proc cdp*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (112 | cond)
  return 4

proc clz*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((150009472 | cond) | (rd << 16))
  return 4

proc cmn*(cond: condition, i: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((3712 | cond) | (i ? 64 : 0)) | (rn << 12))
  return 4

proc cmp*(cond: condition, i: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((2688 | cond) | (i ? 64 : 0)) | (rn << 12))
  return 4

proc cpy*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((1408 | cond) | (rd << 16))
  return 4

proc cps*(mode: Mode, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (16527 | (mode << 24))
  return 4

proc cpsie*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 4239
  return 4

proc cpsid*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 12431
  return 4

proc cpsie_mode*(mode: Mode, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (20623 | (mode << 21))
  return 4

proc cpsid_mode*(mode: Mode, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (28815 | (mode << 21))
  return 4

proc ldc*(cond: condition, write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((560 | cond) | (write ? 256 : 0)) | (rn << 10))
  return 4

proc ldm1*(cond: condition, write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((528 | cond) | (write ? 256 : 0)) | (rn << 10))
  return 4

proc ldm2*(cond: condition, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((656 | cond) | (rn << 10))
  return 4

proc ldm3*(cond: condition, write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((17040 | cond) | (write ? 256 : 0)) | (rn << 10))
  return 4

proc ldr*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((544 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrb*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((672 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrbt*(cond: condition, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((1824 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  return 4

proc ldrd*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((2883584 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrex*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((4193257856 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc ldrh*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((3408384 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrsb*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((2884096 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrsh*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((3932672 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc ldrt*(cond: condition, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((1568 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  return 4

proc mcr*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((131184 | cond) | (rd << 13))
  return 4

proc mcrr*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((560 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc mla*(cond: condition, s: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((150995968 | cond) | (s ? 2048 : 0)) | (rn << 16)) | (rd << 12))
  return 4

proc mov*(cond: condition, i: bool, s: bool, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((1408 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16))
  return 4

proc mrc*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((131440 | cond) | (rd << 13))
  return 4

proc mrrc*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((2608 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc mrs*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((61568 | cond) | (rd << 16))
  return 4

proc mul*(cond: condition, s: bool, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((150994944 | cond) | (s ? 2048 : 0)) | (rd << 12))
  return 4

proc mvn*(cond: condition, i: bool, s: bool, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((1920 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16))
  return 4

proc msr_imm*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (62656 | cond)
  return 4

proc msr_reg*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (62592 | cond)
  return 4

proc pkhbt*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((134218080 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc pkhtb*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((167772512 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc pld*(i: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((492975 | (i ? 64 : 0)) | (rn << 11))
  return 4

proc qadd*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((167772288 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149947488 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166724704 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qaddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217056352 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qdadd*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((167772800 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qdsub*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((167773824 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qsub*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((167773312 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qsub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250610784 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qsub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267388000 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc qsubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183501920 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc rev*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((217120096 | cond) | (rd << 16))
  return 4

proc rev16*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((233897312 | cond) | (rd << 16))
  return 4

proc revsh*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((233897824 | cond) | (rd << 16))
  return 4

proc rfe*(write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((1311263 | (write ? 256 : 0)) | (rn << 10))
  return 4

proc sadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149948512 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166725728 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc saddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217057376 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sel*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((233832800 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc setendbe*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 4227215
  return 4

proc setendle*(buf: ptr byte): int =
  cast[ptr int32](buf)[0] = 32911
  return 4

proc shadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149949536 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc shadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166726752 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc shaddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217058400 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc shsub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250612832 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc shsub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267390048 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc shsubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183503968 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc smlabb*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((16777344 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlabt*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((83886208 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlatb*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((50331776 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlatt*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((117440640 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlad*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((67109088 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlal*(cond: condition, s: bool, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((150996736 | cond) | (s ? 2048 : 0))
  return 4

proc smlalbb*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (16777856 | cond)
  return 4

proc smlalbt*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (83886720 | cond)
  return 4

proc smlaltb*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (50332288 | cond)
  return 4

proc smlaltt*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (117441152 | cond)
  return 4

proc smlald*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (67109600 | cond)
  return 4

proc smlawb*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((16778368 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlawt*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((50332800 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlsd*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((100663520 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smlsld*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (100664032 | cond)
  return 4

proc smmla*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((134220512 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smmls*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((184552160 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc smmul*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((135203552 | cond) | (rd << 12))
  return 4

proc smuad*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((68092128 | cond) | (rd << 12))
  return 4

proc smulbb*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((16778880 | cond) | (rd << 12))
  return 4

proc smulbt*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((83887744 | cond) | (rd << 12))
  return 4

proc smultb*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((50333312 | cond) | (rd << 12))
  return 4

proc smultt*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((117442176 | cond) | (rd << 12))
  return 4

proc smull*(cond: condition, s: bool, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((301991424 | cond) | (s ? 4096 : 0))
  return 4

proc smulwb*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((83887232 | cond) | (rd << 12))
  return 4

proc smulwt*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((117441664 | cond) | (rd << 12))
  return 4

proc smusd*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((101646560 | cond) | (rd << 12))
  return 4

proc srs*(write: bool, mode: Mode, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((2632863 | (write ? 256 : 0)) | (mode << 26))
  return 4

proc ssat*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((133728 | cond) | (rd << 12))
  return 4

proc ssat16*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((13567328 | cond) | (rd << 12))
  return 4

proc ssub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250611808 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc ssub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267389024 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc ssubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183502944 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc stc*(cond: condition, write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((48 | cond) | (write ? 256 : 0)) | (rn << 10))
  return 4

proc stm1*(cond: condition, write: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((16 | cond) | (write ? 256 : 0)) | (rn << 10))
  return 4

proc stm2*(cond: condition, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((144 | cond) | (rn << 10))
  return 4

proc str*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((32 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc strb*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((160 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc strbt*(cond: condition, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((800 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  return 4

proc strd*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((3932160 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc strex*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((83362176 | cond) | (rn << 11)) | (rd << 15))
  return 4

proc strh*(cond: condition, write: bool, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((((3407872 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14))
  return 4

proc strt*(cond: condition, i: bool, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((((544 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15))
  return 4

proc swi*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (240 | cond)
  return 4

proc swp*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((150995072 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc swpb*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((150995584 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sxtab*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58721632 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sxtab16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58720608 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sxtah*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58723680 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc sxtb*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58783072 | cond) | (rd << 16))
  return 4

proc sxtb16*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58782048 | cond) | (rd << 16))
  return 4

proc sxth*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58785120 | cond) | (rd << 16))
  return 4

proc teq*(cond: condition, i: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((3200 | cond) | (i ? 64 : 0)) | (rn << 12))
  return 4

proc tst*(cond: condition, i: bool, rn: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((2176 | cond) | (i ? 64 : 0)) | (rn << 12))
  return 4

proc uadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149949024 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166726240 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uaddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217057888 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149950048 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166727264 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhaddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217058912 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhsub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250613344 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhsub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267390560 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uhsubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183504480 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc umaal*(cond: condition, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (150995456 | cond)
  return 4

proc umlal*(cond: condition, s: bool, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((150996224 | cond) | (s ? 2048 : 0))
  return 4

proc umull*(cond: condition, s: bool, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((150995200 | cond) | (s ? 2048 : 0))
  return 4

proc uqadd16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((149948000 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uqadd8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((166725216 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uqaddsubx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((217056864 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uqsub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250611296 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uqsub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267388512 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uqsubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183502432 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc usad8*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((135201248 | cond) | (rd << 12))
  return 4

proc usada8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((134218208 | cond) | (rn << 16)) | (rd << 12))
  return 4

proc usat*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((67424 | cond) | (rd << 11))
  return 4

proc usat16*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((13567840 | cond) | (rd << 12))
  return 4

proc usub16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((250612320 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc usub8*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((267389536 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc usubaddx*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((183503456 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uxtab*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58722144 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uxtab16*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58721120 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uxtah*(cond: condition, rn: reg, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = (((58724192 | cond) | (rn << 12)) | (rd << 16))
  return 4

proc uxtb*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58783584 | cond) | (rd << 16))
  return 4

proc uxtb16*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58782560 | cond) | (rd << 16))
  return 4

proc uxth*(cond: condition, rd: reg, buf: ptr byte): int =
  cast[ptr int32](buf)[0] = ((58785632 | cond) | (rd << 16))
  return 4

