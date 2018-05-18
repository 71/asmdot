#![allow(unused_parens, unused_mut)]
use ::arm::*;
/// Emits an `adc` instruction.
pub unsafe fn adc(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((1280 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `add` instruction.
pub unsafe fn add(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((256 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `and` instruction.
pub unsafe fn and(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((0 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `eor` instruction.
pub unsafe fn eor(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((1024 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `orr` instruction.
pub unsafe fn orr(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((384 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `rsb` instruction.
pub unsafe fn rsb(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((1536 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `rsc` instruction.
pub unsafe fn rsc(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((1792 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sbc` instruction.
pub unsafe fn sbc(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((768 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sub` instruction.
pub unsafe fn sub(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((512 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `bkpt` instruction.
pub unsafe fn bkpt(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 234882183 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `b` instruction.
pub unsafe fn b(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (80 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `bic` instruction.
pub unsafe fn bic(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((896 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `blx` instruction.
pub unsafe fn blx(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (218100864 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `bx` instruction.
pub unsafe fn bx(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (150992000 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `bxj` instruction.
pub unsafe fn bxj(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (83883136 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `blxun` instruction.
pub unsafe fn blxun(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 95 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cdp` instruction.
pub unsafe fn cdp(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (112 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `clz` instruction.
pub unsafe fn clz(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((150009472 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cmn` instruction.
pub unsafe fn cmn(buf: &mut *mut (), cond: Condition, i: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((3712 | cond) | (i << 6)) | (rn << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cmp` instruction.
pub unsafe fn cmp(buf: &mut *mut (), cond: Condition, i: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((2688 | cond) | (i << 6)) | (rn << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cpy` instruction.
pub unsafe fn cpy(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((1408 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cps` instruction.
pub unsafe fn cps(buf: &mut *mut (), mode: Mode) {
    let mut mode = mode as u32;
    *(*buf as *mut u32) = (16527 | (mode << 24)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cpsie` instruction.
pub unsafe fn cpsie(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 4239 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cpsid` instruction.
pub unsafe fn cpsid(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 12431 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cpsie_mode` instruction.
pub unsafe fn cpsie_mode(buf: &mut *mut (), mode: Mode) {
    let mut mode = mode as u32;
    *(*buf as *mut u32) = (20623 | (mode << 21)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `cpsid_mode` instruction.
pub unsafe fn cpsid_mode(buf: &mut *mut (), mode: Mode) {
    let mut mode = mode as u32;
    *(*buf as *mut u32) = (28815 | (mode << 21)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldc` instruction.
pub unsafe fn ldc(buf: &mut *mut (), cond: Condition, write: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((560 | cond) | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldm1` instruction.
pub unsafe fn ldm1(buf: &mut *mut (), cond: Condition, write: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((528 | cond) | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldm2` instruction.
pub unsafe fn ldm2(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((656 | cond) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldm3` instruction.
pub unsafe fn ldm3(buf: &mut *mut (), cond: Condition, write: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((17040 | cond) | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldr` instruction.
pub unsafe fn ldr(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((544 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrb` instruction.
pub unsafe fn ldrb(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((672 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrbt` instruction.
pub unsafe fn ldrbt(buf: &mut *mut (), cond: Condition, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((1824 | cond) | (i << 6)) | (rn << 11)) | (rd << 15)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrd` instruction.
pub unsafe fn ldrd(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((2883584 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrex` instruction.
pub unsafe fn ldrex(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((4193257856 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrh` instruction.
pub unsafe fn ldrh(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((3408384 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrsb` instruction.
pub unsafe fn ldrsb(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((2884096 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrsh` instruction.
pub unsafe fn ldrsh(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((3932672 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ldrt` instruction.
pub unsafe fn ldrt(buf: &mut *mut (), cond: Condition, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((1568 | cond) | (i << 6)) | (rn << 11)) | (rd << 15)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mcr` instruction.
pub unsafe fn mcr(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((131184 | cond) | (rd << 13)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mcrr` instruction.
pub unsafe fn mcrr(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((560 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mla` instruction.
pub unsafe fn mla(buf: &mut *mut (), cond: Condition, s: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((150995968 | cond) | (s << 11)) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mov` instruction.
pub unsafe fn mov(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((1408 | cond) | (i << 6)) | (s << 11)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mrc` instruction.
pub unsafe fn mrc(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((131440 | cond) | (rd << 13)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mrrc` instruction.
pub unsafe fn mrrc(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((2608 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mrs` instruction.
pub unsafe fn mrs(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((61568 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mul` instruction.
pub unsafe fn mul(buf: &mut *mut (), cond: Condition, s: bool, rd: Register) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((150994944 | cond) | (s << 11)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `mvn` instruction.
pub unsafe fn mvn(buf: &mut *mut (), cond: Condition, i: bool, s: bool, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut s = s as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((1920 | cond) | (i << 6)) | (s << 11)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `msr_imm` instruction.
pub unsafe fn msr_imm(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (62656 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `msr_reg` instruction.
pub unsafe fn msr_reg(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (62592 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `pkhbt` instruction.
pub unsafe fn pkhbt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((134218080 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `pkhtb` instruction.
pub unsafe fn pkhtb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((167772512 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `pld` instruction.
pub unsafe fn pld(buf: &mut *mut (), i: bool, rn: Register) {
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((492975 | (i << 6)) | (rn << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qadd` instruction.
pub unsafe fn qadd(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((167772288 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qadd16` instruction.
pub unsafe fn qadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149947488 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qadd8` instruction.
pub unsafe fn qadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166724704 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qaddsubx` instruction.
pub unsafe fn qaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217056352 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qdadd` instruction.
pub unsafe fn qdadd(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((167772800 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qdsub` instruction.
pub unsafe fn qdsub(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((167773824 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qsub` instruction.
pub unsafe fn qsub(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((167773312 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qsub16` instruction.
pub unsafe fn qsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250610784 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qsub8` instruction.
pub unsafe fn qsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267388000 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `qsubaddx` instruction.
pub unsafe fn qsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183501920 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `rev` instruction.
pub unsafe fn rev(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((217120096 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `rev16` instruction.
pub unsafe fn rev16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((233897312 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `revsh` instruction.
pub unsafe fn revsh(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((233897824 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `rfe` instruction.
pub unsafe fn rfe(buf: &mut *mut (), write: bool, rn: Register) {
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((1311263 | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sadd16` instruction.
pub unsafe fn sadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149948512 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sadd8` instruction.
pub unsafe fn sadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166725728 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `saddsubx` instruction.
pub unsafe fn saddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217057376 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sel` instruction.
pub unsafe fn sel(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((233832800 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `setendbe` instruction.
pub unsafe fn setendbe(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 4227215 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `setendle` instruction.
pub unsafe fn setendle(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 32911 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shadd16` instruction.
pub unsafe fn shadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149949536 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shadd8` instruction.
pub unsafe fn shadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166726752 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shaddsubx` instruction.
pub unsafe fn shaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217058400 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shsub16` instruction.
pub unsafe fn shsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250612832 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shsub8` instruction.
pub unsafe fn shsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267390048 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `shsubaddx` instruction.
pub unsafe fn shsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183503968 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlabb` instruction.
pub unsafe fn smlabb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777344 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlabt` instruction.
pub unsafe fn smlabt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((83886208 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlatb` instruction.
pub unsafe fn smlatb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((50331776 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlatt` instruction.
pub unsafe fn smlatt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((117440640 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlad` instruction.
pub unsafe fn smlad(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((67109088 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlal` instruction.
pub unsafe fn smlal(buf: &mut *mut (), cond: Condition, s: bool) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    *(*buf as *mut u32) = ((150996736 | cond) | (s << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlalbb` instruction.
pub unsafe fn smlalbb(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (16777856 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlalbt` instruction.
pub unsafe fn smlalbt(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (83886720 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlaltb` instruction.
pub unsafe fn smlaltb(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (50332288 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlaltt` instruction.
pub unsafe fn smlaltt(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (117441152 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlald` instruction.
pub unsafe fn smlald(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (67109600 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlawb` instruction.
pub unsafe fn smlawb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16778368 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlawt` instruction.
pub unsafe fn smlawt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((50332800 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlsd` instruction.
pub unsafe fn smlsd(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((100663520 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smlsld` instruction.
pub unsafe fn smlsld(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (100664032 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smmla` instruction.
pub unsafe fn smmla(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((134220512 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smmls` instruction.
pub unsafe fn smmls(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((184552160 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smmul` instruction.
pub unsafe fn smmul(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((135203552 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smuad` instruction.
pub unsafe fn smuad(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((68092128 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smulbb` instruction.
pub unsafe fn smulbb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((16778880 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smulbt` instruction.
pub unsafe fn smulbt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((83887744 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smultb` instruction.
pub unsafe fn smultb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((50333312 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smultt` instruction.
pub unsafe fn smultt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((117442176 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smull` instruction.
pub unsafe fn smull(buf: &mut *mut (), cond: Condition, s: bool) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    *(*buf as *mut u32) = ((301991424 | cond) | (s << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smulwb` instruction.
pub unsafe fn smulwb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((83887232 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smulwt` instruction.
pub unsafe fn smulwt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((117441664 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `smusd` instruction.
pub unsafe fn smusd(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((101646560 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `srs` instruction.
pub unsafe fn srs(buf: &mut *mut (), write: bool, mode: Mode) {
    let mut write = write as u32;
    let mut mode = mode as u32;
    *(*buf as *mut u32) = ((2632863 | (write << 8)) | (mode << 26)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ssat` instruction.
pub unsafe fn ssat(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((133728 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ssat16` instruction.
pub unsafe fn ssat16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((13567328 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ssub16` instruction.
pub unsafe fn ssub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250611808 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ssub8` instruction.
pub unsafe fn ssub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267389024 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `ssubaddx` instruction.
pub unsafe fn ssubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183502944 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `stc` instruction.
pub unsafe fn stc(buf: &mut *mut (), cond: Condition, write: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((48 | cond) | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `stm1` instruction.
pub unsafe fn stm1(buf: &mut *mut (), cond: Condition, write: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((16 | cond) | (write << 8)) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `stm2` instruction.
pub unsafe fn stm2(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((144 | cond) | (rn << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `str` instruction.
pub unsafe fn str(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((32 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strb` instruction.
pub unsafe fn strb(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((160 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strbt` instruction.
pub unsafe fn strbt(buf: &mut *mut (), cond: Condition, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((800 | cond) | (i << 6)) | (rn << 11)) | (rd << 15)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strd` instruction.
pub unsafe fn strd(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((3932160 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strex` instruction.
pub unsafe fn strex(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((83362176 | cond) | (rn << 11)) | (rd << 15)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strh` instruction.
pub unsafe fn strh(buf: &mut *mut (), cond: Condition, write: bool, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((((3407872 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `strt` instruction.
pub unsafe fn strt(buf: &mut *mut (), cond: Condition, i: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((544 | cond) | (i << 6)) | (rn << 11)) | (rd << 15)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `swi` instruction.
pub unsafe fn swi(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (240 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `swp` instruction.
pub unsafe fn swp(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((150995072 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `swpb` instruction.
pub unsafe fn swpb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((150995584 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxtab` instruction.
pub unsafe fn sxtab(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58721632 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxtab16` instruction.
pub unsafe fn sxtab16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58720608 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxtah` instruction.
pub unsafe fn sxtah(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58723680 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxtb` instruction.
pub unsafe fn sxtb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58783072 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxtb16` instruction.
pub unsafe fn sxtb16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58782048 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `sxth` instruction.
pub unsafe fn sxth(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58785120 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `teq` instruction.
pub unsafe fn teq(buf: &mut *mut (), cond: Condition, i: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((3200 | cond) | (i << 6)) | (rn << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a `tst` instruction.
pub unsafe fn tst(buf: &mut *mut (), cond: Condition, i: bool, rn: Register) {
    let mut cond = cond as u32;
    let mut i = i as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = (((2176 | cond) | (i << 6)) | (rn << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uadd16` instruction.
pub unsafe fn uadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149949024 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uadd8` instruction.
pub unsafe fn uadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166726240 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uaddsubx` instruction.
pub unsafe fn uaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217057888 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhadd16` instruction.
pub unsafe fn uhadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149950048 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhadd8` instruction.
pub unsafe fn uhadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166727264 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhaddsubx` instruction.
pub unsafe fn uhaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217058912 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhsub16` instruction.
pub unsafe fn uhsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250613344 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhsub8` instruction.
pub unsafe fn uhsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267390560 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uhsubaddx` instruction.
pub unsafe fn uhsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183504480 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `umaal` instruction.
pub unsafe fn umaal(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (150995456 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `umlal` instruction.
pub unsafe fn umlal(buf: &mut *mut (), cond: Condition, s: bool) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    *(*buf as *mut u32) = ((150996224 | cond) | (s << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `umull` instruction.
pub unsafe fn umull(buf: &mut *mut (), cond: Condition, s: bool) {
    let mut cond = cond as u32;
    let mut s = s as u32;
    *(*buf as *mut u32) = ((150995200 | cond) | (s << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqadd16` instruction.
pub unsafe fn uqadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((149948000 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqadd8` instruction.
pub unsafe fn uqadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((166725216 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqaddsubx` instruction.
pub unsafe fn uqaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((217056864 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqsub16` instruction.
pub unsafe fn uqsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250611296 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqsub8` instruction.
pub unsafe fn uqsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267388512 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uqsubaddx` instruction.
pub unsafe fn uqsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183502432 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usad8` instruction.
pub unsafe fn usad8(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((135201248 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usada8` instruction.
pub unsafe fn usada8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((134218208 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usat` instruction.
pub unsafe fn usat(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((67424 | cond) | (rd << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usat16` instruction.
pub unsafe fn usat16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((13567840 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usub16` instruction.
pub unsafe fn usub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((250612320 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usub8` instruction.
pub unsafe fn usub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((267389536 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `usubaddx` instruction.
pub unsafe fn usubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((183503456 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxtab` instruction.
pub unsafe fn uxtab(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58722144 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxtab16` instruction.
pub unsafe fn uxtab16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58721120 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxtah` instruction.
pub unsafe fn uxtah(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((58724192 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxtb` instruction.
pub unsafe fn uxtb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58783584 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxtb16` instruction.
pub unsafe fn uxtb16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58782560 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an `uxth` instruction.
pub unsafe fn uxth(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((58785632 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

