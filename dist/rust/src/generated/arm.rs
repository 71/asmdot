#![allow(unused_parens, unused_mut)]
use ::arm::*;

/// An ARM register.
pub struct Register(pub u8);

impl Register {
    pub const R0: Self = 0;
    pub const R1: Self = 1;
    pub const R2: Self = 2;
    pub const R3: Self = 3;
    pub const R4: Self = 4;
    pub const R5: Self = 5;
    pub const R6: Self = 6;
    pub const R7: Self = 7;
    pub const R8: Self = 8;
    pub const R9: Self = 9;
    pub const R10: Self = 10;
    pub const R11: Self = 11;
    pub const R12: Self = 12;
    pub const R13: Self = 13;
    pub const R14: Self = 14;
    pub const R15: Self = 15;
    pub const A1: Self = 0;
    pub const A2: Self = 1;
    pub const A3: Self = 2;
    pub const A4: Self = 3;
    pub const V1: Self = 4;
    pub const V2: Self = 5;
    pub const V3: Self = 6;
    pub const V4: Self = 7;
    pub const V5: Self = 8;
    pub const V6: Self = 9;
    pub const V7: Self = 10;
    pub const V8: Self = 11;
    pub const IP: Self = 12;
    pub const SP: Self = 13;
    pub const LR: Self = 14;
    pub const PC: Self = 15;
    pub const WR: Self = 7;
    pub const SB: Self = 9;
    pub const SL: Self = 10;
    pub const FP: Self = 11;
}

/// An ARM coprocessor.
pub struct Coprocessor(pub u8);

impl Coprocessor {
    pub const CP0: Self = 0;
    pub const CP1: Self = 1;
    pub const CP2: Self = 2;
    pub const CP3: Self = 3;
    pub const CP4: Self = 4;
    pub const CP5: Self = 5;
    pub const CP6: Self = 6;
    pub const CP7: Self = 7;
    pub const CP8: Self = 8;
    pub const CP9: Self = 9;
    pub const CP10: Self = 10;
    pub const CP11: Self = 11;
    pub const CP12: Self = 12;
    pub const CP13: Self = 13;
    pub const CP14: Self = 14;
    pub const CP15: Self = 15;
}

/// Condition for an ARM instruction to be executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    /// Equal.
    EQ = 0,
    /// Not equal.
    NE = 1,
    /// Unsigned higher or same.
    HS = 2,
    /// Unsigned lower.
    LO = 3,
    /// Minus / negative.
    MI = 4,
    /// Plus / positive or zero.
    PL = 5,
    /// Overflow.
    VS = 6,
    /// No overflow.
    VC = 7,
    /// Unsigned higher.
    HI = 8,
    /// Unsigned lower or same.
    LS = 9,
    /// Signed greater than or equal.
    GE = 10,
    /// Signed less than.
    LT = 11,
    /// Signed greater than.
    GT = 12,
    /// Signed less than or equal.
    LE = 13,
    /// Always (unconditional).
    AL = 14,
    /// Unpredictable (ARMv4 or lower).
    UN = 15,
}

impl Condition {
    /// Carry set.
    pub const CS: Self = 2;
    /// Carry clear.
    pub const CC: Self = 3;
}

/// Processor mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// User mode.
    USR = 16,
    /// FIQ (high-speed data transfer) mode.
    FIQ = 17,
    /// IRQ (general-purpose interrupt handling) mode.
    IRQ = 18,
    /// Supervisor mode.
    SVC = 19,
    /// Abort mode.
    ABT = 23,
    /// Undefined mode.
    UND = 27,
    /// System (privileged) mode.
    SYS = 31,
}

/// Kind of a shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shift {
    /// Logical shift left.
    LSL = 0,
    /// Logical shift right.
    LSR = 1,
    /// Arithmetic shift right.
    ASR = 2,
    /// Rotate right.
    ROR = 3,
}

impl Shift {
    /// Shifted right by one bit.
    pub const RRX: Self = 3;
}

/// Kind of a right rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rotation {
    /// Do not rotate.
    NOP = 0,
    /// Rotate 8 bits to the right.
    ROR8 = 1,
    /// Rotate 16 bits to the right.
    ROR16 = 2,
    /// Rotate 24 bits to the right.
    ROR24 = 3,
}

bitflags! {
    /// Field mask bits.
    pub struct FieldMask: u8 {
        /// Control field mask bit.
        const C = 1;
        /// Extension field mask bit.
        const X = 2;
        /// Status field mask bit.
        const S = 4;
        /// Flags field mask bit.
        const F = 8;
    }
}

bitflags! {
    /// Interrupt flags.
    pub struct InterruptFlags: u8 {
        /// FIQ interrupt bit.
        const F = 1;
        /// IRQ interrupt bit.
        const I = 2;
        /// Imprecise data abort bit.
        const A = 4;
    }
}

/// Addressing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Addressing {
    /// Post-indexed addressing.
    PostIndexed = 0,
    /// Pre-indexed addressing (or offset addressing if `write` is false).
    PreIndexed = 1,
}

impl Addressing {
    /// Offset addressing (or pre-indexed addressing if `write` is true).
    pub const Offset: Self = 1;
}

/// Offset adding or subtracting mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OffsetMode {
    /// Subtract offset from the base.
    Subtract = 0,
    /// Add offset to the base.
    Add = 1,
}

/// Emits an 'adc' instruction.
pub unsafe fn adc(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'add' instruction.
pub unsafe fn add(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'and' instruction.
pub unsafe fn and(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'eor' instruction.
pub unsafe fn eor(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'orr' instruction.
pub unsafe fn orr(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'rsb' instruction.
pub unsafe fn rsb(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'rsc' instruction.
pub unsafe fn rsc(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sbc' instruction.
pub unsafe fn sbc(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sub' instruction.
pub unsafe fn sub(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'bkpt' instruction.
pub unsafe fn bkpt(buf: &mut *mut (), immed: u16) {
    let u16(mut immed) = immed;
    *(*buf as *mut u32) = ((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'b' instruction.
pub unsafe fn b(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (167772160 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'bic' instruction.
pub unsafe fn bic(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'blx' instruction.
pub unsafe fn blx(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (19922736 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'bx' instruction.
pub unsafe fn bx(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (19922704 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'bxj' instruction.
pub unsafe fn bxj(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (19922720 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'blxun' instruction.
pub unsafe fn blxun(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 4194304000 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'clz' instruction.
pub unsafe fn clz(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((24055568 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cmn' instruction.
pub unsafe fn cmn(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((24117248 | cond) | (rn << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cmp' instruction.
pub unsafe fn cmp(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((22020096 | cond) | (rn << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cpy' instruction.
pub unsafe fn cpy(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((27262976 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cps' instruction.
pub unsafe fn cps(buf: &mut *mut (), mode: Mode) {
    let mut mode = mode as u32;
    *(*buf as *mut u32) = (4043440128 | (mode << 0)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cpsie' instruction.
pub unsafe fn cpsie(buf: &mut *mut (), iflags: InterruptFlags) {
    let mut iflags = ::std::mem::transmute::<_, u8>(iflags) as u32;
    *(*buf as *mut u32) = (4043833344 | (iflags << 6)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cpsid' instruction.
pub unsafe fn cpsid(buf: &mut *mut (), iflags: InterruptFlags) {
    let mut iflags = ::std::mem::transmute::<_, u8>(iflags) as u32;
    *(*buf as *mut u32) = (4044095488 | (iflags << 6)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cpsie_mode' instruction.
pub unsafe fn cpsie_mode(buf: &mut *mut (), iflags: InterruptFlags, mode: Mode) {
    let mut iflags = ::std::mem::transmute::<_, u8>(iflags) as u32;
    let mut mode = mode as u32;
    *(*buf as *mut u32) = ((4043964416 | (iflags << 6)) | (mode << 0)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cpsid_mode' instruction.
pub unsafe fn cpsid_mode(buf: &mut *mut (), iflags: InterruptFlags, mode: Mode) {
    let mut iflags = ::std::mem::transmute::<_, u8>(iflags) as u32;
    let mut mode = mode as u32;
    *(*buf as *mut u32) = ((4044226560 | (iflags << 6)) | (mode << 0)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldc' instruction.
pub unsafe fn ldc(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldm' instruction.
pub unsafe fn ldm(buf: &mut *mut (), cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, copy_spsr: bool) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    let mut registers = ::std::mem::transmute::<_, u8>(registers) as u32;
    let mut write = write as u32;
    let mut copy_spsr = copy_spsr as u32;
    assert!((copy_spsr ^ (write == (registers & 32768))));
    *(*buf as *mut u32) = ((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldr' instruction.
pub unsafe fn ldr(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrb' instruction.
pub unsafe fn ldrb(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrbt' instruction.
pub unsafe fn ldrbt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    *(*buf as *mut u32) = ((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrd' instruction.
pub unsafe fn ldrd(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrex' instruction.
pub unsafe fn ldrex(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((26218399 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrh' instruction.
pub unsafe fn ldrh(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrsb' instruction.
pub unsafe fn ldrsb(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrsh' instruction.
pub unsafe fn ldrsh(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ldrt' instruction.
pub unsafe fn ldrt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    *(*buf as *mut u32) = ((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'cdp' instruction.
pub unsafe fn cdp(buf: &mut *mut (), cond: Condition, cpnum: Coprocessor) {
    let mut cond = cond as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    *(*buf as *mut u32) = ((234881024 | cond) | (cpnum << 8)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mcr' instruction.
pub unsafe fn mcr(buf: &mut *mut (), cond: Condition, rd: Register, cpnum: Coprocessor) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    *(*buf as *mut u32) = (((234881040 | cond) | (rd << 12)) | (cpnum << 8)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mrc' instruction.
pub unsafe fn mrc(buf: &mut *mut (), cond: Condition, rd: Register, cpnum: Coprocessor) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    *(*buf as *mut u32) = (((235929616 | cond) | (rd << 12)) | (cpnum << 8)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mcrr' instruction.
pub unsafe fn mcrr(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    *(*buf as *mut u32) = ((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mla' instruction.
pub unsafe fn mla(buf: &mut *mut (), cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mov' instruction.
pub unsafe fn mov(buf: &mut *mut (), cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = ((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mrrc' instruction.
pub unsafe fn mrrc(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    *(*buf as *mut u32) = ((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mrs' instruction.
pub unsafe fn mrs(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((17760256 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mul' instruction.
pub unsafe fn mul(buf: &mut *mut (), cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = ((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'mvn' instruction.
pub unsafe fn mvn(buf: &mut *mut (), cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = ((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'msr_imm' instruction.
pub unsafe fn msr#_imm(buf: &mut *mut (), cond: Condition, fieldmask: FieldMask) {
    let mut cond = cond as u32;
    let mut fieldmask = ::std::mem::transmute::<_, u8>(fieldmask) as u32;
    *(*buf as *mut u32) = ((52490240 | cond) | (fieldmask << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'msr_reg' instruction.
pub unsafe fn msr#_reg(buf: &mut *mut (), cond: Condition, fieldmask: FieldMask) {
    let mut cond = cond as u32;
    let mut fieldmask = ::std::mem::transmute::<_, u8>(fieldmask) as u32;
    *(*buf as *mut u32) = ((18935808 | cond) | (fieldmask << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'pkhbt' instruction.
pub unsafe fn pkhbt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((109051920 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'pkhtb' instruction.
pub unsafe fn pkhtb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((109051984 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'pld' instruction.
pub unsafe fn pld(buf: &mut *mut (), rn: Register, offset_mode: OffsetMode) {
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    *(*buf as *mut u32) = ((4115722240 | (rn << 16)) | (offset_mode << 23)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qadd' instruction.
pub unsafe fn qadd(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777296 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qadd16' instruction.
pub unsafe fn qadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764304 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qadd8' instruction.
pub unsafe fn qadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764432 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qaddsubx' instruction.
pub unsafe fn qaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764336 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qdadd' instruction.
pub unsafe fn qdadd(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((20971600 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qdsub' instruction.
pub unsafe fn qdsub(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((23068752 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qsub' instruction.
pub unsafe fn qsub(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((18874448 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qsub16' instruction.
pub unsafe fn qsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764400 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qsub8' instruction.
pub unsafe fn qsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764528 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'qsubaddx' instruction.
pub unsafe fn qsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((102764368 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'rev' instruction.
pub unsafe fn rev(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((113184560 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'rev16' instruction.
pub unsafe fn rev16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((113184688 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'revsh' instruction.
pub unsafe fn revsh(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((117378992 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'rfe' instruction.
pub unsafe fn rfe(buf: &mut *mut (), write: bool, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sadd16' instruction.
pub unsafe fn sadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715728 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sadd8' instruction.
pub unsafe fn sadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715856 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'saddsubx' instruction.
pub unsafe fn saddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715760 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sel' instruction.
pub unsafe fn sel(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((109055920 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'setendbe' instruction.
pub unsafe fn setendbe(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 4043375104 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'setendle' instruction.
pub unsafe fn setendle(buf: &mut *mut ()) {
    *(*buf as *mut u32) = 4043374592 as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shadd16' instruction.
pub unsafe fn shadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103812880 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shadd8' instruction.
pub unsafe fn shadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103813008 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shaddsubx' instruction.
pub unsafe fn shaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103812912 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shsub16' instruction.
pub unsafe fn shsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103812976 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shsub8' instruction.
pub unsafe fn shsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103813104 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'shsubaddx' instruction.
pub unsafe fn shsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((103812944 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlabb' instruction.
pub unsafe fn smlabb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777344 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlabt' instruction.
pub unsafe fn smlabt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777376 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlatb' instruction.
pub unsafe fn smlatb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777408 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlatt' instruction.
pub unsafe fn smlatt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777440 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlad' instruction.
pub unsafe fn smlad(buf: &mut *mut (), cond: Condition, exchange: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlal' instruction.
pub unsafe fn smlal(buf: &mut *mut (), cond: Condition, update_cprs: bool, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlalbb' instruction.
pub unsafe fn smlalbb(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (20971648 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlalbt' instruction.
pub unsafe fn smlalbt(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (20971680 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlaltb' instruction.
pub unsafe fn smlaltb(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (20971712 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlaltt' instruction.
pub unsafe fn smlaltt(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (20971744 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlald' instruction.
pub unsafe fn smlald(buf: &mut *mut (), cond: Condition, exchange: bool) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    *(*buf as *mut u32) = ((121634832 | cond) | (exchange << 5)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlawb' instruction.
pub unsafe fn smlawb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((18874496 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlawt' instruction.
pub unsafe fn smlawt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((18874560 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlsd' instruction.
pub unsafe fn smlsd(buf: &mut *mut (), cond: Condition, exchange: bool, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smlsld' instruction.
pub unsafe fn smlsld(buf: &mut *mut (), cond: Condition, exchange: bool) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    *(*buf as *mut u32) = ((121634896 | cond) | (exchange << 5)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smmla' instruction.
pub unsafe fn smmla(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((122683408 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smmls' instruction.
pub unsafe fn smmls(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((122683600 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smmul' instruction.
pub unsafe fn smmul(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((122744848 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smuad' instruction.
pub unsafe fn smuad(buf: &mut *mut (), cond: Condition, exchange: bool, rd: Register) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((117501968 | cond) | (exchange << 5)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smulbb' instruction.
pub unsafe fn smulbb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((23068800 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smulbt' instruction.
pub unsafe fn smulbt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((23068832 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smultb' instruction.
pub unsafe fn smultb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((23068864 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smultt' instruction.
pub unsafe fn smultt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((23068896 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smull' instruction.
pub unsafe fn smull(buf: &mut *mut (), cond: Condition, update_cprs: bool, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smulwb' instruction.
pub unsafe fn smulwb(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((18874528 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smulwt' instruction.
pub unsafe fn smulwt(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((18874592 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'smusd' instruction.
pub unsafe fn smusd(buf: &mut *mut (), cond: Condition, exchange: bool, rd: Register) {
    let mut cond = cond as u32;
    let mut exchange = exchange as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((117502032 | cond) | (exchange << 5)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'srs' instruction.
pub unsafe fn srs(buf: &mut *mut (), write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut write = write as u32;
    let mut mode = mode as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ssat' instruction.
pub unsafe fn ssat(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((105906192 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ssat16' instruction.
pub unsafe fn ssat16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((111152944 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ssub16' instruction.
pub unsafe fn ssub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715824 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ssub8' instruction.
pub unsafe fn ssub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715952 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'ssubaddx' instruction.
pub unsafe fn ssubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((101715792 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'stc' instruction.
pub unsafe fn stc(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut cpnum = ::std::mem::transmute::<_, u8>(cpnum) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'stm' instruction.
pub unsafe fn stm(buf: &mut *mut (), cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, user_mode: bool) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    let mut registers = ::std::mem::transmute::<_, u8>(registers) as u32;
    let mut write = write as u32;
    let mut user_mode = user_mode as u32;
    assert!(((user_mode == 0) || (write == 0)));
    *(*buf as *mut u32) = ((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'str' instruction.
pub unsafe fn str(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strb' instruction.
pub unsafe fn str#b(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strbt' instruction.
pub unsafe fn str#bt(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    *(*buf as *mut u32) = ((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strd' instruction.
pub unsafe fn str#d(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strex' instruction.
pub unsafe fn strex(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((25169808 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strh' instruction.
pub unsafe fn str#h(buf: &mut *mut (), cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) {
    let mut cond = cond as u32;
    let mut write = write as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    let mut addressing_mode = ::std::mem::transmute::<_, u8>(addressing_mode) as u32;
    *(*buf as *mut u32) = ((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'strt' instruction.
pub unsafe fn str#t(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut offset_mode = ::std::mem::transmute::<_, u8>(offset_mode) as u32;
    *(*buf as *mut u32) = ((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'swi' instruction.
pub unsafe fn swi(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (251658240 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'swp' instruction.
pub unsafe fn swp(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((16777360 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'swpb' instruction.
pub unsafe fn swpb(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((20971664 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxtab' instruction.
pub unsafe fn sxtab(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxtab16' instruction.
pub unsafe fn sxtab16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxtah' instruction.
pub unsafe fn sxtah(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxtb' instruction.
pub unsafe fn sxtb(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((112132208 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxtb16' instruction.
pub unsafe fn sxtb16(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((110035056 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'sxth' instruction.
pub unsafe fn sxth(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((113180784 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'teq' instruction.
pub unsafe fn teq(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((19922944 | cond) | (rn << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits a 'tst' instruction.
pub unsafe fn tst(buf: &mut *mut (), cond: Condition, rn: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    *(*buf as *mut u32) = ((17825792 | cond) | (rn << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uadd16' instruction.
pub unsafe fn uadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910032 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uadd8' instruction.
pub unsafe fn uadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910160 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uaddsubx' instruction.
pub unsafe fn uaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910064 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhadd16' instruction.
pub unsafe fn uhadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007184 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhadd8' instruction.
pub unsafe fn uhadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007312 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhaddsubx' instruction.
pub unsafe fn uhaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007216 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhsub16' instruction.
pub unsafe fn uhsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007280 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhsub8' instruction.
pub unsafe fn uhsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007408 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uhsubaddx' instruction.
pub unsafe fn uhsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((108007248 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'umaal' instruction.
pub unsafe fn umaal(buf: &mut *mut (), cond: Condition) {
    let mut cond = cond as u32;
    *(*buf as *mut u32) = (4194448 | cond) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'umlal' instruction.
pub unsafe fn umlal(buf: &mut *mut (), cond: Condition, update_cprs: bool, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'umull' instruction.
pub unsafe fn umull(buf: &mut *mut (), cond: Condition, update_cprs: bool, update_condition: bool) {
    let mut cond = cond as u32;
    let mut update_cprs = update_cprs as u32;
    let mut update_condition = update_condition as u32;
    *(*buf as *mut u32) = (((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqadd16' instruction.
pub unsafe fn uqadd16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958608 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqadd8' instruction.
pub unsafe fn uqadd8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958736 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqaddsubx' instruction.
pub unsafe fn uqaddsubx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958640 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqsub16' instruction.
pub unsafe fn uqsub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958704 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqsub8' instruction.
pub unsafe fn uqsub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958832 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uqsubaddx' instruction.
pub unsafe fn uqsubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((106958672 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usad8' instruction.
pub unsafe fn usad8(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((125890576 | cond) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usada8' instruction.
pub unsafe fn usada8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((125829136 | cond) | (rn << 12)) | (rd << 16)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usat' instruction.
pub unsafe fn usat(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((115343376 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usat16' instruction.
pub unsafe fn usat16(buf: &mut *mut (), cond: Condition, rd: Register) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = ((115347248 | cond) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usub16' instruction.
pub unsafe fn usub16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910128 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usub8' instruction.
pub unsafe fn usub8(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910256 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'usubaddx' instruction.
pub unsafe fn usubaddx(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    *(*buf as *mut u32) = (((105910096 | cond) | (rn << 16)) | (rd << 12)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxtab' instruction.
pub unsafe fn uxtab(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxtab16' instruction.
pub unsafe fn uxtab16(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxtah' instruction.
pub unsafe fn uxtah(buf: &mut *mut (), cond: Condition, rn: Register, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rn = ::std::mem::transmute::<_, u8>(rn) as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxtb' instruction.
pub unsafe fn uxtb(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((116326512 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxtb16' instruction.
pub unsafe fn uxtb16(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((114229360 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

/// Emits an 'uxth' instruction.
pub unsafe fn uxth(buf: &mut *mut (), cond: Condition, rd: Register, rotate: Rotation) {
    let mut cond = cond as u32;
    let mut rd = ::std::mem::transmute::<_, u8>(rd) as u32;
    let mut rotate = ::std::mem::transmute::<_, u8>(rotate) as u32;
    *(*buf as *mut u32) = (((117375088 | cond) | (rd << 12)) | (rotate << 10)) as _;
    *(&mut (*buf as usize)) += 4;
}

