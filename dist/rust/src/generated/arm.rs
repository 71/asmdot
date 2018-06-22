#![allow(unused_imports, unused_parens, unused_mut)]
use ::arm::*;

use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// An ARM register.
pub struct Register(pub u8);

impl Register {
    pub const R0: Self = Register(0);
    pub const R1: Self = Register(1);
    pub const R2: Self = Register(2);
    pub const R3: Self = Register(3);
    pub const R4: Self = Register(4);
    pub const R5: Self = Register(5);
    pub const R6: Self = Register(6);
    pub const R7: Self = Register(7);
    pub const R8: Self = Register(8);
    pub const R9: Self = Register(9);
    pub const R10: Self = Register(10);
    pub const R11: Self = Register(11);
    pub const R12: Self = Register(12);
    pub const R13: Self = Register(13);
    pub const R14: Self = Register(14);
    pub const R15: Self = Register(15);
    pub const A1: Self = Register(0);
    pub const A2: Self = Register(1);
    pub const A3: Self = Register(2);
    pub const A4: Self = Register(3);
    pub const V1: Self = Register(4);
    pub const V2: Self = Register(5);
    pub const V3: Self = Register(6);
    pub const V4: Self = Register(7);
    pub const V5: Self = Register(8);
    pub const V6: Self = Register(9);
    pub const V7: Self = Register(10);
    pub const V8: Self = Register(11);
    pub const IP: Self = Register(12);
    pub const SP: Self = Register(13);
    pub const LR: Self = Register(14);
    pub const PC: Self = Register(15);
    pub const WR: Self = Register(7);
    pub const SB: Self = Register(9);
    pub const SL: Self = Register(10);
    pub const FP: Self = Register(11);
}

/// An ARM coprocessor.
pub struct Coprocessor(pub u8);

impl Coprocessor {
    pub const CP0: Self = Coprocessor(0);
    pub const CP1: Self = Coprocessor(1);
    pub const CP2: Self = Coprocessor(2);
    pub const CP3: Self = Coprocessor(3);
    pub const CP4: Self = Coprocessor(4);
    pub const CP5: Self = Coprocessor(5);
    pub const CP6: Self = Coprocessor(6);
    pub const CP7: Self = Coprocessor(7);
    pub const CP8: Self = Coprocessor(8);
    pub const CP9: Self = Coprocessor(9);
    pub const CP10: Self = Coprocessor(10);
    pub const CP11: Self = Coprocessor(11);
    pub const CP12: Self = Coprocessor(12);
    pub const CP13: Self = Coprocessor(13);
    pub const CP14: Self = Coprocessor(14);
    pub const CP15: Self = Coprocessor(15);
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
    pub const CS: Self = mem::transmute(2);
    /// Carry clear.
    pub const CC: Self = mem::transmute(3);
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
    pub const RRX: Self = mem::transmute(3);
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
        const C = mem::transmute(1);
        /// Extension field mask bit.
        const X = mem::transmute(2);
        /// Status field mask bit.
        const S = mem::transmute(4);
        /// Flags field mask bit.
        const F = mem::transmute(8);
    }
}

bitflags! {
    /// Interrupt flags.
    pub struct InterruptFlags: u8 {
        /// FIQ interrupt bit.
        const F = mem::transmute(1);
        /// IRQ interrupt bit.
        const I = mem::transmute(2);
        /// Imprecise data abort bit.
        const A = mem::transmute(4);
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
    pub const Offset: Self = mem::transmute(1);
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
pub fn adc(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'add' instruction.
pub fn add(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'and' instruction.
pub fn and(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'eor' instruction.
pub fn eor(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'orr' instruction.
pub fn orr(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'rsb' instruction.
pub fn rsb(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'rsc' instruction.
pub fn rsc(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'sbc' instruction.
pub fn sbc(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'sub' instruction.
pub fn sub(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'bkpt' instruction.
pub fn bkpt(buf: &mut Write, immed: u16) -> Result<()> {
    unsafe {
        buf.write_u32::<LE>(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)))?;
    }
    Ok(())
}

/// Emits a 'b' instruction.
pub fn b(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((167772160 | cond))?;
    }
    Ok(())
}

/// Emits a 'bic' instruction.
pub fn bic(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'blx' instruction.
pub fn blx(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((19922736 | cond))?;
    }
    Ok(())
}

/// Emits a 'bx' instruction.
pub fn bx(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((19922704 | cond))?;
    }
    Ok(())
}

/// Emits a 'bxj' instruction.
pub fn bxj(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((19922720 | cond))?;
    }
    Ok(())
}

/// Emits a 'blxun' instruction.
pub fn blxun(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u32::<LE>(4194304000)?;
    }
    Ok(())
}

/// Emits a 'clz' instruction.
pub fn clz(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((24055568 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'cmn' instruction.
pub fn cmn(buf: &mut Write, cond: Condition, rn: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        buf.write_u32::<LE>(((24117248 | cond) | (rn << 16)))?;
    }
    Ok(())
}

/// Emits a 'cmp' instruction.
pub fn cmp(buf: &mut Write, cond: Condition, rn: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        buf.write_u32::<LE>(((22020096 | cond) | (rn << 16)))?;
    }
    Ok(())
}

/// Emits a 'cpy' instruction.
pub fn cpy(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((27262976 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'cps' instruction.
pub fn cps(buf: &mut Write, mode: Mode) -> Result<()> {
    unsafe {
        let mut mode = mode as u32;
        buf.write_u32::<LE>((4043440128 | (mode << 0)))?;
    }
    Ok(())
}

/// Emits a 'cpsie' instruction.
pub fn cpsie(buf: &mut Write, iflags: InterruptFlags) -> Result<()> {
    unsafe {
        let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
        buf.write_u32::<LE>((4043833344 | (iflags << 6)))?;
    }
    Ok(())
}

/// Emits a 'cpsid' instruction.
pub fn cpsid(buf: &mut Write, iflags: InterruptFlags) -> Result<()> {
    unsafe {
        let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
        buf.write_u32::<LE>((4044095488 | (iflags << 6)))?;
    }
    Ok(())
}

/// Emits a 'cpsie_mode' instruction.
pub fn cpsie_mode(buf: &mut Write, iflags: InterruptFlags, mode: Mode) -> Result<()> {
    unsafe {
        let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
        let mut mode = mode as u32;
        buf.write_u32::<LE>(((4043964416 | (iflags << 6)) | (mode << 0)))?;
    }
    Ok(())
}

/// Emits a 'cpsid_mode' instruction.
pub fn cpsid_mode(buf: &mut Write, iflags: InterruptFlags, mode: Mode) -> Result<()> {
    unsafe {
        let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
        let mut mode = mode as u32;
        buf.write_u32::<LE>(((4044226560 | (iflags << 6)) | (mode << 0)))?;
    }
    Ok(())
}

/// Emits a 'ldc' instruction.
pub fn ldc(buf: &mut Write, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldm' instruction.
pub fn ldm(buf: &mut Write, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, copy_spsr: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        let mut registers = mem::transmute::<_, u8>(registers) as u32;
        let mut write = write as u32;
        let mut copy_spsr = copy_spsr as u32;
        assert!((copy_spsr ^ (write == (registers & 32768))));
        buf.write_u32::<LE>(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)))?;
    }
    Ok(())
}

/// Emits a 'ldr' instruction.
pub fn ldr(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrb' instruction.
pub fn ldrb(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrbt' instruction.
pub fn ldrbt(buf: &mut Write, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        buf.write_u32::<LE>(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)))?;
    }
    Ok(())
}

/// Emits a 'ldrd' instruction.
pub fn ldrd(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrex' instruction.
pub fn ldrex(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((26218399 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'ldrh' instruction.
pub fn ldrh(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrsb' instruction.
pub fn ldrsb(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrsh' instruction.
pub fn ldrsh(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ldrt' instruction.
pub fn ldrt(buf: &mut Write, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        buf.write_u32::<LE>(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)))?;
    }
    Ok(())
}

/// Emits a 'cdp' instruction.
pub fn cdp(buf: &mut Write, cond: Condition, cpnum: Coprocessor) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        buf.write_u32::<LE>(((234881024 | cond) | (cpnum << 8)))?;
    }
    Ok(())
}

/// Emits a 'mcr' instruction.
pub fn mcr(buf: &mut Write, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        buf.write_u32::<LE>((((234881040 | cond) | (rd << 12)) | (cpnum << 8)))?;
    }
    Ok(())
}

/// Emits a 'mrc' instruction.
pub fn mrc(buf: &mut Write, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        buf.write_u32::<LE>((((235929616 | cond) | (rd << 12)) | (cpnum << 8)))?;
    }
    Ok(())
}

/// Emits a 'mcrr' instruction.
pub fn mcrr(buf: &mut Write, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        buf.write_u32::<LE>(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)))?;
    }
    Ok(())
}

/// Emits a 'mla' instruction.
pub fn mla(buf: &mut Write, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'mov' instruction.
pub fn mov(buf: &mut Write, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'mrrc' instruction.
pub fn mrrc(buf: &mut Write, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        buf.write_u32::<LE>(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)))?;
    }
    Ok(())
}

/// Emits a 'mrs' instruction.
pub fn mrs(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((17760256 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'mul' instruction.
pub fn mul(buf: &mut Write, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'mvn' instruction.
pub fn mvn(buf: &mut Write, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'msr_imm' instruction.
pub fn msr_imm(buf: &mut Write, cond: Condition, fieldmask: FieldMask) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut fieldmask = mem::transmute::<_, u8>(fieldmask) as u32;
        buf.write_u32::<LE>(((52490240 | cond) | (fieldmask << 16)))?;
    }
    Ok(())
}

/// Emits a 'msr_reg' instruction.
pub fn msr_reg(buf: &mut Write, cond: Condition, fieldmask: FieldMask) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut fieldmask = mem::transmute::<_, u8>(fieldmask) as u32;
        buf.write_u32::<LE>(((18935808 | cond) | (fieldmask << 16)))?;
    }
    Ok(())
}

/// Emits a 'pkhbt' instruction.
pub fn pkhbt(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((109051920 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'pkhtb' instruction.
pub fn pkhtb(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((109051984 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'pld' instruction.
pub fn pld(buf: &mut Write, rn: Register, offset_mode: OffsetMode) -> Result<()> {
    unsafe {
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        buf.write_u32::<LE>(((4115722240 | (rn << 16)) | (offset_mode << 23)))?;
    }
    Ok(())
}

/// Emits a 'qadd' instruction.
pub fn qadd(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777296 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qadd16' instruction.
pub fn qadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764304 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qadd8' instruction.
pub fn qadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764432 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qaddsubx' instruction.
pub fn qaddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764336 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qdadd' instruction.
pub fn qdadd(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((20971600 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qdsub' instruction.
pub fn qdsub(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((23068752 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qsub' instruction.
pub fn qsub(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((18874448 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qsub16' instruction.
pub fn qsub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764400 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qsub8' instruction.
pub fn qsub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764528 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'qsubaddx' instruction.
pub fn qsubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((102764368 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'rev' instruction.
pub fn rev(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((113184560 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'rev16' instruction.
pub fn rev16(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((113184688 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'revsh' instruction.
pub fn revsh(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((117378992 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'rfe' instruction.
pub fn rfe(buf: &mut Write, write: bool, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'sadd16' instruction.
pub fn sadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715728 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'sadd8' instruction.
pub fn sadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715856 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'saddsubx' instruction.
pub fn saddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715760 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'sel' instruction.
pub fn sel(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((109055920 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'setendbe' instruction.
pub fn setendbe(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u32::<LE>(4043375104)?;
    }
    Ok(())
}

/// Emits a 'setendle' instruction.
pub fn setendle(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u32::<LE>(4043374592)?;
    }
    Ok(())
}

/// Emits a 'shadd16' instruction.
pub fn shadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103812880 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'shadd8' instruction.
pub fn shadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103813008 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'shaddsubx' instruction.
pub fn shaddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103812912 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'shsub16' instruction.
pub fn shsub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103812976 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'shsub8' instruction.
pub fn shsub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103813104 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'shsubaddx' instruction.
pub fn shsubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((103812944 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'smlabb' instruction.
pub fn smlabb(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777344 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlabt' instruction.
pub fn smlabt(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777376 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlatb' instruction.
pub fn smlatb(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777408 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlatt' instruction.
pub fn smlatt(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777440 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlad' instruction.
pub fn smlad(buf: &mut Write, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlal' instruction.
pub fn smlal(buf: &mut Write, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'smlalbb' instruction.
pub fn smlalbb(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((20971648 | cond))?;
    }
    Ok(())
}

/// Emits a 'smlalbt' instruction.
pub fn smlalbt(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((20971680 | cond))?;
    }
    Ok(())
}

/// Emits a 'smlaltb' instruction.
pub fn smlaltb(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((20971712 | cond))?;
    }
    Ok(())
}

/// Emits a 'smlaltt' instruction.
pub fn smlaltt(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((20971744 | cond))?;
    }
    Ok(())
}

/// Emits a 'smlald' instruction.
pub fn smlald(buf: &mut Write, cond: Condition, exchange: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        buf.write_u32::<LE>(((121634832 | cond) | (exchange << 5)))?;
    }
    Ok(())
}

/// Emits a 'smlawb' instruction.
pub fn smlawb(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((18874496 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlawt' instruction.
pub fn smlawt(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((18874560 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlsd' instruction.
pub fn smlsd(buf: &mut Write, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smlsld' instruction.
pub fn smlsld(buf: &mut Write, cond: Condition, exchange: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        buf.write_u32::<LE>(((121634896 | cond) | (exchange << 5)))?;
    }
    Ok(())
}

/// Emits a 'smmla' instruction.
pub fn smmla(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((122683408 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smmls' instruction.
pub fn smmls(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((122683600 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smmul' instruction.
pub fn smmul(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((122744848 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smuad' instruction.
pub fn smuad(buf: &mut Write, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((117501968 | cond) | (exchange << 5)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smulbb' instruction.
pub fn smulbb(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((23068800 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smulbt' instruction.
pub fn smulbt(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((23068832 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smultb' instruction.
pub fn smultb(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((23068864 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smultt' instruction.
pub fn smultt(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((23068896 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smull' instruction.
pub fn smull(buf: &mut Write, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits a 'smulwb' instruction.
pub fn smulwb(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((18874528 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smulwt' instruction.
pub fn smulwt(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((18874592 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'smusd' instruction.
pub fn smusd(buf: &mut Write, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut exchange = exchange as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((117502032 | cond) | (exchange << 5)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits a 'srs' instruction.
pub fn srs(buf: &mut Write, write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut write = write as u32;
        let mut mode = mode as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'ssat' instruction.
pub fn ssat(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((105906192 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'ssat16' instruction.
pub fn ssat16(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((111152944 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'ssub16' instruction.
pub fn ssub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715824 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'ssub8' instruction.
pub fn ssub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715952 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'ssubaddx' instruction.
pub fn ssubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((101715792 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'stc' instruction.
pub fn stc(buf: &mut Write, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'stm' instruction.
pub fn stm(buf: &mut Write, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, user_mode: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        let mut registers = mem::transmute::<_, u8>(registers) as u32;
        let mut write = write as u32;
        let mut user_mode = user_mode as u32;
        assert!(((user_mode == 0) || (write == 0)));
        buf.write_u32::<LE>(((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10)))?;
    }
    Ok(())
}

/// Emits a 'str' instruction.
pub fn str(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'strb' instruction.
pub fn strb(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'strbt' instruction.
pub fn strbt(buf: &mut Write, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        buf.write_u32::<LE>(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)))?;
    }
    Ok(())
}

/// Emits a 'strd' instruction.
pub fn strd(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'strex' instruction.
pub fn strex(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((25169808 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'strh' instruction.
pub fn strh(buf: &mut Write, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut write = write as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
        buf.write_u32::<LE>(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)))?;
    }
    Ok(())
}

/// Emits a 'strt' instruction.
pub fn strt(buf: &mut Write, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
        buf.write_u32::<LE>(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)))?;
    }
    Ok(())
}

/// Emits a 'swi' instruction.
pub fn swi(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((251658240 | cond))?;
    }
    Ok(())
}

/// Emits a 'swp' instruction.
pub fn swp(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((16777360 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'swpb' instruction.
pub fn swpb(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((20971664 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits a 'sxtab' instruction.
pub fn sxtab(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'sxtab16' instruction.
pub fn sxtab16(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'sxtah' instruction.
pub fn sxtah(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'sxtb' instruction.
pub fn sxtb(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((112132208 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'sxtb16' instruction.
pub fn sxtb16(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((110035056 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'sxth' instruction.
pub fn sxth(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((113180784 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits a 'teq' instruction.
pub fn teq(buf: &mut Write, cond: Condition, rn: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        buf.write_u32::<LE>(((19922944 | cond) | (rn << 16)))?;
    }
    Ok(())
}

/// Emits a 'tst' instruction.
pub fn tst(buf: &mut Write, cond: Condition, rn: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        buf.write_u32::<LE>(((17825792 | cond) | (rn << 16)))?;
    }
    Ok(())
}

/// Emits an 'uadd16' instruction.
pub fn uadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910032 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uadd8' instruction.
pub fn uadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910160 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uaddsubx' instruction.
pub fn uaddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910064 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhadd16' instruction.
pub fn uhadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007184 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhadd8' instruction.
pub fn uhadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007312 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhaddsubx' instruction.
pub fn uhaddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007216 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhsub16' instruction.
pub fn uhsub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007280 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhsub8' instruction.
pub fn uhsub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007408 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uhsubaddx' instruction.
pub fn uhsubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((108007248 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'umaal' instruction.
pub fn umaal(buf: &mut Write, cond: Condition) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        buf.write_u32::<LE>((4194448 | cond))?;
    }
    Ok(())
}

/// Emits an 'umlal' instruction.
pub fn umlal(buf: &mut Write, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'umull' instruction.
pub fn umull(buf: &mut Write, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut update_cprs = update_cprs as u32;
        let mut update_condition = update_condition as u32;
        buf.write_u32::<LE>((((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20)))?;
    }
    Ok(())
}

/// Emits an 'uqadd16' instruction.
pub fn uqadd16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958608 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uqadd8' instruction.
pub fn uqadd8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958736 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uqaddsubx' instruction.
pub fn uqaddsubx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958640 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uqsub16' instruction.
pub fn uqsub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958704 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uqsub8' instruction.
pub fn uqsub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958832 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uqsubaddx' instruction.
pub fn uqsubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((106958672 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'usad8' instruction.
pub fn usad8(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((125890576 | cond) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits an 'usada8' instruction.
pub fn usada8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((125829136 | cond) | (rn << 12)) | (rd << 16)))?;
    }
    Ok(())
}

/// Emits an 'usat' instruction.
pub fn usat(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((115343376 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'usat16' instruction.
pub fn usat16(buf: &mut Write, cond: Condition, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>(((115347248 | cond) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'usub16' instruction.
pub fn usub16(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910128 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'usub8' instruction.
pub fn usub8(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910256 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'usubaddx' instruction.
pub fn usubaddx(buf: &mut Write, cond: Condition, rn: Register, rd: Register) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        buf.write_u32::<LE>((((105910096 | cond) | (rn << 16)) | (rd << 12)))?;
    }
    Ok(())
}

/// Emits an 'uxtab' instruction.
pub fn uxtab(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits an 'uxtab16' instruction.
pub fn uxtab16(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits an 'uxtah' instruction.
pub fn uxtah(buf: &mut Write, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rn = mem::transmute::<_, u8>(rn) as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits an 'uxtb' instruction.
pub fn uxtb(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((116326512 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits an 'uxtb16' instruction.
pub fn uxtb16(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((114229360 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

/// Emits an 'uxth' instruction.
pub fn uxth(buf: &mut Write, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
    unsafe {
        let mut cond = cond as u32;
        let mut rd = mem::transmute::<_, u8>(rd) as u32;
        let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
        buf.write_u32::<LE>((((117375088 | cond) | (rd << 12)) | (rotate << 10)))?;
    }
    Ok(())
}

