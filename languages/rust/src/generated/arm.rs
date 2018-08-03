#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

use ::arm::*;

use std::any::Any;
use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// An ARM register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Register(pub u8);

impl Into<u8> for Register {
    fn into(self) -> u8 { self.0 }
}

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

bitflags! {
    /// A list of ARM registers, where each register corresponds to a single bit.
    pub struct RegList: u16 {
        /// Register #1.
        const R0 = transmute_const!(0);
        /// Register #2.
        const R1 = transmute_const!(1);
        /// Register #3.
        const R2 = transmute_const!(2);
        /// Register #4.
        const R3 = transmute_const!(3);
        /// Register #5.
        const R4 = transmute_const!(4);
        /// Register #6.
        const R5 = transmute_const!(5);
        /// Register #7.
        const R6 = transmute_const!(6);
        /// Register #8.
        const R7 = transmute_const!(7);
        /// Register #9.
        const R8 = transmute_const!(8);
        /// Register #10.
        const R9 = transmute_const!(9);
        /// Register #11.
        const R10 = transmute_const!(10);
        /// Register #12.
        const R11 = transmute_const!(11);
        /// Register #13.
        const R12 = transmute_const!(12);
        /// Register #14.
        const R13 = transmute_const!(13);
        /// Register #15.
        const R14 = transmute_const!(14);
        /// Register #16.
        const R15 = transmute_const!(15);
        /// Register A1.
        const A1 = transmute_const!(0);
        /// Register A2.
        const A2 = transmute_const!(1);
        /// Register A3.
        const A3 = transmute_const!(2);
        /// Register A4.
        const A4 = transmute_const!(3);
        /// Register V1.
        const V1 = transmute_const!(4);
        /// Register V2.
        const V2 = transmute_const!(5);
        /// Register V3.
        const V3 = transmute_const!(6);
        /// Register V4.
        const V4 = transmute_const!(7);
        /// Register V5.
        const V5 = transmute_const!(8);
        /// Register V6.
        const V6 = transmute_const!(9);
        /// Register V7.
        const V7 = transmute_const!(10);
        /// Register V8.
        const V8 = transmute_const!(11);
        /// Register IP.
        const IP = transmute_const!(12);
        /// Register SP.
        const SP = transmute_const!(13);
        /// Register LR.
        const LR = transmute_const!(14);
        /// Register PC.
        const PC = transmute_const!(15);
        /// Register WR.
        const WR = transmute_const!(7);
        /// Register SB.
        const SB = transmute_const!(9);
        /// Register SL.
        const SL = transmute_const!(10);
        /// Register FP.
        const FP = transmute_const!(11);
    }
}

impl Into<u16> for RegList {
    fn into(self) -> u16 { self.bits() }
}

/// An ARM coprocessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Coprocessor(pub u8);

impl Into<u8> for Coprocessor {
    fn into(self) -> u8 { self.0 }
}

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

impl Into<u8> for Condition {
    fn into(self) -> u8 { self as u8 }
}

impl Condition {
    /// Carry set.
    pub const CS: Self = transmute_const!(2);
    /// Carry clear.
    pub const CC: Self = transmute_const!(3);
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

impl Into<u8> for Mode {
    fn into(self) -> u8 { self as u8 }
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

impl Into<u8> for Shift {
    fn into(self) -> u8 { self as u8 }
}

impl Shift {
    /// Shifted right by one bit.
    pub const RRX: Self = transmute_const!(3);
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

impl Into<u8> for Rotation {
    fn into(self) -> u8 { self as u8 }
}

bitflags! {
    /// Field mask bits.
    pub struct FieldMask: u8 {
        /// Control field mask bit.
        const C = transmute_const!(1);
        /// Extension field mask bit.
        const X = transmute_const!(2);
        /// Status field mask bit.
        const S = transmute_const!(4);
        /// Flags field mask bit.
        const F = transmute_const!(8);
    }
}

impl Into<u8> for FieldMask {
    fn into(self) -> u8 { self.bits() }
}

bitflags! {
    /// Interrupt flags.
    pub struct InterruptFlags: u8 {
        /// FIQ interrupt bit.
        const F = transmute_const!(1);
        /// IRQ interrupt bit.
        const I = transmute_const!(2);
        /// Imprecise data abort bit.
        const A = transmute_const!(4);
    }
}

impl Into<u8> for InterruptFlags {
    fn into(self) -> u8 { self.bits() }
}

/// Addressing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Addressing {
    /// Post-indexed addressing.
    PostIndexed = 0,
    /// Pre-indexed addressing (or offset addressing if `write` is false).
    PreIndexed = 1,
}

impl Into<u8> for Addressing {
    fn into(self) -> u8 { self as u8 }
}

impl Addressing {
    /// Offset addressing (or pre-indexed addressing if `write` is true).
    pub const Offset: Self = transmute_const!(1);
}

/// Offset adding or subtracting mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OffsetMode {
    /// Subtract offset from the base.
    Subtract = 0,
    /// Add offset to the base.
    Add = 1,
}

impl Into<u8> for OffsetMode {
    fn into(self) -> u8 { self as u8 }
}

/// Allows any struct that implements `Write` to assemble Arm instructions.
pub trait ArmAssembler: Write {

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'eor' instruction.
    #[inline]
    fn eor(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'orr' instruction.
    #[inline]
    fn orr(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rsb' instruction.
    #[inline]
    fn rsb(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rsc' instruction.
    #[inline]
    fn rsc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbc' instruction.
    #[inline]
    fn sbc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bkpt' instruction.
    #[inline]
    fn bkpt(&mut self, immed: u16) -> Result<()> {
        unsafe {
            let mut immed = immed as u32;
            self.write_u32::<LE>(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'b' instruction.
    #[inline]
    fn b(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((167772160 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bic' instruction.
    #[inline]
    fn bic(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'blx' instruction.
    #[inline]
    fn blx(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((19922736 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bx' instruction.
    #[inline]
    fn bx(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((19922704 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bxj' instruction.
    #[inline]
    fn bxj(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((19922720 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'blxun' instruction.
    #[inline]
    fn blxun(&mut self) -> Result<()> {
        unsafe {
            self.write_u32::<LE>(4194304000 as _)?;
        }
        Ok(())
    }

    /// Emits a 'clz' instruction.
    #[inline]
    fn clz(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((24055568 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmn' instruction.
    #[inline]
    fn cmn(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            self.write_u32::<LE>(((24117248 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            self.write_u32::<LE>(((22020096 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpy' instruction.
    #[inline]
    fn cpy(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((27262976 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cps' instruction.
    #[inline]
    fn cps(&mut self, mode: Mode) -> Result<()> {
        unsafe {
            let mut mode = Into::<u8>::into(mode) as u32;
            self.write_u32::<LE>((4043440128 | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsie' instruction.
    #[inline]
    fn cpsie(&mut self, iflags: InterruptFlags) -> Result<()> {
        unsafe {
            let mut iflags = Into::<u8>::into(iflags) as u32;
            self.write_u32::<LE>((4043833344 | (iflags << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsid' instruction.
    #[inline]
    fn cpsid(&mut self, iflags: InterruptFlags) -> Result<()> {
        unsafe {
            let mut iflags = Into::<u8>::into(iflags) as u32;
            self.write_u32::<LE>((4044095488 | (iflags << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsie_mode' instruction.
    #[inline]
    fn cpsie_mode(&mut self, iflags: InterruptFlags, mode: Mode) -> Result<()> {
        unsafe {
            let mut iflags = Into::<u8>::into(iflags) as u32;
            let mut mode = Into::<u8>::into(mode) as u32;
            self.write_u32::<LE>(((4043964416 | (iflags << 6)) | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsid_mode' instruction.
    #[inline]
    fn cpsid_mode(&mut self, iflags: InterruptFlags, mode: Mode) -> Result<()> {
        unsafe {
            let mut iflags = Into::<u8>::into(iflags) as u32;
            let mut mode = Into::<u8>::into(mode) as u32;
            self.write_u32::<LE>(((4044226560 | (iflags << 6)) | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldc' instruction.
    #[inline]
    fn ldc(&mut self, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldm' instruction.
    #[inline]
    fn ldm(&mut self, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, copy_spsr: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            let mut registers = Into::<u16>::into(registers) as u32;
            let mut write = write as u32;
            let mut copy_spsr = copy_spsr as u32;
            assert!(((copy_spsr == 1) ^ (write == (registers & 32768))));
            self.write_u32::<LE>(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldr' instruction.
    #[inline]
    fn ldr(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrb' instruction.
    #[inline]
    fn ldrb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrbt' instruction.
    #[inline]
    fn ldrbt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            self.write_u32::<LE>(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrd' instruction.
    #[inline]
    fn ldrd(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrex' instruction.
    #[inline]
    fn ldrex(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((26218399 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrh' instruction.
    #[inline]
    fn ldrh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrsb' instruction.
    #[inline]
    fn ldrsb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrsh' instruction.
    #[inline]
    fn ldrsh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrt' instruction.
    #[inline]
    fn ldrt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            self.write_u32::<LE>(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cdp' instruction.
    #[inline]
    fn cdp(&mut self, cond: Condition, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            self.write_u32::<LE>(((234881024 | cond) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mcr' instruction.
    #[inline]
    fn mcr(&mut self, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            self.write_u32::<LE>((((234881040 | cond) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrc' instruction.
    #[inline]
    fn mrc(&mut self, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            self.write_u32::<LE>((((235929616 | cond) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mcrr' instruction.
    #[inline]
    fn mcrr(&mut self, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            self.write_u32::<LE>(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mla' instruction.
    #[inline]
    fn mla(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mov' instruction.
    #[inline]
    fn mov(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrrc' instruction.
    #[inline]
    fn mrrc(&mut self, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            self.write_u32::<LE>(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrs' instruction.
    #[inline]
    fn mrs(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((17760256 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mul' instruction.
    #[inline]
    fn mul(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mvn' instruction.
    #[inline]
    fn mvn(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'msr_imm' instruction.
    #[inline]
    fn msr_imm(&mut self, cond: Condition, fieldmask: FieldMask) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut fieldmask = Into::<u8>::into(fieldmask) as u32;
            self.write_u32::<LE>(((52490240 | cond) | (fieldmask << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'msr_reg' instruction.
    #[inline]
    fn msr_reg(&mut self, cond: Condition, fieldmask: FieldMask) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut fieldmask = Into::<u8>::into(fieldmask) as u32;
            self.write_u32::<LE>(((18935808 | cond) | (fieldmask << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pkhbt' instruction.
    #[inline]
    fn pkhbt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((109051920 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pkhtb' instruction.
    #[inline]
    fn pkhtb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((109051984 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pld' instruction.
    #[inline]
    fn pld(&mut self, rn: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            self.write_u32::<LE>(((4115722240 | (rn << 16)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd' instruction.
    #[inline]
    fn qadd(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777296 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd16' instruction.
    #[inline]
    fn qadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764304 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd8' instruction.
    #[inline]
    fn qadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764432 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qaddsubx' instruction.
    #[inline]
    fn qaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764336 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qdadd' instruction.
    #[inline]
    fn qdadd(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((20971600 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qdsub' instruction.
    #[inline]
    fn qdsub(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((23068752 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub' instruction.
    #[inline]
    fn qsub(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((18874448 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub16' instruction.
    #[inline]
    fn qsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764400 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub8' instruction.
    #[inline]
    fn qsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764528 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsubaddx' instruction.
    #[inline]
    fn qsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((102764368 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rev' instruction.
    #[inline]
    fn rev(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((113184560 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rev16' instruction.
    #[inline]
    fn rev16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((113184688 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'revsh' instruction.
    #[inline]
    fn revsh(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((117378992 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rfe' instruction.
    #[inline]
    fn rfe(&mut self, write: bool, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sadd16' instruction.
    #[inline]
    fn sadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715728 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sadd8' instruction.
    #[inline]
    fn sadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715856 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'saddsubx' instruction.
    #[inline]
    fn saddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715760 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sel' instruction.
    #[inline]
    fn sel(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((109055920 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'setendbe' instruction.
    #[inline]
    fn setendbe(&mut self) -> Result<()> {
        unsafe {
            self.write_u32::<LE>(4043375104 as _)?;
        }
        Ok(())
    }

    /// Emits a 'setendle' instruction.
    #[inline]
    fn setendle(&mut self) -> Result<()> {
        unsafe {
            self.write_u32::<LE>(4043374592 as _)?;
        }
        Ok(())
    }

    /// Emits a 'shadd16' instruction.
    #[inline]
    fn shadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103812880 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shadd8' instruction.
    #[inline]
    fn shadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103813008 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shaddsubx' instruction.
    #[inline]
    fn shaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103812912 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsub16' instruction.
    #[inline]
    fn shsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103812976 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsub8' instruction.
    #[inline]
    fn shsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103813104 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsubaddx' instruction.
    #[inline]
    fn shsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((103812944 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlabb' instruction.
    #[inline]
    fn smlabb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777344 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlabt' instruction.
    #[inline]
    fn smlabt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777376 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlatb' instruction.
    #[inline]
    fn smlatb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777408 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlatt' instruction.
    #[inline]
    fn smlatt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777440 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlad' instruction.
    #[inline]
    fn smlad(&mut self, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlal' instruction.
    #[inline]
    fn smlal(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlalbb' instruction.
    #[inline]
    fn smlalbb(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((20971648 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlalbt' instruction.
    #[inline]
    fn smlalbt(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((20971680 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlaltb' instruction.
    #[inline]
    fn smlaltb(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((20971712 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlaltt' instruction.
    #[inline]
    fn smlaltt(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((20971744 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlald' instruction.
    #[inline]
    fn smlald(&mut self, cond: Condition, exchange: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            self.write_u32::<LE>(((121634832 | cond) | (exchange << 5)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlawb' instruction.
    #[inline]
    fn smlawb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((18874496 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlawt' instruction.
    #[inline]
    fn smlawt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((18874560 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlsd' instruction.
    #[inline]
    fn smlsd(&mut self, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlsld' instruction.
    #[inline]
    fn smlsld(&mut self, cond: Condition, exchange: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            self.write_u32::<LE>(((121634896 | cond) | (exchange << 5)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmla' instruction.
    #[inline]
    fn smmla(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((122683408 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmls' instruction.
    #[inline]
    fn smmls(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((122683600 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmul' instruction.
    #[inline]
    fn smmul(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((122744848 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smuad' instruction.
    #[inline]
    fn smuad(&mut self, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((117501968 | cond) | (exchange << 5)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulbb' instruction.
    #[inline]
    fn smulbb(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((23068800 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulbt' instruction.
    #[inline]
    fn smulbt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((23068832 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smultb' instruction.
    #[inline]
    fn smultb(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((23068864 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smultt' instruction.
    #[inline]
    fn smultt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((23068896 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smull' instruction.
    #[inline]
    fn smull(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulwb' instruction.
    #[inline]
    fn smulwb(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((18874528 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulwt' instruction.
    #[inline]
    fn smulwt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((18874592 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smusd' instruction.
    #[inline]
    fn smusd(&mut self, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut exchange = exchange as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((117502032 | cond) | (exchange << 5)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'srs' instruction.
    #[inline]
    fn srs(&mut self, write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut write = write as u32;
            let mut mode = Into::<u8>::into(mode) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssat' instruction.
    #[inline]
    fn ssat(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((105906192 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssat16' instruction.
    #[inline]
    fn ssat16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((111152944 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssub16' instruction.
    #[inline]
    fn ssub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715824 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssub8' instruction.
    #[inline]
    fn ssub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715952 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssubaddx' instruction.
    #[inline]
    fn ssubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((101715792 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'stc' instruction.
    #[inline]
    fn stc(&mut self, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut cpnum = Into::<u8>::into(cpnum) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'stm' instruction.
    #[inline]
    fn stm(&mut self, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: RegList, write: bool, user_mode: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            let mut registers = Into::<u16>::into(registers) as u32;
            let mut write = write as u32;
            let mut user_mode = user_mode as u32;
            assert!(((user_mode == 0) || (write == 0)));
            self.write_u32::<LE>(((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'str' instruction.
    #[inline]
    fn str(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strb' instruction.
    #[inline]
    fn strb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strbt' instruction.
    #[inline]
    fn strbt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            self.write_u32::<LE>(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strd' instruction.
    #[inline]
    fn strd(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strex' instruction.
    #[inline]
    fn strex(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((25169808 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strh' instruction.
    #[inline]
    fn strh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut write = write as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            let mut addressing_mode = Into::<u8>::into(addressing_mode) as u32;
            self.write_u32::<LE>(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strt' instruction.
    #[inline]
    fn strt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut offset_mode = Into::<u8>::into(offset_mode) as u32;
            self.write_u32::<LE>(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swi' instruction.
    #[inline]
    fn swi(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((251658240 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swp' instruction.
    #[inline]
    fn swp(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((16777360 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swpb' instruction.
    #[inline]
    fn swpb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((20971664 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtab' instruction.
    #[inline]
    fn sxtab(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtab16' instruction.
    #[inline]
    fn sxtab16(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtah' instruction.
    #[inline]
    fn sxtah(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtb' instruction.
    #[inline]
    fn sxtb(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((112132208 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtb16' instruction.
    #[inline]
    fn sxtb16(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((110035056 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxth' instruction.
    #[inline]
    fn sxth(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((113180784 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'teq' instruction.
    #[inline]
    fn teq(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            self.write_u32::<LE>(((19922944 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tst' instruction.
    #[inline]
    fn tst(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            self.write_u32::<LE>(((17825792 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uadd16' instruction.
    #[inline]
    fn uadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910032 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uadd8' instruction.
    #[inline]
    fn uadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910160 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uaddsubx' instruction.
    #[inline]
    fn uaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910064 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhadd16' instruction.
    #[inline]
    fn uhadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007184 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhadd8' instruction.
    #[inline]
    fn uhadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007312 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhaddsubx' instruction.
    #[inline]
    fn uhaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007216 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsub16' instruction.
    #[inline]
    fn uhsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007280 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsub8' instruction.
    #[inline]
    fn uhsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007408 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsubaddx' instruction.
    #[inline]
    fn uhsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((108007248 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'umaal' instruction.
    #[inline]
    fn umaal(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            self.write_u32::<LE>((4194448 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits an 'umlal' instruction.
    #[inline]
    fn umlal(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'umull' instruction.
    #[inline]
    fn umull(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut update_cprs = update_cprs as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqadd16' instruction.
    #[inline]
    fn uqadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958608 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqadd8' instruction.
    #[inline]
    fn uqadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958736 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqaddsubx' instruction.
    #[inline]
    fn uqaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958640 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsub16' instruction.
    #[inline]
    fn uqsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958704 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsub8' instruction.
    #[inline]
    fn uqsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958832 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsubaddx' instruction.
    #[inline]
    fn uqsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((106958672 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usad8' instruction.
    #[inline]
    fn usad8(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((125890576 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usada8' instruction.
    #[inline]
    fn usada8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((125829136 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usat' instruction.
    #[inline]
    fn usat(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((115343376 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usat16' instruction.
    #[inline]
    fn usat16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>(((115347248 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usub16' instruction.
    #[inline]
    fn usub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910128 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usub8' instruction.
    #[inline]
    fn usub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910256 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usubaddx' instruction.
    #[inline]
    fn usubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            self.write_u32::<LE>((((105910096 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtab' instruction.
    #[inline]
    fn uxtab(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtab16' instruction.
    #[inline]
    fn uxtab16(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtah' instruction.
    #[inline]
    fn uxtah(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rn = Into::<u8>::into(rn) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtb' instruction.
    #[inline]
    fn uxtb(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((116326512 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtb16' instruction.
    #[inline]
    fn uxtb16(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((114229360 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxth' instruction.
    #[inline]
    fn uxth(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = Into::<u8>::into(cond) as u32;
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rotate = Into::<u8>::into(rotate) as u32;
            self.write_u32::<LE>((((117375088 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Assembles an instruction, given its opcode and operands.
    ///
    /// # Returns
    /// - `Ok(True)` if the corresponding instruction was assembled.
    /// - `Ok(False)` if the corresponding instruction could not be bound.
    /// - `Err(_)` if the writing operation resulted in an IO error.
    fn assemble(&mut self, opcode: &str, operands: &[&Any]) -> Result<bool> {
        Ok(match opcode {
            "adc" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.adc(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "add" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.add(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "and" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.and(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "b" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.b(*cond)?; true },
                _ => false
            },
            "bic" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.bic(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "bkpt" if operands.len() == 1 => match (operands[0].downcast_ref::<u16>()) {
                (Some(immed)) => { self.bkpt(*immed)?; true },
                _ => false
            },
            "blx" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.blx(*cond)?; true },
                _ => false
            },
            "blxun" if operands.len() == 0 => { self.blxun()?; true },
            "bx" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.bx(*cond)?; true },
                _ => false
            },
            "bxj" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.bxj(*cond)?; true },
                _ => false
            },
            "cdp" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Coprocessor>()) {
                (Some(cond), Some(cpnum)) => { self.cdp(*cond, *cpnum)?; true },
                _ => false
            },
            "clz" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.clz(*cond, *rd)?; true },
                _ => false
            },
            "cmn" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rn)) => { self.cmn(*cond, *rn)?; true },
                _ => false
            },
            "cmp" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rn)) => { self.cmp(*cond, *rn)?; true },
                _ => false
            },
            "cps" if operands.len() == 1 => match (operands[0].downcast_ref::<Mode>()) {
                (Some(mode)) => { self.cps(*mode)?; true },
                _ => false
            },
            "cpsid" if operands.len() == 1 => match (operands[0].downcast_ref::<InterruptFlags>()) {
                (Some(iflags)) => { self.cpsid(*iflags)?; true },
                _ => false
            },
            "cpsid_mode" if operands.len() == 2 => match (operands[0].downcast_ref::<InterruptFlags>(), operands[1].downcast_ref::<Mode>()) {
                (Some(iflags), Some(mode)) => { self.cpsid_mode(*iflags, *mode)?; true },
                _ => false
            },
            "cpsie" if operands.len() == 1 => match (operands[0].downcast_ref::<InterruptFlags>()) {
                (Some(iflags)) => { self.cpsie(*iflags)?; true },
                _ => false
            },
            "cpsie_mode" if operands.len() == 2 => match (operands[0].downcast_ref::<InterruptFlags>(), operands[1].downcast_ref::<Mode>()) {
                (Some(iflags), Some(mode)) => { self.cpsie_mode(*iflags, *mode)?; true },
                _ => false
            },
            "cpy" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.cpy(*cond, *rd)?; true },
                _ => false
            },
            "eor" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.eor(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "ldc" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Coprocessor>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(cpnum), Some(offset_mode), Some(addressing_mode)) => { self.ldc(*cond, *write, *rn, *cpnum, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldm" if operands.len() == 7 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<OffsetMode>(), operands[3].downcast_ref::<Addressing>(), operands[4].downcast_ref::<RegList>(), operands[5].downcast_ref::<bool>(), operands[6].downcast_ref::<bool>()) {
                (Some(cond), Some(rn), Some(offset_mode), Some(addressing_mode), Some(registers), Some(write), Some(copy_spsr)) => { self.ldm(*cond, *rn, *offset_mode, *addressing_mode, *registers, *write, *copy_spsr)?; true },
                _ => false
            },
            "ldr" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldr(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrb" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldrb(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrbt" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<OffsetMode>()) {
                (Some(cond), Some(rn), Some(rd), Some(offset_mode)) => { self.ldrbt(*cond, *rn, *rd, *offset_mode)?; true },
                _ => false
            },
            "ldrd" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldrd(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrex" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.ldrex(*cond, *rn, *rd)?; true },
                _ => false
            },
            "ldrh" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldrh(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrsb" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldrsb(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrsh" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.ldrsh(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ldrt" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<OffsetMode>()) {
                (Some(cond), Some(rn), Some(rd), Some(offset_mode)) => { self.ldrt(*cond, *rn, *rd, *offset_mode)?; true },
                _ => false
            },
            "mcr" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Coprocessor>()) {
                (Some(cond), Some(rd), Some(cpnum)) => { self.mcr(*cond, *rd, *cpnum)?; true },
                _ => false
            },
            "mcrr" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Coprocessor>()) {
                (Some(cond), Some(rn), Some(rd), Some(cpnum)) => { self.mcrr(*cond, *rn, *rd, *cpnum)?; true },
                _ => false
            },
            "mla" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.mla(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "mov" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rd), Some(update_condition)) => { self.mov(*cond, *update_cprs, *rd, *update_condition)?; true },
                _ => false
            },
            "mrc" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Coprocessor>()) {
                (Some(cond), Some(rd), Some(cpnum)) => { self.mrc(*cond, *rd, *cpnum)?; true },
                _ => false
            },
            "mrrc" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Coprocessor>()) {
                (Some(cond), Some(rn), Some(rd), Some(cpnum)) => { self.mrrc(*cond, *rn, *rd, *cpnum)?; true },
                _ => false
            },
            "mrs" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.mrs(*cond, *rd)?; true },
                _ => false
            },
            "msr_imm" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<FieldMask>()) {
                (Some(cond), Some(fieldmask)) => { self.msr_imm(*cond, *fieldmask)?; true },
                _ => false
            },
            "msr_reg" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<FieldMask>()) {
                (Some(cond), Some(fieldmask)) => { self.msr_reg(*cond, *fieldmask)?; true },
                _ => false
            },
            "mul" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rd), Some(update_condition)) => { self.mul(*cond, *update_cprs, *rd, *update_condition)?; true },
                _ => false
            },
            "mvn" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rd), Some(update_condition)) => { self.mvn(*cond, *update_cprs, *rd, *update_condition)?; true },
                _ => false
            },
            "orr" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.orr(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "pkhbt" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.pkhbt(*cond, *rn, *rd)?; true },
                _ => false
            },
            "pkhtb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.pkhtb(*cond, *rn, *rd)?; true },
                _ => false
            },
            "pld" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<OffsetMode>()) {
                (Some(rn), Some(offset_mode)) => { self.pld(*rn, *offset_mode)?; true },
                _ => false
            },
            "qadd" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qadd(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qaddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qaddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qdadd" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qdadd(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qdsub" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qdsub(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qsub" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qsub(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qsub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qsub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qsub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qsub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "qsubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.qsubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "rev" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.rev(*cond, *rd)?; true },
                _ => false
            },
            "rev16" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.rev16(*cond, *rd)?; true },
                _ => false
            },
            "revsh" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.revsh(*cond, *rd)?; true },
                _ => false
            },
            "rfe" if operands.len() == 4 => match (operands[0].downcast_ref::<bool>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<OffsetMode>(), operands[3].downcast_ref::<Addressing>()) {
                (Some(write), Some(rn), Some(offset_mode), Some(addressing_mode)) => { self.rfe(*write, *rn, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "rsb" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.rsb(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "rsc" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.rsc(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "sadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.sadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "sadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.sadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "saddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.saddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "sbc" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.sbc(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "sel" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.sel(*cond, *rn, *rd)?; true },
                _ => false
            },
            "setendbe" if operands.len() == 0 => { self.setendbe()?; true },
            "setendle" if operands.len() == 0 => { self.setendle()?; true },
            "shadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "shadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "shaddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shaddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "shsub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shsub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "shsub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shsub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "shsubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.shsubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlabb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlabb(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlabt" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlabt(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlad" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>()) {
                (Some(cond), Some(exchange), Some(rn), Some(rd)) => { self.smlad(*cond, *exchange, *rn, *rd)?; true },
                _ => false
            },
            "smlal" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(update_condition)) => { self.smlal(*cond, *update_cprs, *update_condition)?; true },
                _ => false
            },
            "smlalbb" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.smlalbb(*cond)?; true },
                _ => false
            },
            "smlalbt" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.smlalbt(*cond)?; true },
                _ => false
            },
            "smlald" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>()) {
                (Some(cond), Some(exchange)) => { self.smlald(*cond, *exchange)?; true },
                _ => false
            },
            "smlaltb" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.smlaltb(*cond)?; true },
                _ => false
            },
            "smlaltt" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.smlaltt(*cond)?; true },
                _ => false
            },
            "smlatb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlatb(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlatt" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlatt(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlawb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlawb(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlawt" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smlawt(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smlsd" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>()) {
                (Some(cond), Some(exchange), Some(rn), Some(rd)) => { self.smlsd(*cond, *exchange, *rn, *rd)?; true },
                _ => false
            },
            "smlsld" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>()) {
                (Some(cond), Some(exchange)) => { self.smlsld(*cond, *exchange)?; true },
                _ => false
            },
            "smmla" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smmla(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smmls" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.smmls(*cond, *rn, *rd)?; true },
                _ => false
            },
            "smmul" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smmul(*cond, *rd)?; true },
                _ => false
            },
            "smuad" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(exchange), Some(rd)) => { self.smuad(*cond, *exchange, *rd)?; true },
                _ => false
            },
            "smulbb" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smulbb(*cond, *rd)?; true },
                _ => false
            },
            "smulbt" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smulbt(*cond, *rd)?; true },
                _ => false
            },
            "smull" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(update_condition)) => { self.smull(*cond, *update_cprs, *update_condition)?; true },
                _ => false
            },
            "smultb" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smultb(*cond, *rd)?; true },
                _ => false
            },
            "smultt" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smultt(*cond, *rd)?; true },
                _ => false
            },
            "smulwb" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smulwb(*cond, *rd)?; true },
                _ => false
            },
            "smulwt" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.smulwt(*cond, *rd)?; true },
                _ => false
            },
            "smusd" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(exchange), Some(rd)) => { self.smusd(*cond, *exchange, *rd)?; true },
                _ => false
            },
            "srs" if operands.len() == 4 => match (operands[0].downcast_ref::<bool>(), operands[1].downcast_ref::<Mode>(), operands[2].downcast_ref::<OffsetMode>(), operands[3].downcast_ref::<Addressing>()) {
                (Some(write), Some(mode), Some(offset_mode), Some(addressing_mode)) => { self.srs(*write, *mode, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "ssat" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.ssat(*cond, *rd)?; true },
                _ => false
            },
            "ssat16" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.ssat16(*cond, *rd)?; true },
                _ => false
            },
            "ssub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.ssub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "ssub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.ssub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "ssubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.ssubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "stc" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Coprocessor>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(cpnum), Some(offset_mode), Some(addressing_mode)) => { self.stc(*cond, *write, *rn, *cpnum, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "stm" if operands.len() == 7 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<OffsetMode>(), operands[3].downcast_ref::<Addressing>(), operands[4].downcast_ref::<RegList>(), operands[5].downcast_ref::<bool>(), operands[6].downcast_ref::<bool>()) {
                (Some(cond), Some(rn), Some(offset_mode), Some(addressing_mode), Some(registers), Some(write), Some(user_mode)) => { self.stm(*cond, *rn, *offset_mode, *addressing_mode, *registers, *write, *user_mode)?; true },
                _ => false
            },
            "str" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.str(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "strb" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.strb(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "strbt" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<OffsetMode>()) {
                (Some(cond), Some(rn), Some(rd), Some(offset_mode)) => { self.strbt(*cond, *rn, *rd, *offset_mode)?; true },
                _ => false
            },
            "strd" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.strd(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "strex" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.strex(*cond, *rn, *rd)?; true },
                _ => false
            },
            "strh" if operands.len() == 6 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<OffsetMode>(), operands[5].downcast_ref::<Addressing>()) {
                (Some(cond), Some(write), Some(rn), Some(rd), Some(offset_mode), Some(addressing_mode)) => { self.strh(*cond, *write, *rn, *rd, *offset_mode, *addressing_mode)?; true },
                _ => false
            },
            "strt" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<OffsetMode>()) {
                (Some(cond), Some(rn), Some(rd), Some(offset_mode)) => { self.strt(*cond, *rn, *rd, *offset_mode)?; true },
                _ => false
            },
            "sub" if operands.len() == 5 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Register>(), operands[4].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(rn), Some(rd), Some(update_condition)) => { self.sub(*cond, *update_cprs, *rn, *rd, *update_condition)?; true },
                _ => false
            },
            "swi" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.swi(*cond)?; true },
                _ => false
            },
            "swp" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.swp(*cond, *rn, *rd)?; true },
                _ => false
            },
            "swpb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.swpb(*cond, *rn, *rd)?; true },
                _ => false
            },
            "sxtab" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.sxtab(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "sxtab16" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.sxtab16(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "sxtah" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.sxtah(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "sxtb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.sxtb(*cond, *rd, *rotate)?; true },
                _ => false
            },
            "sxtb16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.sxtb16(*cond, *rd, *rotate)?; true },
                _ => false
            },
            "sxth" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.sxth(*cond, *rd, *rotate)?; true },
                _ => false
            },
            "teq" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rn)) => { self.teq(*cond, *rn)?; true },
                _ => false
            },
            "tst" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rn)) => { self.tst(*cond, *rn)?; true },
                _ => false
            },
            "uadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uaddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uaddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhaddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhaddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhsub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhsub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhsub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhsub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uhsubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uhsubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "umaal" if operands.len() == 1 => match (operands[0].downcast_ref::<Condition>()) {
                (Some(cond)) => { self.umaal(*cond)?; true },
                _ => false
            },
            "umlal" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(update_condition)) => { self.umlal(*cond, *update_cprs, *update_condition)?; true },
                _ => false
            },
            "umull" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<bool>(), operands[2].downcast_ref::<bool>()) {
                (Some(cond), Some(update_cprs), Some(update_condition)) => { self.umull(*cond, *update_cprs, *update_condition)?; true },
                _ => false
            },
            "uqadd16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqadd16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uqadd8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqadd8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uqaddsubx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqaddsubx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uqsub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqsub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uqsub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqsub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uqsubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.uqsubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "usad8" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.usad8(*cond, *rd)?; true },
                _ => false
            },
            "usada8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.usada8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "usat" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.usat(*cond, *rd)?; true },
                _ => false
            },
            "usat16" if operands.len() == 2 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>()) {
                (Some(cond), Some(rd)) => { self.usat16(*cond, *rd)?; true },
                _ => false
            },
            "usub16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.usub16(*cond, *rn, *rd)?; true },
                _ => false
            },
            "usub8" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.usub8(*cond, *rn, *rd)?; true },
                _ => false
            },
            "usubaddx" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>()) {
                (Some(cond), Some(rn), Some(rd)) => { self.usubaddx(*cond, *rn, *rd)?; true },
                _ => false
            },
            "uxtab" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.uxtab(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "uxtab16" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.uxtab16(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "uxtah" if operands.len() == 4 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rn), Some(rd), Some(rotate)) => { self.uxtah(*cond, *rn, *rd, *rotate)?; true },
                _ => false
            },
            "uxtb" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.uxtb(*cond, *rd, *rotate)?; true },
                _ => false
            },
            "uxtb16" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.uxtb16(*cond, *rd, *rotate)?; true },
                _ => false
            },
            "uxth" if operands.len() == 3 => match (operands[0].downcast_ref::<Condition>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Rotation>()) {
                (Some(cond), Some(rd), Some(rotate)) => { self.uxth(*cond, *rd, *rotate)?; true },
                _ => false
            },
            _ => false
        })
    }
}

/// Implementation of `ArmAssembler` for all `Write` implementations.
impl<W: Write + ?Sized> ArmAssembler for W {}
