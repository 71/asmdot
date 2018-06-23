#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

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

/// Allows any struct that implements `Write` to assemble Arm instructions.
pub trait ArmAssembler: Write {

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'eor' instruction.
    #[inline]
    fn eor(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'orr' instruction.
    #[inline]
    fn orr(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rsb' instruction.
    #[inline]
    fn rsb(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rsc' instruction.
    #[inline]
    fn rsc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbc' instruction.
    #[inline]
    fn sbc(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bkpt' instruction.
    #[inline]
    fn bkpt(&mut self, immed: u16) -> Result<()> {
        unsafe {
            self.write_u32::<LE>(((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'b' instruction.
    #[inline]
    fn b(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((167772160 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bic' instruction.
    #[inline]
    fn bic(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'blx' instruction.
    #[inline]
    fn blx(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((19922736 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bx' instruction.
    #[inline]
    fn bx(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((19922704 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bxj' instruction.
    #[inline]
    fn bxj(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
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
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((24055568 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmn' instruction.
    #[inline]
    fn cmn(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            self.write_u32::<LE>(((24117248 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            self.write_u32::<LE>(((22020096 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpy' instruction.
    #[inline]
    fn cpy(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((27262976 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cps' instruction.
    #[inline]
    fn cps(&mut self, mode: Mode) -> Result<()> {
        unsafe {
            let mut mode = mode as u32;
            self.write_u32::<LE>((4043440128 | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsie' instruction.
    #[inline]
    fn cpsie(&mut self, iflags: InterruptFlags) -> Result<()> {
        unsafe {
            let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
            self.write_u32::<LE>((4043833344 | (iflags << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsid' instruction.
    #[inline]
    fn cpsid(&mut self, iflags: InterruptFlags) -> Result<()> {
        unsafe {
            let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
            self.write_u32::<LE>((4044095488 | (iflags << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsie_mode' instruction.
    #[inline]
    fn cpsie_mode(&mut self, iflags: InterruptFlags, mode: Mode) -> Result<()> {
        unsafe {
            let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
            let mut mode = mode as u32;
            self.write_u32::<LE>(((4043964416 | (iflags << 6)) | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cpsid_mode' instruction.
    #[inline]
    fn cpsid_mode(&mut self, iflags: InterruptFlags, mode: Mode) -> Result<()> {
        unsafe {
            let mut iflags = mem::transmute::<_, u8>(iflags) as u32;
            let mut mode = mode as u32;
            self.write_u32::<LE>(((4044226560 | (iflags << 6)) | (mode << 0)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldc' instruction.
    #[inline]
    fn ldc(&mut self, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldm' instruction.
    #[inline]
    fn ldm(&mut self, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, copy_spsr: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            let mut registers = mem::transmute::<_, u8>(registers) as u32;
            let mut write = write as u32;
            let mut copy_spsr = copy_spsr as u32;
            //assert!((copy_spsr ^ (write == (registers & 32768))));
            self.write_u32::<LE>(((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldr' instruction.
    #[inline]
    fn ldr(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrb' instruction.
    #[inline]
    fn ldrb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrbt' instruction.
    #[inline]
    fn ldrbt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            self.write_u32::<LE>(((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrd' instruction.
    #[inline]
    fn ldrd(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrex' instruction.
    #[inline]
    fn ldrex(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((26218399 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrh' instruction.
    #[inline]
    fn ldrh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrsb' instruction.
    #[inline]
    fn ldrsb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrsh' instruction.
    #[inline]
    fn ldrsh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ldrt' instruction.
    #[inline]
    fn ldrt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            self.write_u32::<LE>(((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'cdp' instruction.
    #[inline]
    fn cdp(&mut self, cond: Condition, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            self.write_u32::<LE>(((234881024 | cond) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mcr' instruction.
    #[inline]
    fn mcr(&mut self, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            self.write_u32::<LE>((((234881040 | cond) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrc' instruction.
    #[inline]
    fn mrc(&mut self, cond: Condition, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            self.write_u32::<LE>((((235929616 | cond) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mcrr' instruction.
    #[inline]
    fn mcrr(&mut self, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            self.write_u32::<LE>(((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mla' instruction.
    #[inline]
    fn mla(&mut self, cond: Condition, update_cprs: bool, rn: Register, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>((((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mov' instruction.
    #[inline]
    fn mov(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrrc' instruction.
    #[inline]
    fn mrrc(&mut self, cond: Condition, rn: Register, rd: Register, cpnum: Coprocessor) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            self.write_u32::<LE>(((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mrs' instruction.
    #[inline]
    fn mrs(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((17760256 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mul' instruction.
    #[inline]
    fn mul(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mvn' instruction.
    #[inline]
    fn mvn(&mut self, cond: Condition, update_cprs: bool, rd: Register, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut update_cprs = update_cprs as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut update_condition = update_condition as u32;
            self.write_u32::<LE>(((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'msr_imm' instruction.
    #[inline]
    fn msr_imm(&mut self, cond: Condition, fieldmask: FieldMask) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut fieldmask = mem::transmute::<_, u8>(fieldmask) as u32;
            self.write_u32::<LE>(((52490240 | cond) | (fieldmask << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'msr_reg' instruction.
    #[inline]
    fn msr_reg(&mut self, cond: Condition, fieldmask: FieldMask) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut fieldmask = mem::transmute::<_, u8>(fieldmask) as u32;
            self.write_u32::<LE>(((18935808 | cond) | (fieldmask << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pkhbt' instruction.
    #[inline]
    fn pkhbt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((109051920 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pkhtb' instruction.
    #[inline]
    fn pkhtb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((109051984 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'pld' instruction.
    #[inline]
    fn pld(&mut self, rn: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            self.write_u32::<LE>(((4115722240 | (rn << 16)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd' instruction.
    #[inline]
    fn qadd(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777296 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd16' instruction.
    #[inline]
    fn qadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764304 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qadd8' instruction.
    #[inline]
    fn qadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764432 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qaddsubx' instruction.
    #[inline]
    fn qaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764336 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qdadd' instruction.
    #[inline]
    fn qdadd(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((20971600 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qdsub' instruction.
    #[inline]
    fn qdsub(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((23068752 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub' instruction.
    #[inline]
    fn qsub(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((18874448 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub16' instruction.
    #[inline]
    fn qsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764400 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsub8' instruction.
    #[inline]
    fn qsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764528 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'qsubaddx' instruction.
    #[inline]
    fn qsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((102764368 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rev' instruction.
    #[inline]
    fn rev(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((113184560 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rev16' instruction.
    #[inline]
    fn rev16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((113184688 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'revsh' instruction.
    #[inline]
    fn revsh(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((117378992 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'rfe' instruction.
    #[inline]
    fn rfe(&mut self, write: bool, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sadd16' instruction.
    #[inline]
    fn sadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715728 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sadd8' instruction.
    #[inline]
    fn sadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715856 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'saddsubx' instruction.
    #[inline]
    fn saddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715760 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sel' instruction.
    #[inline]
    fn sel(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
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
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103812880 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shadd8' instruction.
    #[inline]
    fn shadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103813008 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shaddsubx' instruction.
    #[inline]
    fn shaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103812912 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsub16' instruction.
    #[inline]
    fn shsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103812976 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsub8' instruction.
    #[inline]
    fn shsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103813104 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'shsubaddx' instruction.
    #[inline]
    fn shsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((103812944 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlabb' instruction.
    #[inline]
    fn smlabb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777344 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlabt' instruction.
    #[inline]
    fn smlabt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777376 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlatb' instruction.
    #[inline]
    fn smlatb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777408 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlatt' instruction.
    #[inline]
    fn smlatt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777440 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlad' instruction.
    #[inline]
    fn smlad(&mut self, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlal' instruction.
    #[inline]
    fn smlal(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
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
            let mut cond = cond as u32;
            self.write_u32::<LE>((20971648 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlalbt' instruction.
    #[inline]
    fn smlalbt(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((20971680 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlaltb' instruction.
    #[inline]
    fn smlaltb(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((20971712 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlaltt' instruction.
    #[inline]
    fn smlaltt(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((20971744 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlald' instruction.
    #[inline]
    fn smlald(&mut self, cond: Condition, exchange: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            self.write_u32::<LE>(((121634832 | cond) | (exchange << 5)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlawb' instruction.
    #[inline]
    fn smlawb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((18874496 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlawt' instruction.
    #[inline]
    fn smlawt(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((18874560 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlsd' instruction.
    #[inline]
    fn smlsd(&mut self, cond: Condition, exchange: bool, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smlsld' instruction.
    #[inline]
    fn smlsld(&mut self, cond: Condition, exchange: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            self.write_u32::<LE>(((121634896 | cond) | (exchange << 5)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmla' instruction.
    #[inline]
    fn smmla(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((122683408 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmls' instruction.
    #[inline]
    fn smmls(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((122683600 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smmul' instruction.
    #[inline]
    fn smmul(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((122744848 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smuad' instruction.
    #[inline]
    fn smuad(&mut self, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((117501968 | cond) | (exchange << 5)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulbb' instruction.
    #[inline]
    fn smulbb(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((23068800 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulbt' instruction.
    #[inline]
    fn smulbt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((23068832 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smultb' instruction.
    #[inline]
    fn smultb(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((23068864 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smultt' instruction.
    #[inline]
    fn smultt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((23068896 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smull' instruction.
    #[inline]
    fn smull(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
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
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((18874528 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smulwt' instruction.
    #[inline]
    fn smulwt(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((18874592 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'smusd' instruction.
    #[inline]
    fn smusd(&mut self, cond: Condition, exchange: bool, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut exchange = exchange as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((117502032 | cond) | (exchange << 5)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'srs' instruction.
    #[inline]
    fn srs(&mut self, write: bool, mode: Mode, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut write = write as u32;
            let mut mode = mode as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssat' instruction.
    #[inline]
    fn ssat(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((105906192 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssat16' instruction.
    #[inline]
    fn ssat16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((111152944 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssub16' instruction.
    #[inline]
    fn ssub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715824 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssub8' instruction.
    #[inline]
    fn ssub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715952 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ssubaddx' instruction.
    #[inline]
    fn ssubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((101715792 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'stc' instruction.
    #[inline]
    fn stc(&mut self, cond: Condition, write: bool, rn: Register, cpnum: Coprocessor, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut cpnum = mem::transmute::<_, u8>(cpnum) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'stm' instruction.
    #[inline]
    fn stm(&mut self, cond: Condition, rn: Register, offset_mode: OffsetMode, addressing_mode: Addressing, registers: Register, write: bool, user_mode: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            let mut registers = mem::transmute::<_, u8>(registers) as u32;
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
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strb' instruction.
    #[inline]
    fn strb(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strbt' instruction.
    #[inline]
    fn strbt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            self.write_u32::<LE>(((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strd' instruction.
    #[inline]
    fn strd(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strex' instruction.
    #[inline]
    fn strex(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((25169808 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strh' instruction.
    #[inline]
    fn strh(&mut self, cond: Condition, write: bool, rn: Register, rd: Register, offset_mode: OffsetMode, addressing_mode: Addressing) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut write = write as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            let mut addressing_mode = mem::transmute::<_, u8>(addressing_mode) as u32;
            self.write_u32::<LE>(((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'strt' instruction.
    #[inline]
    fn strt(&mut self, cond: Condition, rn: Register, rd: Register, offset_mode: OffsetMode) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut offset_mode = mem::transmute::<_, u8>(offset_mode) as u32;
            self.write_u32::<LE>(((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swi' instruction.
    #[inline]
    fn swi(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((251658240 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swp' instruction.
    #[inline]
    fn swp(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((16777360 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'swpb' instruction.
    #[inline]
    fn swpb(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((20971664 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtab' instruction.
    #[inline]
    fn sxtab(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtab16' instruction.
    #[inline]
    fn sxtab16(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtah' instruction.
    #[inline]
    fn sxtah(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtb' instruction.
    #[inline]
    fn sxtb(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((112132208 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxtb16' instruction.
    #[inline]
    fn sxtb16(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((110035056 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sxth' instruction.
    #[inline]
    fn sxth(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((113180784 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'teq' instruction.
    #[inline]
    fn teq(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            self.write_u32::<LE>(((19922944 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tst' instruction.
    #[inline]
    fn tst(&mut self, cond: Condition, rn: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            self.write_u32::<LE>(((17825792 | cond) | (rn << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uadd16' instruction.
    #[inline]
    fn uadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910032 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uadd8' instruction.
    #[inline]
    fn uadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910160 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uaddsubx' instruction.
    #[inline]
    fn uaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910064 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhadd16' instruction.
    #[inline]
    fn uhadd16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007184 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhadd8' instruction.
    #[inline]
    fn uhadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007312 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhaddsubx' instruction.
    #[inline]
    fn uhaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007216 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsub16' instruction.
    #[inline]
    fn uhsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007280 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsub8' instruction.
    #[inline]
    fn uhsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007408 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uhsubaddx' instruction.
    #[inline]
    fn uhsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((108007248 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'umaal' instruction.
    #[inline]
    fn umaal(&mut self, cond: Condition) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            self.write_u32::<LE>((4194448 | cond) as _)?;
        }
        Ok(())
    }

    /// Emits an 'umlal' instruction.
    #[inline]
    fn umlal(&mut self, cond: Condition, update_cprs: bool, update_condition: bool) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
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
            let mut cond = cond as u32;
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
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958608 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqadd8' instruction.
    #[inline]
    fn uqadd8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958736 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqaddsubx' instruction.
    #[inline]
    fn uqaddsubx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958640 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsub16' instruction.
    #[inline]
    fn uqsub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958704 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsub8' instruction.
    #[inline]
    fn uqsub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958832 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uqsubaddx' instruction.
    #[inline]
    fn uqsubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((106958672 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usad8' instruction.
    #[inline]
    fn usad8(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((125890576 | cond) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usada8' instruction.
    #[inline]
    fn usada8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((125829136 | cond) | (rn << 12)) | (rd << 16)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usat' instruction.
    #[inline]
    fn usat(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((115343376 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usat16' instruction.
    #[inline]
    fn usat16(&mut self, cond: Condition, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>(((115347248 | cond) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usub16' instruction.
    #[inline]
    fn usub16(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910128 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usub8' instruction.
    #[inline]
    fn usub8(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910256 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'usubaddx' instruction.
    #[inline]
    fn usubaddx(&mut self, cond: Condition, rn: Register, rd: Register) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            self.write_u32::<LE>((((105910096 | cond) | (rn << 16)) | (rd << 12)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtab' instruction.
    #[inline]
    fn uxtab(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtab16' instruction.
    #[inline]
    fn uxtab16(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtah' instruction.
    #[inline]
    fn uxtah(&mut self, cond: Condition, rn: Register, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rn = mem::transmute::<_, u8>(rn) as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>(((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtb' instruction.
    #[inline]
    fn uxtb(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((116326512 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxtb16' instruction.
    #[inline]
    fn uxtb16(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((114229360 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'uxth' instruction.
    #[inline]
    fn uxth(&mut self, cond: Condition, rd: Register, rotate: Rotation) -> Result<()> {
        unsafe {
            let mut cond = cond as u32;
            let mut rd = mem::transmute::<_, u8>(rd) as u32;
            let mut rotate = mem::transmute::<_, u8>(rotate) as u32;
            self.write_u32::<LE>((((117375088 | cond) | (rd << 12)) | (rotate << 10)) as _)?;
        }
        Ok(())
    }

}

/// Implementation of `ArmAssembler` for all `Write` implementations.
impl<W: Write + ?Sized> ArmAssembler for W {}
