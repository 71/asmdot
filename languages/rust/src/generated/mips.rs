#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

use ::mips::*;

use std::any::Any;
use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// A Mips register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Register(pub u8);

impl Into<u8> for Register {
    fn into(self) -> u8 { self.0 }
}

impl Register {
    pub const ZERO: Self = Register(0);
    pub const AT: Self = Register(1);
    pub const V0: Self = Register(2);
    pub const V1: Self = Register(3);
    pub const A0: Self = Register(4);
    pub const A1: Self = Register(5);
    pub const A2: Self = Register(6);
    pub const A3: Self = Register(7);
    pub const T0: Self = Register(8);
    pub const T1: Self = Register(9);
    pub const T2: Self = Register(10);
    pub const T3: Self = Register(11);
    pub const T4: Self = Register(12);
    pub const T5: Self = Register(13);
    pub const T6: Self = Register(14);
    pub const T7: Self = Register(15);
    pub const S0: Self = Register(16);
    pub const S1: Self = Register(17);
    pub const S2: Self = Register(18);
    pub const S3: Self = Register(19);
    pub const S4: Self = Register(20);
    pub const S5: Self = Register(21);
    pub const S6: Self = Register(22);
    pub const S7: Self = Register(23);
    pub const T8: Self = Register(24);
    pub const T9: Self = Register(25);
    pub const K0: Self = Register(26);
    pub const K1: Self = Register(27);
    pub const GP: Self = Register(28);
    pub const SP: Self = Register(29);
    pub const FP: Self = Register(30);
    pub const RA: Self = Register(31);
}

/// Allows any struct that implements `Write` to assemble Mips instructions.
pub trait MipsAssembler: Write {

    /// Emits a 'sll' instruction.
    #[inline]
    fn sll(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'movci' instruction.
    #[inline]
    fn movci(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'srl' instruction.
    #[inline]
    fn srl(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sra' instruction.
    #[inline]
    fn sra(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sllv' instruction.
    #[inline]
    fn sllv_r(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'srlv' instruction.
    #[inline]
    fn srlv(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'srav' instruction.
    #[inline]
    fn srav(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'jr' instruction.
    #[inline]
    fn jr(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'jalr' instruction.
    #[inline]
    fn jalr_r(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'movz' instruction.
    #[inline]
    fn movz(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'movn' instruction.
    #[inline]
    fn movn(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'syscall' instruction.
    #[inline]
    fn syscall(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'breakpoint' instruction.
    #[inline]
    fn breakpoint(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sync' instruction.
    #[inline]
    fn sync(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mfhi' instruction.
    #[inline]
    fn mfhi(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mthi' instruction.
    #[inline]
    fn mthi(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mflo' instruction.
    #[inline]
    fn mflo(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsllv' instruction.
    #[inline]
    fn dsllv_r(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsrlv' instruction.
    #[inline]
    fn dsrlv(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsrav' instruction.
    #[inline]
    fn dsrav(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mult' instruction.
    #[inline]
    fn mult(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'multu' instruction.
    #[inline]
    fn multu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'div' instruction.
    #[inline]
    fn div(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'divu' instruction.
    #[inline]
    fn divu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dmult' instruction.
    #[inline]
    fn dmult(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dmultu' instruction.
    #[inline]
    fn dmultu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ddiv' instruction.
    #[inline]
    fn ddiv(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'ddivu' instruction.
    #[inline]
    fn ddivu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'addu' instruction.
    #[inline]
    fn addu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'subu' instruction.
    #[inline]
    fn subu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'nor' instruction.
    #[inline]
    fn nor(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'slt' instruction.
    #[inline]
    fn slt(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sltu' instruction.
    #[inline]
    fn sltu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dadd' instruction.
    #[inline]
    fn dadd(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'daddu' instruction.
    #[inline]
    fn daddu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsub' instruction.
    #[inline]
    fn dsub(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsubu' instruction.
    #[inline]
    fn dsubu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tge' instruction.
    #[inline]
    fn tge(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tgeu' instruction.
    #[inline]
    fn tgeu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tlt' instruction.
    #[inline]
    fn tlt(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tltu' instruction.
    #[inline]
    fn tltu(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'teq' instruction.
    #[inline]
    fn teq(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tne' instruction.
    #[inline]
    fn tne(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsll' instruction.
    #[inline]
    fn dsll(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dslr' instruction.
    #[inline]
    fn dslr(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsra' instruction.
    #[inline]
    fn dsra(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'mhc0' instruction.
    #[inline]
    fn mhc0(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'btlz' instruction.
    #[inline]
    fn btlz(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bgez' instruction.
    #[inline]
    fn bgez(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bltzl' instruction.
    #[inline]
    fn bltzl(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bgezl' instruction.
    #[inline]
    fn bgezl(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sllv' instruction.
    #[inline]
    fn sllv_ri(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tgei' instruction.
    #[inline]
    fn tgei(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'jalr' instruction.
    #[inline]
    fn jalr_ri(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tlti' instruction.
    #[inline]
    fn tlti(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tltiu' instruction.
    #[inline]
    fn tltiu(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'teqi' instruction.
    #[inline]
    fn teqi(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'tnei' instruction.
    #[inline]
    fn tnei(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bltzal' instruction.
    #[inline]
    fn bltzal(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bgezal' instruction.
    #[inline]
    fn bgezal(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bltzall' instruction.
    #[inline]
    fn bltzall(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bgezall' instruction.
    #[inline]
    fn bgezall(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'dsllv' instruction.
    #[inline]
    fn dsllv_ri(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'synci' instruction.
    #[inline]
    fn synci(&mut self, rs: Register, target: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut target = target as u32;
            self.write_u32::<LE>(((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'addi' instruction.
    #[inline]
    fn addi(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'addiu' instruction.
    #[inline]
    fn addiu(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'andi' instruction.
    #[inline]
    fn andi(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'beq' instruction.
    #[inline]
    fn beq(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'blez' instruction.
    #[inline]
    fn blez(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'bne' instruction.
    #[inline]
    fn bne(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'lw' instruction.
    #[inline]
    fn lw(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'lbu' instruction.
    #[inline]
    fn lbu(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'lhu' instruction.
    #[inline]
    fn lhu(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'lui' instruction.
    #[inline]
    fn lui(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits an 'ori' instruction.
    #[inline]
    fn ori(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sb' instruction.
    #[inline]
    fn sb(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sh' instruction.
    #[inline]
    fn sh(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'slti' instruction.
    #[inline]
    fn slti(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sltiu' instruction.
    #[inline]
    fn sltiu(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sw' instruction.
    #[inline]
    fn sw(&mut self, rs: Register, rt: Register, imm: u16) -> Result<()> {
        unsafe {
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut imm = imm as u32;
            self.write_u32::<LE>((((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'j' instruction.
    #[inline]
    fn j(&mut self, address: u32) -> Result<()> {
        unsafe {
            let mut address = address as u32;
            self.write_u32::<LE>((134217728 | ((address >> 2) & 67108863)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'jal' instruction.
    #[inline]
    fn jal(&mut self, address: u32) -> Result<()> {
        unsafe {
            let mut address = address as u32;
            self.write_u32::<LE>((201326592 | ((address >> 2) & 67108863)) as _)?;
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
            "add" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.add(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "addi" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.addi(*rs, *rt, *imm)?; true },
                _ => false
            },
            "addiu" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.addiu(*rs, *rt, *imm)?; true },
                _ => false
            },
            "addu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.addu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "and" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.and(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "andi" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.andi(*rs, *rt, *imm)?; true },
                _ => false
            },
            "beq" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.beq(*rs, *rt, *imm)?; true },
                _ => false
            },
            "bgez" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bgez(*rs, *target)?; true },
                _ => false
            },
            "bgezal" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bgezal(*rs, *target)?; true },
                _ => false
            },
            "bgezall" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bgezall(*rs, *target)?; true },
                _ => false
            },
            "bgezl" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bgezl(*rs, *target)?; true },
                _ => false
            },
            "blez" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.blez(*rs, *rt, *imm)?; true },
                _ => false
            },
            "bltzal" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bltzal(*rs, *target)?; true },
                _ => false
            },
            "bltzall" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bltzall(*rs, *target)?; true },
                _ => false
            },
            "bltzl" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.bltzl(*rs, *target)?; true },
                _ => false
            },
            "bne" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.bne(*rs, *rt, *imm)?; true },
                _ => false
            },
            "breakpoint" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.breakpoint(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "btlz" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.btlz(*rs, *target)?; true },
                _ => false
            },
            "dadd" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dadd(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "daddu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.daddu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "ddiv" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.ddiv(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "ddivu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.ddivu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "div" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.div(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "divu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.divu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dmult" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dmult(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dmultu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dmultu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsll" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsll(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsllv" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsllv_r(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsllv" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.dsllv_ri(*rs, *target)?; true },
                _ => false
            },
            "dslr" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dslr(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsra" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsra(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsrav" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsrav(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsrlv" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsrlv(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsub" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsub(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "dsubu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.dsubu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "j" if operands.len() == 1 => match (operands[0].downcast_ref::<u32>()) {
                (Some(address)) => { self.j(*address)?; true },
                _ => false
            },
            "jal" if operands.len() == 1 => match (operands[0].downcast_ref::<u32>()) {
                (Some(address)) => { self.jal(*address)?; true },
                _ => false
            },
            "jalr" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.jalr_r(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "jalr" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.jalr_ri(*rs, *target)?; true },
                _ => false
            },
            "jr" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.jr(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "lbu" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.lbu(*rs, *rt, *imm)?; true },
                _ => false
            },
            "lhu" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.lhu(*rs, *rt, *imm)?; true },
                _ => false
            },
            "lui" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.lui(*rs, *rt, *imm)?; true },
                _ => false
            },
            "lw" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.lw(*rs, *rt, *imm)?; true },
                _ => false
            },
            "mfhi" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.mfhi(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "mflo" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.mflo(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "mhc0" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.mhc0(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "movci" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.movci(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "movn" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.movn(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "movz" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.movz(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "mthi" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.mthi(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "mult" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.mult(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "multu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.multu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "nor" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.nor(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "or" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.or(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "ori" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.ori(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sb" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.sb(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sh" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.sh(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sll" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sll(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "sllv" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sllv_r(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "sllv" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.sllv_ri(*rs, *target)?; true },
                _ => false
            },
            "slt" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.slt(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "slti" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.slti(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sltiu" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.sltiu(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sltu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sltu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "sra" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sra(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "srav" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.srav(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "srl" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.srl(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "srlv" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.srlv(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "sub" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sub(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "subu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.subu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "sw" if operands.len() == 3 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<u16>()) {
                (Some(rs), Some(rt), Some(imm)) => { self.sw(*rs, *rt, *imm)?; true },
                _ => false
            },
            "sync" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.sync(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "synci" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.synci(*rs, *target)?; true },
                _ => false
            },
            "syscall" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.syscall(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "teq" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.teq(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "teqi" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.teqi(*rs, *target)?; true },
                _ => false
            },
            "tge" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.tge(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "tgei" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.tgei(*rs, *target)?; true },
                _ => false
            },
            "tgeu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.tgeu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "tlt" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.tlt(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "tlti" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.tlti(*rs, *target)?; true },
                _ => false
            },
            "tltiu" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.tltiu(*rs, *target)?; true },
                _ => false
            },
            "tltu" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.tltu(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "tne" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.tne(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            "tnei" if operands.len() == 2 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<u16>()) {
                (Some(rs), Some(target)) => { self.tnei(*rs, *target)?; true },
                _ => false
            },
            "xor" if operands.len() == 4 => match (operands[0].downcast_ref::<Register>(), operands[1].downcast_ref::<Register>(), operands[2].downcast_ref::<Register>(), operands[3].downcast_ref::<u8>()) {
                (Some(rd), Some(rs), Some(rt), Some(shift)) => { self.xor(*rd, *rs, *rt, *shift)?; true },
                _ => false
            },
            _ => false
        })
    }
}

/// Implementation of `MipsAssembler` for all `Write` implementations.
impl<W: Write + ?Sized> MipsAssembler for W {}
