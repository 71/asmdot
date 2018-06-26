#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

use ::mips::*;

use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// A Mips register.
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

    /// Emits an 'add' instruction.
    #[inline]
    fn add(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((32 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((33 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((36 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((26 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((27 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((8 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((16 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((18 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((1073741824 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((24 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((25 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((39 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((38 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((37 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((42 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((43 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
        }
        Ok(())
    }

    /// Emits a 'sll' instruction.
    #[inline]
    fn sll(&mut self, rd: Register, rs: Register, rt: Register, shift: u8) -> Result<()> {
        unsafe {
            let mut rd = Into::<u8>::into(rd) as u32;
            let mut rs = Into::<u8>::into(rs) as u32;
            let mut rt = Into::<u8>::into(rt) as u32;
            let mut shift = shift as u32;
            self.write_u32::<LE>(((((0 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((2 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((3 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((34 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>(((((35 | (rs << 21)) | (rt << 16)) | (rd << 11)) | (shift << 6)) as _)?;
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
            self.write_u32::<LE>((((536870912 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((603979776 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((805306368 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((268435456 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((402653184 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((335544320 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((2415919104 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((2483027968 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((1006632960 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((872415232 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((2684354560 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((2751463424 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((671088640 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((738197504 | (rs << 21)) | (rt << 16)) | imm) as _)?;
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
            self.write_u32::<LE>((((2885681152 | (rs << 21)) | (rt << 16)) | imm) as _)?;
        }
        Ok(())
    }

    /// Emits a 'j' instruction.
    #[inline]
    fn j(&mut self, address: u32) -> Result<()> {
        unsafe {
            let mut address = address as u32;
            self.write_u32::<LE>((2885681152 | (67108863 & (address << 2))) as _)?;
        }
        Ok(())
    }

    /// Emits a 'jal' instruction.
    #[inline]
    fn jal(&mut self, address: u32) -> Result<()> {
        unsafe {
            let mut address = address as u32;
            self.write_u32::<LE>((2885681152 | (67108863 & (address << 2))) as _)?;
        }
        Ok(())
    }

}

/// Implementation of `MipsAssembler` for all `Write` implementations.
impl<W: Write + ?Sized> MipsAssembler for W {}
