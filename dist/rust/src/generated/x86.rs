#![allow(unused_imports, unused_parens, unused_mut, unused_unsafe)]
#![allow(non_upper_case_globals, overflowing_literals)]

use ::x86::*;

use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// An x86 8-bits register.
pub struct Register8(pub u8);

impl Into<u8> for Register8 {
    fn into(self) -> u8 { self.0 }
}

impl Register8 {
    pub const AL: Self = Register8(0);
    pub const CL: Self = Register8(1);
    pub const DL: Self = Register8(2);
    pub const BL: Self = Register8(3);
    pub const SPL: Self = Register8(4);
    pub const BPL: Self = Register8(5);
    pub const SIL: Self = Register8(6);
    pub const DIL: Self = Register8(7);
    pub const R8B: Self = Register8(8);
    pub const R9B: Self = Register8(9);
    pub const R10B: Self = Register8(10);
    pub const R11B: Self = Register8(11);
    pub const R12B: Self = Register8(12);
    pub const R13B: Self = Register8(13);
    pub const R14B: Self = Register8(14);
    pub const R15B: Self = Register8(15);
}

/// An x86 16-bits register.
pub struct Register16(pub u8);

impl Into<u8> for Register16 {
    fn into(self) -> u8 { self.0 }
}

impl Register16 {
    pub const AX: Self = Register16(0);
    pub const CX: Self = Register16(1);
    pub const DX: Self = Register16(2);
    pub const BX: Self = Register16(3);
    pub const SP: Self = Register16(4);
    pub const BP: Self = Register16(5);
    pub const SI: Self = Register16(6);
    pub const DI: Self = Register16(7);
    pub const R8W: Self = Register16(8);
    pub const R9W: Self = Register16(9);
    pub const R10W: Self = Register16(10);
    pub const R11W: Self = Register16(11);
    pub const R12W: Self = Register16(12);
    pub const R13W: Self = Register16(13);
    pub const R14W: Self = Register16(14);
    pub const R15W: Self = Register16(15);
}

/// An x86 32-bits register.
pub struct Register32(pub u8);

impl Into<u8> for Register32 {
    fn into(self) -> u8 { self.0 }
}

impl Register32 {
    pub const EAX: Self = Register32(0);
    pub const ECX: Self = Register32(1);
    pub const EDX: Self = Register32(2);
    pub const EBX: Self = Register32(3);
    pub const ESP: Self = Register32(4);
    pub const EBP: Self = Register32(5);
    pub const ESI: Self = Register32(6);
    pub const EDI: Self = Register32(7);
    pub const R8D: Self = Register32(8);
    pub const R9D: Self = Register32(9);
    pub const R10D: Self = Register32(10);
    pub const R11D: Self = Register32(11);
    pub const R12D: Self = Register32(12);
    pub const R13D: Self = Register32(13);
    pub const R14D: Self = Register32(14);
    pub const R15D: Self = Register32(15);
}

/// An x86 64-bits register.
pub struct Register64(pub u8);

impl Into<u8> for Register64 {
    fn into(self) -> u8 { self.0 }
}

impl Register64 {
    pub const RAX: Self = Register64(0);
    pub const RCX: Self = Register64(1);
    pub const RDX: Self = Register64(2);
    pub const RBX: Self = Register64(3);
    pub const RSP: Self = Register64(4);
    pub const RBP: Self = Register64(5);
    pub const RSI: Self = Register64(6);
    pub const RDI: Self = Register64(7);
    pub const R8: Self = Register64(8);
    pub const R9: Self = Register64(9);
    pub const R10: Self = Register64(10);
    pub const R11: Self = Register64(11);
    pub const R12: Self = Register64(12);
    pub const R13: Self = Register64(13);
    pub const R14: Self = Register64(14);
    pub const R15: Self = Register64(15);
}

/// An x86 128-bits register.
pub struct Register128(pub u8);

impl Into<u8> for Register128 {
    fn into(self) -> u8 { self.0 }
}

/// Allows any struct that implements `Write` to assemble X86 instructions.
pub trait X86Assembler: Write {

    /// Emits a 'pushf' instruction.
    #[inline]
    fn pushf(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(156)?;
        }
        Ok(())
    }

    /// Emits a 'popf' instruction.
    #[inline]
    fn popf(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(157)?;
        }
        Ok(())
    }

    /// Emits a 'ret' instruction.
    #[inline]
    fn ret(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(195)?;
        }
        Ok(())
    }

    /// Emits a 'clc' instruction.
    #[inline]
    fn clc(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(248)?;
        }
        Ok(())
    }

    /// Emits a 'stc' instruction.
    #[inline]
    fn stc(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(249)?;
        }
        Ok(())
    }

    /// Emits a 'cli' instruction.
    #[inline]
    fn cli(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(250)?;
        }
        Ok(())
    }

    /// Emits a 'sti' instruction.
    #[inline]
    fn sti(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(251)?;
        }
        Ok(())
    }

    /// Emits a 'cld' instruction.
    #[inline]
    fn cld(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(252)?;
        }
        Ok(())
    }

    /// Emits a 'std' instruction.
    #[inline]
    fn std(&mut self) -> Result<()> {
        unsafe {
            self.write_u8(253)?;
        }
        Ok(())
    }

    /// Emits a 'jo' instruction.
    #[inline]
    fn jo_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(112)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jno' instruction.
    #[inline]
    fn jno_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(113)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jb' instruction.
    #[inline]
    fn jb_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(114)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnae' instruction.
    #[inline]
    fn jnae_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(114)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jc' instruction.
    #[inline]
    fn jc_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(114)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnb' instruction.
    #[inline]
    fn jnb_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(115)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jae' instruction.
    #[inline]
    fn jae_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(115)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnc' instruction.
    #[inline]
    fn jnc_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(115)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jz' instruction.
    #[inline]
    fn jz_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(116)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'je' instruction.
    #[inline]
    fn je_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(116)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnz' instruction.
    #[inline]
    fn jnz_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(117)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jne' instruction.
    #[inline]
    fn jne_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(117)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jbe' instruction.
    #[inline]
    fn jbe_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(118)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jna' instruction.
    #[inline]
    fn jna_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(118)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnbe' instruction.
    #[inline]
    fn jnbe_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(119)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'ja' instruction.
    #[inline]
    fn ja_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(119)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'js' instruction.
    #[inline]
    fn js_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(120)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jns' instruction.
    #[inline]
    fn jns_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(121)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jp' instruction.
    #[inline]
    fn jp_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(122)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jpe' instruction.
    #[inline]
    fn jpe_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(122)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnp' instruction.
    #[inline]
    fn jnp_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(123)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jpo' instruction.
    #[inline]
    fn jpo_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(123)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jl' instruction.
    #[inline]
    fn jl_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(124)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnge' instruction.
    #[inline]
    fn jnge_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(124)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnl' instruction.
    #[inline]
    fn jnl_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(125)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jge' instruction.
    #[inline]
    fn jge_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(125)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jle' instruction.
    #[inline]
    fn jle_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(126)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jng' instruction.
    #[inline]
    fn jng_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(126)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jnle' instruction.
    #[inline]
    fn jnle_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(127)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits a 'jg' instruction.
    #[inline]
    fn jg_imm8(&mut self, operand: i8) -> Result<()> {
        unsafe {
            let mut operand = operand as i8;
            self.write_u8(127)?;
            self.write_i8(operand)?;
        }
        Ok(())
    }

    /// Emits an 'inc' instruction.
    #[inline]
    fn inc_r16(&mut self, operand: Register16) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            self.write_u8((102 + prefix_adder!(operand)))?;
            self.write_u8((64 + operand))?;
        }
        Ok(())
    }

    /// Emits an 'inc' instruction.
    #[inline]
    fn inc_r32(&mut self, operand: Register32) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            if (operand > 7) {
                self.write_u8(65)?;
            }
            self.write_u8((64 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'dec' instruction.
    #[inline]
    fn dec_r16(&mut self, operand: Register16) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            self.write_u8((102 + prefix_adder!(operand)))?;
            self.write_u8((72 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'dec' instruction.
    #[inline]
    fn dec_r32(&mut self, operand: Register32) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            if (operand > 7) {
                self.write_u8(65)?;
            }
            self.write_u8((72 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'push' instruction.
    #[inline]
    fn push_r16(&mut self, operand: Register16) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            self.write_u8((102 + prefix_adder!(operand)))?;
            self.write_u8((80 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'push' instruction.
    #[inline]
    fn push_r32(&mut self, operand: Register32) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            if (operand > 7) {
                self.write_u8(65)?;
            }
            self.write_u8((80 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'pop' instruction.
    #[inline]
    fn pop_r16(&mut self, operand: Register16) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            self.write_u8((102 + prefix_adder!(operand)))?;
            self.write_u8((88 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'pop' instruction.
    #[inline]
    fn pop_r32(&mut self, operand: Register32) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            if (operand > 7) {
                self.write_u8(65)?;
            }
            self.write_u8((88 + operand))?;
        }
        Ok(())
    }

    /// Emits a 'pop' instruction.
    #[inline]
    fn pop_r64(&mut self, operand: Register64) -> Result<()> {
        unsafe {
            let mut operand = Into::<u8>::into(operand) as u8;
            self.write_u8((72 + prefix_adder!(operand)))?;
            self.write_u8((88 + operand))?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 0))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 1))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 2))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 3))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 4))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 5))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 6))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm8_imm8(&mut self, reg: Register8, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(128)?;
            self.write_u8((reg + 7))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 0))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 0))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 0))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 0))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 1))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 1))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 1))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 1))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 2))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 2))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 2))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 2))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 3))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 3))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 3))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 3))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 4))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 4))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 4))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 4))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 5))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 5))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 5))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 5))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 6))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 6))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 6))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 6))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm16_imm16(&mut self, reg: Register16, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 7))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm16_imm32(&mut self, reg: Register16, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(102)?;
            self.write_u8(129)?;
            self.write_u8((reg + 7))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm32_imm16(&mut self, reg: Register32, value: i16) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i16;
            self.write_u8(129)?;
            self.write_u8((reg + 7))?;
            self.write_i16::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm32_imm32(&mut self, reg: Register32, value: i32) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i32;
            self.write_u8(129)?;
            self.write_u8((reg + 7))?;
            self.write_i32::<LE>(value as _)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 0))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'add' instruction.
    #[inline]
    fn add_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 0))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 1))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'or' instruction.
    #[inline]
    fn or_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 1))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 2))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'adc' instruction.
    #[inline]
    fn adc_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 2))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 3))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sbb' instruction.
    #[inline]
    fn sbb_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 3))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 4))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits an 'and' instruction.
    #[inline]
    fn and_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 4))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 5))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'sub' instruction.
    #[inline]
    fn sub_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 5))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 6))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'xor' instruction.
    #[inline]
    fn xor_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 6))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm16_imm8(&mut self, reg: Register16, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(102)?;
            self.write_u8(131)?;
            self.write_u8((reg + 7))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

    /// Emits a 'cmp' instruction.
    #[inline]
    fn cmp_rm32_imm8(&mut self, reg: Register32, value: i8) -> Result<()> {
        unsafe {
            let mut reg = Into::<u8>::into(reg) as u8;
            let mut value = value as i8;
            self.write_u8(131)?;
            self.write_u8((reg + 7))?;
            self.write_i8(value)?;
        }
        Ok(())
    }

}

/// Implementation of `X86Assembler` for all `Write` implementations.
impl<W: Write + ?Sized> X86Assembler for W {}
