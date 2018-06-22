#![allow(unused_imports, unused_parens, unused_mut)]
use ::x86::*;

use std::io::{Result, Write};
use std::mem;

use byteorder::{WriteBytesExt, LE};

/// An x86 8-bits register.
pub struct Register8(pub u8);

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

/// Emits an 'inc' instruction.
pub fn inc_r16(buf: &mut Write, operand: Register16) -> Result<()> {
    unsafe {
        let Register16(mut operand) = operand;
        buf.write_u8((102 + prefix_adder!(operand)))?;
        buf.write_u8((64 + operand))?;
    }
    Ok(())
}

/// Emits an 'inc' instruction.
pub fn inc_r32(buf: &mut Write, operand: Register32) -> Result<()> {
    unsafe {
        let Register32(mut operand) = operand;
        if (operand > 7) {
            buf.write_u8(65)?;
        }
        buf.write_u8((64 + operand))?;
    }
    Ok(())
}

/// Emits a 'dec' instruction.
pub fn dec_r16(buf: &mut Write, operand: Register16) -> Result<()> {
    unsafe {
        let Register16(mut operand) = operand;
        buf.write_u8((102 + prefix_adder!(operand)))?;
        buf.write_u8((72 + operand))?;
    }
    Ok(())
}

/// Emits a 'dec' instruction.
pub fn dec_r32(buf: &mut Write, operand: Register32) -> Result<()> {
    unsafe {
        let Register32(mut operand) = operand;
        if (operand > 7) {
            buf.write_u8(65)?;
        }
        buf.write_u8((72 + operand))?;
    }
    Ok(())
}

/// Emits a 'push' instruction.
pub fn push_r16(buf: &mut Write, operand: Register16) -> Result<()> {
    unsafe {
        let Register16(mut operand) = operand;
        buf.write_u8((102 + prefix_adder!(operand)))?;
        buf.write_u8((80 + operand))?;
    }
    Ok(())
}

/// Emits a 'push' instruction.
pub fn push_r32(buf: &mut Write, operand: Register32) -> Result<()> {
    unsafe {
        let Register32(mut operand) = operand;
        if (operand > 7) {
            buf.write_u8(65)?;
        }
        buf.write_u8((80 + operand))?;
    }
    Ok(())
}

/// Emits a 'pop' instruction.
pub fn pop_r16(buf: &mut Write, operand: Register16) -> Result<()> {
    unsafe {
        let Register16(mut operand) = operand;
        buf.write_u8((102 + prefix_adder!(operand)))?;
        buf.write_u8((88 + operand))?;
    }
    Ok(())
}

/// Emits a 'pop' instruction.
pub fn pop_r32(buf: &mut Write, operand: Register32) -> Result<()> {
    unsafe {
        let Register32(mut operand) = operand;
        if (operand > 7) {
            buf.write_u8(65)?;
        }
        buf.write_u8((88 + operand))?;
    }
    Ok(())
}

/// Emits a 'pop' instruction.
pub fn pop_r64(buf: &mut Write, operand: Register64) -> Result<()> {
    unsafe {
        let Register64(mut operand) = operand;
        buf.write_u8((72 + prefix_adder!(operand)))?;
        buf.write_u8((88 + operand))?;
    }
    Ok(())
}

/// Emits a 'pushf' instruction.
pub fn pushf(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u8(156)?;
    }
    Ok(())
}

/// Emits a 'popf' instruction.
pub fn popf(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u8(157)?;
    }
    Ok(())
}

/// Emits a 'ret' instruction.
pub fn ret(buf: &mut Write) -> Result<()> {
    unsafe {
        buf.write_u8(195)?;
    }
    Ok(())
}

