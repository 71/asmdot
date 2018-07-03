//! Fast, minimal and zero-copy assembler for ARM and x86.
#![feature(pattern_parentheses)]

#[macro_use]
extern crate bitflags;
extern crate byteorder;

mod generated;

/// Provides ARM-specific types and the `ArmAssembler` trait, which
/// allows any `Write` struct to assemble ARM instructions.
/// 
/// # Example
/// ```rust
/// use asm::arm::{ArmAssembler, Mode};
/// 
/// let mut buf = Vec::new();
/// 
/// assert!( buf.cps(Mode::USR).is_ok() );
/// assert!( buf.cps(Mode::USR).is_ok() );
/// 
/// assert_eq!(buf, b"\x10\x00\x02\xf1\x10\x00\x02\xf1");
/// ```
pub mod arm {
    pub use generated::arm::*;
}

/// Provides MIPS-specific types and the `MipsAssembler` trait, which
/// allows any `Write` struct to assemble MIPS instructions.
/// 
/// # Example
/// ```rust
/// use asm::mips::{MipsAssembler, Register};
/// 
/// let mut buf = Vec::new();
/// 
/// assert!( buf.li(Register::T1).is_ok() );
/// assert!( buf.li(Register::T2).is_ok() );
/// assert!( buf.addi(Register::T1, Register::T2, 0).is_ok() );
/// 
/// assert_eq!(buf, b"\x05\x00\x0d\x24\x0a\x00\x0e\x24\x00\x00\xcd\x21");
/// ```
pub mod mips {
    pub use generated::mips::*;
}

/// Provides x86-specific types and the `X86Assembler` trait, which
/// allows any `Write` struct to assemble x86 instructions.
/// 
/// # Example
/// ```rust
/// use asm::x86::{X86Assembler, Register32};
/// 
/// let mut buf = Vec::new();
/// 
/// assert!( buf.inc_r32(Register32::EAX).is_ok() );
/// assert!( buf.ret().is_ok() );
/// 
/// assert_eq!( buf, b"\x40\xc3" );
/// ```
pub mod x86 {
    pub use generated::x86::*;
}
