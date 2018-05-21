#![allow(unused_parens, unused_mut)]
use ::x86::*;

/// An x86 8-bits register.
pub struct Register8(pub u8);

impl Register8 {
    pub const AL: Self = 0;
    pub const CL: Self = 1;
    pub const DL: Self = 2;
    pub const BL: Self = 3;
    pub const SPL: Self = 4;
    pub const BPL: Self = 5;
    pub const SIL: Self = 6;
    pub const DIL: Self = 7;
    pub const R8B: Self = 8;
    pub const R9B: Self = 9;
    pub const R10B: Self = 10;
    pub const R11B: Self = 11;
    pub const R12B: Self = 12;
    pub const R13B: Self = 13;
    pub const R14B: Self = 14;
    pub const R15B: Self = 15;
}

/// An x86 16-bits register.
pub struct Register16(pub u8);

impl Register16 {
    pub const AX: Self = 0;
    pub const CX: Self = 1;
    pub const DX: Self = 2;
    pub const BX: Self = 3;
    pub const SP: Self = 4;
    pub const BP: Self = 5;
    pub const SI: Self = 6;
    pub const DI: Self = 7;
    pub const R8W: Self = 8;
    pub const R9W: Self = 9;
    pub const R10W: Self = 10;
    pub const R11W: Self = 11;
    pub const R12W: Self = 12;
    pub const R13W: Self = 13;
    pub const R14W: Self = 14;
    pub const R15W: Self = 15;
}

/// An x86 32-bits register.
pub struct Register32(pub u8);

impl Register32 {
    pub const EAX: Self = 0;
    pub const ECX: Self = 1;
    pub const EDX: Self = 2;
    pub const EBX: Self = 3;
    pub const ESP: Self = 4;
    pub const EBP: Self = 5;
    pub const ESI: Self = 6;
    pub const EDI: Self = 7;
    pub const R8D: Self = 8;
    pub const R9D: Self = 9;
    pub const R10D: Self = 10;
    pub const R11D: Self = 11;
    pub const R12D: Self = 12;
    pub const R13D: Self = 13;
    pub const R14D: Self = 14;
    pub const R15D: Self = 15;
}

/// An x86 64-bits register.
pub struct Register64(pub u8);

impl Register64 {
    pub const RAX: Self = 0;
    pub const RCX: Self = 1;
    pub const RDX: Self = 2;
    pub const RBX: Self = 3;
    pub const RSP: Self = 4;
    pub const RBP: Self = 5;
    pub const RSI: Self = 6;
    pub const RDI: Self = 7;
    pub const R8: Self = 8;
    pub const R9: Self = 9;
    pub const R10: Self = 10;
    pub const R11: Self = 11;
    pub const R12: Self = 12;
    pub const R13: Self = 13;
    pub const R14: Self = 14;
    pub const R15: Self = 15;
}

/// An x86 128-bits register.
pub struct Register128(pub u8);

/// Emits an 'inc' instruction.
pub unsafe fn inc_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (64 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits an 'inc' instruction.
pub unsafe fn inc_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (64 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'dec' instruction.
pub unsafe fn dec_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (72 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'dec' instruction.
pub unsafe fn dec_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (72 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'push' instruction.
pub unsafe fn push_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (80 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'push' instruction.
pub unsafe fn push_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (80 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'pop' instruction.
pub unsafe fn pop_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'pop' instruction.
pub unsafe fn pop_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'pop' instruction.
pub unsafe fn pop_r64(buf: &mut *mut (), operand: Register64) {
    let Register64(mut operand) = operand;
    *(*buf as *mut u8) = (72 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'pushf' instruction.
pub unsafe fn pushf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 156 as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'popf' instruction.
pub unsafe fn popf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 157 as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a 'ret' instruction.
pub unsafe fn ret(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 195 as _;
    *(&mut (*buf as usize)) += 1;
}

