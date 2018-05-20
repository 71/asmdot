#![allow(unused_parens, unused_mut)]
use ::x86::*;

/// An x86 8-bits register.
pub struct Register8(pub u8);

/// An x86 16-bits register.
pub struct Register16(pub u8);

/// An x86 32-bits register.
pub struct Register32(pub u8);

/// An x86 64-bits register.
pub struct Register64(pub u8);

/// An x86 128-bits register.
pub struct Register128(pub u8);

/// Emits an `inc` instruction.
pub unsafe fn inc_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (64 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits an `inc` instruction.
pub unsafe fn inc_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (64 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `dec` instruction.
pub unsafe fn dec_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (72 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `dec` instruction.
pub unsafe fn dec_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (72 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `push` instruction.
pub unsafe fn push_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (80 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `push` instruction.
pub unsafe fn push_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (80 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r16(buf: &mut *mut (), operand: Register16) {
    let Register16(mut operand) = operand;
    *(*buf as *mut u8) = (102 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r32(buf: &mut *mut (), operand: Register32) {
    let Register32(mut operand) = operand;
    if (operand > 7) {
        *(*buf as *mut u8) = 65 as _;
        *(&mut (*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r64(buf: &mut *mut (), operand: Register64) {
    let Register64(mut operand) = operand;
    *(*buf as *mut u8) = (72 + prefix_adder!(operand)) as _;
    *(&mut (*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand) as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `pushf` instruction.
pub unsafe fn pushf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 156 as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `popf` instruction.
pub unsafe fn popf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 157 as _;
    *(&mut (*buf as usize)) += 1;
}

/// Emits a `ret` instruction.
pub unsafe fn ret(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 195 as _;
    *(&mut (*buf as usize)) += 1;
}

