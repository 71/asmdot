use std::mem::transmute;

/// Emits an `inc` instruction.
pub unsafe fn inc_r16(buf: &mut *mut (), operand: Register16) {
    *(*buf as *mut u8) = (102 + prefix_adder!(operand));
    *(&(*buf as usize)) += 1;
    *(*buf as *mut u8) = (64 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits an `inc` instruction.
pub unsafe fn inc_r32(buf: &mut *mut (), operand: Register32) {
    if (operand > 7) {
        *(*buf as *mut u8) = 65;
        *(&(*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (64 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `dec` instruction.
pub unsafe fn dec_r16(buf: &mut *mut (), operand: Register16) {
    *(*buf as *mut u8) = (102 + prefix_adder!(operand));
    *(&(*buf as usize)) += 1;
    *(*buf as *mut u8) = (72 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `dec` instruction.
pub unsafe fn dec_r32(buf: &mut *mut (), operand: Register32) {
    if (operand > 7) {
        *(*buf as *mut u8) = 65;
        *(&(*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (72 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `push` instruction.
pub unsafe fn push_r16(buf: &mut *mut (), operand: Register16) {
    *(*buf as *mut u8) = (102 + prefix_adder!(operand));
    *(&(*buf as usize)) += 1;
    *(*buf as *mut u8) = (80 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `push` instruction.
pub unsafe fn push_r32(buf: &mut *mut (), operand: Register32) {
    if (operand > 7) {
        *(*buf as *mut u8) = 65;
        *(&(*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (80 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r16(buf: &mut *mut (), operand: Register16) {
    *(*buf as *mut u8) = (102 + prefix_adder!(operand));
    *(&(*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r32(buf: &mut *mut (), operand: Register32) {
    if (operand > 7) {
        *(*buf as *mut u8) = 65;
        *(&(*buf as usize)) += 1;
    }
    *(*buf as *mut u8) = (88 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `pop` instruction.
pub unsafe fn pop_r64(buf: &mut *mut (), operand: Register64) {
    *(*buf as *mut u8) = (72 + prefix_adder!(operand));
    *(&(*buf as usize)) += 1;
    *(*buf as *mut u8) = (88 + operand);
    *(&(*buf as usize)) += 1;
}

/// Emits a `pushf` instruction.
pub unsafe fn pushf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 156;
    *(&(*buf as usize)) += 1;
}

/// Emits a `popf` instruction.
pub unsafe fn popf(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 157;
    *(&(*buf as usize)) += 1;
}

/// Emits a `ret` instruction.
pub unsafe fn ret(buf: &mut *mut ()) {
    *(*buf as *mut u8) = 195;
    *(&(*buf as usize)) += 1;
}

