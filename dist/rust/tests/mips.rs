extern crate asm;

use asm::mips::*;

#[test]
fn should_assemble_single_addi_instruction() {
    let mut buf = Vec::new();

    assert!(buf.addi(Register::T1, Register::T2, 0).is_ok());

    assert_eq!(buf, b"\x00\x00\x49\x21");
}
