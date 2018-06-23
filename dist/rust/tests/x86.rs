extern crate asm;

use asm::x86::*;

#[test]
fn should_assemble_single_ret_instruction() {
    let mut buf = Vec::new();

    assert!(buf.ret().is_ok());

    assert_eq!(buf, b"\xc3");
}
