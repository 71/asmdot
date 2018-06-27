extern crate asm;

use asm::arm::*;

#[test]
fn should_encode_single_cps_instruction() {
    let mut buf = Vec::new();

    assert!(buf.cps(Mode::USR).is_ok());

    assert_eq!(buf, b"\x10\x00\x02\xf1");
}
