Rust
====

## Installation
Simply add this line to your `Cargo.toml` file:

```toml
[dependencies]
asm = { git = "https://github.com/6A/asmdot" }
```

## Usage
```rust
extern crate asm;

use asm::x86::{Register32, X86Assembler};

use std::io;

fn emit_example(buf: &mut io::Write) -> io::Result<()> {
    buf.inc_r32(Register32::EAX)?;
    buf.ret()?;

    Ok(())
}

let mut buf = vec!();

assert!(emit_example(&mut buf) == Ok(()));
assert!(buf.len() == 2);
```
