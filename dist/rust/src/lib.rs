#[macro_use]
extern crate bitflags;
extern crate byteorder;

mod generated;

pub mod arm {
    pub use generated::arm::*;
}

pub mod x86 {
    pub use generated::x86::*;
}
