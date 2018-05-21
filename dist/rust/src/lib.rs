#[macro_use]
extern crate bitflags;

mod generated;

pub mod arm {
    pub use generated::arm::*;
}

pub mod x86 {
    pub use generated::x86::*;
}
