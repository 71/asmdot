mod generated;

macro_rules! impl_register {
    ( $name: ident ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub(crate) u8);
    };
}

pub mod arm {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Condition {
        EQ = 0b0
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Mode {
        EQ = 0b00001
    }

    impl_register!(Register);

    pub use generated::arm::*;
}

pub mod x86 {
    impl_register!(Register8);
    impl_register!(Register16);
    impl_register!(Register32);
    impl_register!(Register64);
    impl_register!(Register128);

    pub use generated::x86::*;
}
