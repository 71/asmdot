macro_rules! impl_register {
    ( $name: ident ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(u8);
    };
}

#[allow(unused_parens)]
pub mod arm {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Condition {

    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Mode {

    }

    impl_register!(Register);

    include!("generated/arm.rs");
}

#[allow(unused_parens)]
pub mod x86 {
    impl_register!(Register8);
    impl_register!(Register16);
    impl_register!(Register32);
    impl_register!(Register64);
    impl_register!(Register128);

    macro_rules! prefix_adder {
        ( $value: expr ) => (if $value > 7 {
            $value -= 8; 1
        } else {
            0
        })
    }

    include!("generated/x86.rs");
}
