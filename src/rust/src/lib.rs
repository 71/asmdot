#[macro_use]
extern crate bitflags;

mod generated;

macro_rules! impl_register {
    ( $name: ident ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub(crate) u8);
    };
}

pub mod arm {
    /// Defines the condition for an ARM instruction to be executed.
    /// See ARM Architecture Reference Manual, Table 3-1 for more informations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Condition {
        /// Equal.
        EQ = 0b0000,
        /// Not equal.
        NE = 0b0001,
        /// Unsigned higher or same.
        HS = 0b0010,
        /// Unsigned lower.
        LO = 0b0011,
        /// Minus / negative.
        MI = 0b0100,
        /// Plus / positive or zero.
        PL = 0b0101,
        /// Overflow.
        VS = 0b0110,
        /// No overflow.
        VC = 0b0111,
        /// Unsigned higher.
        HI = 0b1000,
        /// Unsigned lower or same.
        LS = 0b1001,
        /// Signed greater than or equal.
        GE = 0b1010,
        /// Signed less than.
        LT = 0b1011,
        /// Signed greater than.
        GT = 0b1100,
        /// Signed less than or equal.
        LE = 0b1101,
        /// Always (unconditional).
        AL = 0b1110,
        /// Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).
        UN = 0b1111
    }

    impl Condition {
        /// Carry set.
        pub const CS: Condition = Condition::HS;
        /// Carry clear.
        pub const CC: Condition = Condition::LO;
    }

    /// Defines the processor mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Mode {
        /// User mode.
        USR = 0b10000,
        /// FIQ (high-speed data transfer) mode.
        FIQ = 0b10001,
        /// IRQ (general-purpose interrupt handling) mode.
        IRQ = 0b10010,
        /// Supervisor mode.
        SVC = 0b10011,
        /// Abort mode.
        ABT = 0b10111,
        /// Undefined mode.
        UND = 0b11011,
        /// System (privileged) mode.
        SYS = 0b11111
    }

    /// Defines the kind of a shift.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Shift {
        /// Logical shift left.
        LSL = 0b00,
        /// Logical shift right.
        LSR = 0b01,
        /// Arithmetic shift right.
        ASR = 0b10,
        /// Rotate right.
        ROR = 0b11
    }

    impl Shift {
        /// Shifted right by one bit.
        pub const RRX: Shift = Shift::ROR;
    }

    /// Defines the kind of a right rotation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Rotation {
        /// Rotate 8 bits to the right.
        ROR8  = 0b01,
        /// Rotate 16 bits to the right.
        ROR16 = 0b10,
        /// Rotate 24 bits to the right.
        ROR24 = 0b11,
        /// Do not rotate.
        NOP   = 0b00
    }

    bitflags! {
        /// Field mask bits.
        pub struct Field: u8 {
            /// Control field mask bit.
            const C = 0b0001;
            /// Extension field mask bit.
            const X = 0b0010;
            /// Status field mask bit.
            const S = 0b0100;
            /// Flags field mask bit.
            const F = 0b1000;
        }
    }

    bitflags! {
        /// Interrupt flags.
        pub struct InterruptFlags: u8 {
            /// Imprecise data abort bit.
            const A = 0b100;
            /// IRQ interrupt bit.
            const I = 0b010;
            /// FIQ interrupt bit.
            const F = 0b001;
        }
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
