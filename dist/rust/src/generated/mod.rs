macro_rules! prefix_adder {
    ( $value: expr ) => (if $value > 7 {
        $value -= 8; 1
    } else {
        0
    })
}

/// Trick to transmute one type at compile-time.
/// 
/// # See also
/// https://github.com/rust-lang/rust/issues/49450
pub(crate) union Transmute<T: Copy, U: Copy> {
    from: T,
    to: U
}

macro_rules! transmute_const {
    ( $value: expr ) => {
        unsafe { super::Transmute { from: $value }.to }
    };
}

pub(crate) mod arm;
pub(crate) mod x86;
