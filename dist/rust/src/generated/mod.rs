macro_rules! prefix_adder {
    ( $value: expr ) => (if $value > 7 {
        $value -= 8; 1
    } else {
        0
    })
}

pub(crate) mod arm;
pub(crate) mod x86;
