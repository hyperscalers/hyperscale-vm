//! An instance's creation-fixed configuration, as a test writes it.
//!
//! The kernel's form is a list of evaluated values in declaration order.
//! A test naming one would spell out a `Value` per slot, so the tuple it
//! would have written anyway is accepted instead — the arity is the
//! configuration's, and a slot that is not expressible as one is a
//! configuration the package could not have declared.

use hyperscale_vm_effects::{Address, ComponentAddr, PrincipalAddr, ResourceAddr, Value};

/// One configuration slot.
pub struct Slot(Value);

impl From<Value> for Slot {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl From<u64> for Slot {
    fn from(value: u64) -> Self {
        Self(Value::U64(value))
    }
}

impl From<u128> for Slot {
    fn from(value: u128) -> Self {
        Self(Value::U128(value))
    }
}

macro_rules! addresses {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Slot {
                fn from(address: $ty) -> Self {
                    Self(Value::Address(address.into()))
                }
            }
        )*
    };
}

addresses!(Address, ComponentAddr, PrincipalAddr, ResourceAddr);

/// What an instance is created under.
pub trait Config {
    /// The slots, in the order the package declares them.
    fn values(self) -> Vec<Value>;
}

impl Config for Vec<Value> {
    fn values(self) -> Vec<Value> {
        self
    }
}

impl Config for () {
    fn values(self) -> Vec<Value> {
        Vec::new()
    }
}

macro_rules! tuples {
    ($(($($name:ident),+),)*) => {
        $(
            #[allow(non_snake_case)] // one binding per tuple position
            impl<$($name: Into<Slot>),+> Config for ($($name,)+) {
                fn values(self) -> Vec<Value> {
                    let ($($name,)+) = self;
                    vec![$($name.into().0),+]
                }
            }
        )*
    };
}

tuples! {
    (A),
    (A, B),
    (A, B, C),
    (A, B, C, D),
    (A, B, C, D, E),
    (A, B, C, D, E, F),
}
