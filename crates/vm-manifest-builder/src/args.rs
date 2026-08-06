//! How Rust values become bound node arguments.
//!
//! Scalars and addresses become literals; a [`Bucket`] becomes the edge it
//! stands for, consumed as it binds; a [`Param`] becomes the enclosing
//! intent's yield parameter. [`Value`] is the escape hatch for the literal
//! kinds no plain Rust type maps to — keys, tuples, lists. Both traits are
//! sealed: the set of things that can bind is the signed form's, not the
//! caller's, and growing it is a change to this crate rather than an impl
//! away.

use hyperscale_vm_effects::{Address, GraphArg, Value};

use crate::builder::{Bucket, GraphBuilder, Param};

mod sealed {
    /// The sealing marker for [`Arg`](super::Arg) and
    /// [`Args`](super::Args).
    pub trait Sealed {}
}

/// One value that can bind as a node argument.
pub trait Arg: sealed::Sealed {
    /// Bind into `builder`, consuming any edge the value carries.
    fn bind(self, builder: &mut GraphBuilder) -> GraphArg;
}

impl sealed::Sealed for u64 {}
impl Arg for u64 {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::U64(self))
    }
}

impl sealed::Sealed for u128 {}
impl Arg for u128 {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::U128(self))
    }
}

impl sealed::Sealed for Address {}
impl Arg for Address {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Address(self))
    }
}

impl sealed::Sealed for Vec<u8> {}
impl Arg for Vec<u8> {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self))
    }
}

impl sealed::Sealed for &[u8] {}
impl Arg for &[u8] {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self.to_vec()))
    }
}

impl<const N: usize> sealed::Sealed for &[u8; N] {}
impl<const N: usize> Arg for &[u8; N] {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self.to_vec()))
    }
}

impl sealed::Sealed for Value {}
impl Arg for Value {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Literal(self)
    }
}

impl sealed::Sealed for Bucket {}
impl Arg for Bucket {
    fn bind(self, builder: &mut GraphBuilder) -> GraphArg {
        builder.consume(&self);
        GraphArg::Edge {
            edge: self.edge,
            constraints: self.constraints,
        }
    }
}

impl sealed::Sealed for Param {}
impl Arg for Param {
    fn bind(self, _builder: &mut GraphBuilder) -> GraphArg {
        GraphArg::Param(self.0)
    }
}

/// A tuple of [`Arg`]s, bound in parameter order.
pub trait Args: sealed::Sealed {
    /// Bind every element in order, consuming any edges among them.
    fn bind_all(self, builder: &mut GraphBuilder) -> Vec<GraphArg>;
}

macro_rules! impl_args {
    ($($name:ident)*) => {
        impl<$($name: Arg),*> sealed::Sealed for ($($name,)*) {}
        impl<$($name: Arg),*> Args for ($($name,)*) {
            fn bind_all(self, _builder: &mut GraphBuilder) -> Vec<GraphArg> {
                #[allow(non_snake_case, reason = "one binding per tuple type parameter")]
                let ($($name,)*) = self;
                vec![$($name.bind(_builder)),*]
            }
        }
    };
}

impl_args!();
impl_args!(A);
impl_args!(A B);
impl_args!(A B C);
impl_args!(A B C D);
impl_args!(A B C D E);
impl_args!(A B C D E F);
impl_args!(A B C D E F G);
impl_args!(A B C D E F G H);
