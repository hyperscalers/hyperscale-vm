//! How Rust values become bound node arguments.
//!
//! Scalars and addresses become literals; a [`Bucket`] becomes the edge it
//! stands for, carrying its derived resource type; a [`Param`] becomes the enclosing
//! intent's yield parameter. [`Value`] is the escape hatch for the literal
//! kinds no plain Rust type maps to — keys, tuples, lists. Both traits are
//! sealed: the set of things that can bind is the signed form's, not the
//! caller's, and growing it is a change to this crate rather than an impl
//! away.

use hyperscale_vm_effects::{GraphArg, RoleTable, StoredRule, Value};
use hyperscale_vm_types::{
    Address, CallTarget, ComponentAddr, PackageAddr, PrincipalAddr, ResourceAddr,
};

use crate::builder::{Bucket, GraphBuilder, Param};

mod sealed {
    /// The sealing marker for [`Arg`](super::Arg) and
    /// [`Args`](super::Args).
    pub trait Sealed {}
}

/// One value that can bind as a node argument.
pub trait Arg: sealed::Sealed {
    /// Bind against `builder`, whose only say is refusing an edge it did
    /// not mint. Binding does not consume: the edge is spent when the node
    /// carrying it is appended, so a layer that judges bound arguments
    /// before appending can refuse without having spent anything.
    fn bind(self, builder: &GraphBuilder) -> GraphArg;
}

impl sealed::Sealed for u64 {}
impl Arg for u64 {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::U64(self))
    }
}

impl sealed::Sealed for u128 {}
impl Arg for u128 {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::U128(self))
    }
}

impl sealed::Sealed for Address {}
impl Arg for Address {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Address(self))
    }
}

/// An address argument binds whatever class it carries: a method's
/// declared parameter kind is `address`, and which class belongs at a
/// given position is the package's business, not the argument list's. So a
/// typed address binds like an untyped one rather than needing to forget
/// its class first — a class newtype and a position over several of them
/// alike, since a position narrows an address without changing what it is.
macro_rules! address_arg {
    ($($name:ident),+ $(,)?) => {
        $(
            impl sealed::Sealed for $name {}
            impl Arg for $name {
                fn bind(self, _builder: &GraphBuilder) -> GraphArg {
                    GraphArg::Literal(Value::Address(self.address()))
                }
            }
        )+
    };
}

address_arg!(
    PrincipalAddr,
    ComponentAddr,
    PackageAddr,
    ResourceAddr,
    CallTarget,
);

impl sealed::Sealed for Vec<u8> {}
impl Arg for Vec<u8> {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self))
    }
}

impl sealed::Sealed for &[u8] {}
impl Arg for &[u8] {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self.to_vec()))
    }
}

impl<const N: usize> sealed::Sealed for &[u8; N] {}
impl<const N: usize> Arg for &[u8; N] {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(Value::Bytes(self.to_vec()))
    }
}

impl sealed::Sealed for Value {}
impl Arg for Value {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Literal(self)
    }
}

/// A vocabulary value binds as its canonical bytes — the form admission
/// decodes as the vocabulary.
///
/// Binding panics on a value past the vocabulary's own caps, which no
/// admission path would accept; the compose site is where its author
/// can fix it.
macro_rules! canonical_bytes_arg {
    ($($name:ident),+ $(,)?) => {
        $(
            impl sealed::Sealed for $name {}
            impl Arg for $name {
                fn bind(self, _builder: &GraphBuilder) -> GraphArg {
                    GraphArg::Literal(Value::Bytes(
                        self.to_bytes().expect("a value within the caps encodes"),
                    ))
                }
            }
        )+
    };
}

canonical_bytes_arg!(StoredRule, RoleTable);

impl sealed::Sealed for Bucket {}
impl Arg for Bucket {
    fn bind(self, builder: &GraphBuilder) -> GraphArg {
        builder.check(&self);
        self.into_arg()
    }
}

impl sealed::Sealed for Param {}
impl Arg for Param {
    fn bind(self, _builder: &GraphBuilder) -> GraphArg {
        GraphArg::Param(self.0)
    }
}

/// An argument that fills a declared bucket parameter.
///
/// Exactly the two things a bucket position admits: an edge the author
/// holds, and the hole a composition will bind one to. Naming the pair is
/// what lets a wrapper over a method taking funds be called from inside an
/// intent, where the funds arrive from another intent's graph.
pub trait BucketArg: Arg {}

impl BucketArg for Bucket {}
impl BucketArg for Param {}

/// An argument that fills a declared address parameter.
///
/// Every class, and every position over several of them, because a
/// declared parameter kind is `address` and which class belongs at a
/// position is the package's business. A wrapper over such a position
/// therefore widens to this rather than to one class: narrowing to
/// resources would make an address parameter that means a holder
/// unfillable, and widening to [`Arg`] would let a number fill it.
pub trait AddressArg: Arg {}

macro_rules! address_args {
    ($($name:ident),+ $(,)?) => {
        $(impl AddressArg for $name {})+
    };
}

address_args!(
    Address,
    PrincipalAddr,
    ComponentAddr,
    PackageAddr,
    ResourceAddr,
    CallTarget,
);

/// A tuple of [`Arg`]s, bound in parameter order.
pub trait Args: sealed::Sealed {
    /// Bind every element in order.
    fn bind_all(self, builder: &GraphBuilder) -> Vec<GraphArg>;
}

macro_rules! impl_args {
    ($($name:ident)*) => {
        impl<$($name: Arg),*> sealed::Sealed for ($($name,)*) {}
        impl<$($name: Arg),*> Args for ($($name,)*) {
            fn bind_all(self, _builder: &GraphBuilder) -> Vec<GraphArg> {
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
