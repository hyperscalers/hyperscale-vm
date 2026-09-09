//! The boundary a package's guest is generated against.
//!
//! Synthesised rather than authored, from the same walk that fixed the ABI
//! binding: an export's parameter list *is* the binding, so a signature
//! written beside the metadata could only ever repeat it or contradict
//! it. What each parameter is decides the core type it crosses as and
//! how the generated prologue reads it: a scalar as itself, a handle as
//! its index, and every byte-shaped value as the length of an input
//! register the prologue collects.

use proc_macro2::TokenStream;
use quote::quote;

/// What one export parameter is, on both sides of the boundary.
#[derive(Clone, Debug)]
pub enum Shape {
    /// A borrow of the kernel site the clause's mode materialises.
    Handle,
    /// A `u64` the guest reads as it stands.
    Scalar,
    /// A `bool`: the verdict of the guard on a branch's clauses, which
    /// the guest branches on rather than recomputing the condition.
    Flag,
    /// An address, thirty-two bytes through an input register, rebuilt
    /// as an [`Address`] in the export's prologue.
    ///
    /// [`Address`]: hyperscale_vm_sdk::Address
    Address,
    /// A byte list through an input register, decoded into the named
    /// Rust type.
    Cell(Box<syn::Type>),
    /// A list of `u64` through an input register, read at the type the
    /// declaration named it — the ids of an instance set, or a
    /// configured sequence of scalars.
    ///
    /// It crosses as the numbers it is rather than as a framing the
    /// guest would have to decode, which is what separates it from
    /// [`Shape::Cell`]. Two Rust types wear the same wire shape, so the
    /// one the body reads travels with it, as a cell's does.
    Ids(Box<syn::Type>),
    /// A bucket: a value edge the call transfers to the guest, as the
    /// index the kernel holds it at.
    Bucket,
}

impl Shape {
    /// The core type the parameter crosses as: a `u64` as itself, and
    /// everything else — an index, a flag, or a register's length — as
    /// a `u32`.
    pub fn core(&self) -> TokenStream {
        match self {
            Self::Scalar => quote!(u64),
            Self::Handle
            | Self::Flag
            | Self::Address
            | Self::Cell(_)
            | Self::Ids(_)
            | Self::Bucket => quote!(u32),
        }
    }
}
