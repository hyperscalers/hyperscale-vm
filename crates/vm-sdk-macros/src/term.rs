//! The admissible sub-grammar, and what a local binding can hold.
//!
//! This is the whole trick. The macro never interprets a contract body —
//! it recognises a fixed grammar inside it and refuses everything else. A
//! [`Term`] is an expression the access DSL can express; a [`Slot`] is what
//! the lowering pass knows about a `let`-bound local. Anything that is not
//! a `Term` becomes [`Slot::Opaque`], and an `Opaque` reaching a position
//! where a key is needed is a compile error with a span on it.
//!
//! `Opaque` is not a failure of the analysis, it is the analysis working.
//! A key computed from a state read cannot be declared, because routing
//! runs before execution and never reads state. The macro's job is to say
//! so at the line that did it.

use proc_macro2::TokenStream;
use quote::quote;

/// An expression the DSL admits, in the macro's own IR.
///
/// One-to-one with the subset of `hyperscale_vm_effects::Expr` a body can
/// reach syntactically. Lowered to `hyperscale_vm_sdk` calls rather than to
/// `Expr` literals, so the tracer stays the single implementation of what a
/// declaration means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    /// The n-th positional parameter.
    Arg(u32),
    /// The n-th field of the creation-fixed configuration.
    Config(u32),
    /// The static resource of a bucket parameter.
    ResourceOf(Box<Self>),
    /// A keyed lookup over a configured table.
    Lookup {
        /// The table.
        map: Box<Self>,
        /// The key matched against each pair's first field.
        key: Box<Self>,
    },
    /// A tuple field projection.
    Field(Box<Self>, u32),
    /// An order key packed from a price over a tiebreaker.
    Pack {
        /// The primary sort dimension.
        hi: Box<Self>,
        /// The tiebreaker.
        lo: Box<Self>,
    },
    /// A deterministic fresh id.
    FreshId,
    /// A `u64` literal.
    LitU64(u64),
    /// The element of an enclosing `for`, by absolute nesting depth.
    Binding(usize),
}

impl Term {
    /// Lower to the SDK calls that build the corresponding symbolic value.
    ///
    /// Everything lands at `Opaque`, because these terms are consumed as
    /// child-key material where the DSL is dynamically typed anyway. The
    /// positions that do need a kind — a range bound, a reserve amount —
    /// cast at the use site.
    pub fn emit(&self) -> TokenStream {
        match self {
            Self::Arg(index) => quote!(__t.arg::<::hyperscale_vm_sdk::Opaque>(#index)),
            Self::Config(index) => quote!(__t.config::<::hyperscale_vm_sdk::Opaque>(#index)),
            Self::ResourceOf(inner) => {
                let inner = inner.emit();
                quote!(
                    #inner
                        .cast::<::hyperscale_vm_sdk::Bucket>()
                        .resource()
                        .cast::<::hyperscale_vm_sdk::Opaque>()
                )
            }
            Self::Lookup { map, key } => {
                let map = map.emit();
                let key = key.emit();
                quote!(#map.cast::<::hyperscale_vm_sdk::Seq>().lookup(&#key))
            }
            Self::Field(inner, index) => {
                let inner = inner.emit();
                quote!(#inner.field(#index))
            }
            Self::Pack { hi, lo } => {
                let hi = hi.emit();
                let lo = lo.emit();
                quote!(
                    ::hyperscale_vm_sdk::sym::pack(
                        &#hi.cast::<::hyperscale_vm_sdk::Num>(),
                        &#lo.cast::<::hyperscale_vm_sdk::Num>(),
                    )
                    .cast::<::hyperscale_vm_sdk::Opaque>()
                )
            }
            Self::FreshId => {
                quote!(__t.fresh_id().cast::<::hyperscale_vm_sdk::Opaque>())
            }
            Self::LitU64(value) => quote!(
                ::hyperscale_vm_sdk::sym::lit_u64(#value)
                    .cast::<::hyperscale_vm_sdk::Opaque>()
            ),
            Self::Binding(depth) => {
                // The tracer owns binder identity; the lowering pass names
                // the element by the local it was bound to, and `emit`
                // resolves it to the variable the generated `for_each`
                // closure introduced.
                let ident = binding_ident(*depth);
                quote!(#ident.clone())
            }
        }
    }
}

/// The generated name of the `for-each` element bound at `depth`.
pub fn binding_ident(depth: usize) -> syn::Ident {
    syn::Ident::new(
        &format!("__element_{depth}"),
        proc_macro2::Span::call_site(),
    )
}

/// What the lowering pass knows about a local binding.
#[derive(Clone, Debug)]
pub enum Slot {
    /// A value the DSL can express.
    Value(Term),
    /// An open handle on a declared target; the modes it accumulates are
    /// recorded against the site that opened it.
    Handle(usize),
    /// A value edge held in a local, carrying the named resource.
    Produced(Term),
    /// The locked configuration value; its fields are config slots.
    Config,
    /// Anything else — arithmetic, a state read, a call the macro does not
    /// model. Harmless until it is used as a key.
    Opaque,
}

/// Which access mode one handle operation implies.
///
/// The vocabulary is closed, which is what makes mode derivation sound
/// rather than a guess: there is no way to touch a substate except through
/// one of these, and each names exactly one point of the lattice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// `locked()` — a read of a permanently locked substate.
    Locked,
    /// `get()` — a fresh coherent read.
    Get,
    /// `add()` / `sub()` — a commutative movement.
    Delta,
    /// `reserve(amount)` — a conditional decrement.
    Reserve,
    /// `set()` / `insert()` / `remove()` — an exclusive read-modify-write.
    Set,
}

impl Op {
    /// The operation a method name implies, if it is one of the vocabulary.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "locked" => Some(Self::Locked),
            "get" | "peek" | "count" | "entry" | "order" => Some(Self::Get),
            "add" | "sub" => Some(Self::Delta),
            "reserve" => Some(Self::Reserve),
            "set" | "insert" | "remove" => Some(Self::Set),
            _ => None,
        }
    }
}
