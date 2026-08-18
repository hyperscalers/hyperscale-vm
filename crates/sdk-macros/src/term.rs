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
    /// A deterministic fresh id, by the order its call site appears in the
    /// body.
    ///
    /// The slot the tracer allocates is the tracer's, but one call site is
    /// one id: an entry key derived from a fresh id and the guest
    /// parameter carrying that id have to be the same draw, so the term
    /// names the site rather than re-drawing at every use.
    FreshId(usize),
    /// The order an unordered collection places a key at: the kernel's
    /// hash over the collection's owner, slot and the key.
    OrderKey {
        /// The collection's slot.
        slot: u16,
        /// The logical key.
        key: Box<Self>,
    },
    /// A resource the instance issues, marked apart from its others.
    SelfResource(Vec<u8>),
    /// A non-fungible edge: the resource, and the instances it carries.
    NfBucket {
        /// The resource the edge is denominated in.
        resource: Box<Self>,
        /// The instance ids.
        ids: Box<Self>,
    },
    /// A `u64` literal.
    LitU64(u64),
    /// A `u128` literal — the order-key width, which is where the whole
    /// of an interval's span is spelled.
    LitU128(u128),
    /// The element of an enclosing `for`, by absolute nesting depth.
    Binding(usize),
    /// Negation of a judgment.
    Not(Box<Self>),
    /// Conjunction, short-circuiting on a false left operand.
    And(Box<Self>, Box<Self>),
    /// Disjunction, short-circuiting on a true left operand.
    Or(Box<Self>, Box<Self>),
    /// Structural equality between two values of one kind.
    Eq(Box<Self>, Box<Self>),
    /// Strict ordering, over one integer width.
    Lt(Box<Self>, Box<Self>),
    /// Whether a table holds a key.
    Contains {
        /// The table.
        map: Box<Self>,
        /// The key matched against each pair's first field.
        key: Box<Self>,
    },
    /// Selection between two expressions, evaluating only the taken arm.
    If {
        /// The judgment selecting an arm.
        cond: Box<Self>,
        /// Taken when the condition holds.
        then: Box<Self>,
        /// Taken when it does not.
        otherwise: Box<Self>,
    },
    /// A sequence spelled inline — the rows of a table a package declares
    /// rather than one a caller configures.
    List(Vec<Self>),
    /// A product spelled inline; a table's row is one of these.
    Tuple(Vec<Self>),
}

impl Term {
    /// Whether this evaluates to a judgment rather than to a value.
    ///
    /// What the `if`, `!`, `&&` and `||` spellings are recognised
    /// against: `!` over an integer is a bitwise complement and `if` over
    /// anything but a judgment is control flow, so the recognition asks
    /// the term rather than the syntax.
    pub const fn is_judgment(&self) -> bool {
        matches!(
            self,
            Self::Not(_)
                | Self::And(..)
                | Self::Or(..)
                | Self::Eq(..)
                | Self::Lt(..)
                | Self::Contains { .. }
        )
    }

    /// Lower to the SDK calls that build the corresponding symbolic value.
    ///
    /// Everything lands at `Opaque`, because these terms are consumed as
    /// child-key material where the DSL is dynamically typed anyway. The
    /// positions that do need a kind — a range bound, a reserve amount —
    /// cast at the use site.
    #[allow(clippy::too_many_lines)] // one arm per Term variant
    pub fn emit(&self) -> TokenStream {
        // The two casts the lowering makes that are not `Opaque`: a
        // condition is a judgment, and a table is a sequence.
        let flag = |term: &Self| {
            let term = term.emit();
            quote!(#term.cast::<::hyperscale_vm_sdk::Flag>())
        };
        let opaque = |call: TokenStream| quote!(#call.cast::<::hyperscale_vm_sdk::Opaque>());
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
            Self::FreshId(site) => {
                let ident = fresh_ident(*site);
                quote!(#ident.clone().cast::<::hyperscale_vm_sdk::Opaque>())
            }
            Self::OrderKey { slot, key } => {
                let key = key.emit();
                quote!(
                    __t.order_key(::hyperscale_vm_sdk::SlotId(#slot), &#key)
                        .cast::<::hyperscale_vm_sdk::Opaque>()
                )
            }
            Self::SelfResource(mark) => {
                let mark = syn::LitByteStr::new(mark, proc_macro2::Span::call_site());
                quote!(__t.self_resource(#mark).cast::<::hyperscale_vm_sdk::Opaque>())
            }
            Self::NfBucket { resource, ids } => {
                let resource = resource.emit();
                let ids = ids.emit();
                quote!(
                    ::hyperscale_vm_sdk::sym::nf_bucket(
                        &#resource.cast::<::hyperscale_vm_sdk::Addr>(),
                        &#ids,
                    )
                )
            }
            Self::LitU64(value) => quote!(
                ::hyperscale_vm_sdk::sym::lit_u64(#value)
                    .cast::<::hyperscale_vm_sdk::Opaque>()
            ),
            Self::LitU128(value) => quote!(
                ::hyperscale_vm_sdk::sym::lit_u128(#value)
                    .cast::<::hyperscale_vm_sdk::Opaque>()
            ),
            Self::Not(inner) => {
                let inner = flag(inner);
                opaque(quote!(::hyperscale_vm_sdk::sym::not(&#inner)))
            }
            Self::And(left, right) | Self::Or(left, right) => {
                let call = if matches!(self, Self::Or(..)) {
                    quote!(or)
                } else {
                    quote!(and)
                };
                let (left, right) = (flag(left), flag(right));
                opaque(quote!(::hyperscale_vm_sdk::sym::#call(&#left, &#right)))
            }
            Self::Eq(left, right) | Self::Lt(left, right) => {
                let call = if matches!(self, Self::Lt(..)) {
                    quote!(lt)
                } else {
                    quote!(eq)
                };
                let (left, right) = (left.emit(), right.emit());
                opaque(quote!(::hyperscale_vm_sdk::sym::#call(&#left, &#right)))
            }
            Self::Contains { map, key } => {
                let (map, key) = (map.emit(), key.emit());
                opaque(quote!(#map.cast::<::hyperscale_vm_sdk::Seq>().contains(&#key)))
            }
            Self::If {
                cond,
                then,
                otherwise,
            } => {
                let cond = flag(cond);
                let (then, otherwise) = (then.emit(), otherwise.emit());
                quote!(::hyperscale_vm_sdk::sym::select(&#cond, &#then, &#otherwise))
            }
            Self::List(elements) | Self::Tuple(elements) => {
                let call = if matches!(self, Self::Tuple(_)) {
                    quote!(tuple)
                } else {
                    quote!(list)
                };
                let elements = elements.iter().map(Self::emit);
                quote!(::hyperscale_vm_sdk::sym::#call(&[#(#elements),*]))
            }
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

/// The generated name of the fresh id drawn at the `site`-th `fresh_id()`
/// call in the body.
pub fn fresh_ident(site: usize) -> syn::Ident {
    syn::Ident::new(&format!("__fresh_{site}"), proc_macro2::Span::call_site())
}

/// What the lowering pass knows about a local binding.
#[derive(Clone, Debug)]
pub enum Slot {
    /// A value the DSL can express, held in a guest local.
    Value(Term),
    /// A value the DSL can express, with no guest local behind it: the
    /// `let` that named it emitted nothing, so each use re-derives the
    /// term and an export parameter is bound only where the guest reads
    /// one rather than wherever the declaration does.
    Deferred(Term),
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
/// rather than a guess: there is no way to touch a substate except
/// through one of these. A movement is the one that does not name its
/// own point on the lattice — it commutes where a body only moves value
/// and needs exclusivity where a body also reads the balance, and the
/// body is what says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    /// `locked()` — a read of a permanently locked substate.
    Locked,
    /// `get()` — a fresh coherent read.
    Get,
    /// `put()` / `take()` — value moving into or out of an amount cell.
    ///
    /// One operation for both modes, because both move value and neither
    /// spelling says which: what decides is whether the body also reads
    /// the balance.
    Move,
    /// `reserve(amount)` — a conditional decrement.
    Reserve,
    /// `set()` / `insert()` / `remove()` — an exclusive read-modify-write.
    Set,
    /// `create()` — the same write, on a leaf that must not be there.
    Create,
    /// `existing()` — the same write, on a leaf that must be.
    Existing,
}

impl Op {
    /// The operation a method name implies, if it is one of the vocabulary.
    pub fn from_method(name: &str) -> Option<Self> {
        match name {
            "locked" => Some(Self::Locked),
            "get" | "peek" | "count" | "entry" | "order" | "balance" => Some(Self::Get),
            "put" | "take" | "declared" => Some(Self::Move),
            "reserve" => Some(Self::Reserve),
            "set" | "insert" | "remove" => Some(Self::Set),
            "create" => Some(Self::Create),
            "existing" => Some(Self::Existing),
            _ => None,
        }
    }
}
