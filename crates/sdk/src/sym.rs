//! Symbolic values: what a method's inputs look like while its declaration
//! is being traced.
//!
//! A [`Sym`] carries an [`Expr`] and a phantom kind. Building one is how
//! the author writes `self.vault(input.resource())` and gets an
//! [`Expr::ChildKey`] out the other end — the declaration reads as ordinary
//! Rust, and the DSL term is the residue.
//!
//! What is *absent* from this type is load-bearing. `Sym` implements
//! `Clone` and `Debug` and nothing else: no `PartialEq`, no `PartialOrd`,
//! no `Deref`, no arithmetic, no conversion to a primitive. The DSL has no
//! conditional — there is no `Expr::If` — so a declaration that branched on
//! an input would be untraceable, and the trace would silently record
//! whichever side ran. Leaving the comparison operators unimplemented turns
//! that from a wrong answer into a type error. Data-dependent selection has
//! a supported spelling: [`Sym::lookup`], which is what the DSL offers in
//! place of a branch.
//!
//! Kinds are a convenience over a dynamically typed evaluator, not a
//! soundness claim: the evaluator type-checks every term anyway. Where the
//! static kind is genuinely unknown — a tuple projection, a lookup result —
//! the kind is [`Opaque`] and the author says which kind they meant with
//! [`Sym::cast`].

use core::marker::PhantomData;

use hyperscale_vm_effects::{Address, Expr, ParamType, RoleId, Value};

/// A symbolic value's static kind.
pub trait Kind {
    /// The kind's name, for trace-time diagnostics.
    const NAME: &'static str;

    /// The declared parameter kind this maps to, where one exists.
    ///
    /// [`Key`] and [`Seq`] are derived rather than bound — no manifest
    /// argument can carry them — and [`Opaque`] declines to claim. The
    /// tracer checks this against the method's declared parameter list, so
    /// a signature whose `params` and whose effect expressions disagree is
    /// a build failure rather than a call that always fails to route.
    const PARAM: Option<ParamType> = None;
}

/// An unsigned 64-bit integer.
#[derive(Clone, Copy, Debug)]
pub struct Num;

/// An unsigned 128-bit integer — the amount width.
#[derive(Clone, Copy, Debug)]
pub struct Amount;

/// Opaque bytes.
#[derive(Clone, Copy, Debug)]
pub struct Blob;

/// A global object's address.
#[derive(Clone, Copy, Debug)]
pub struct Addr;

/// A full substate key.
#[derive(Clone, Copy, Debug)]
pub struct Key;

/// A value edge; its resource type is static, its amount dynamic.
#[derive(Clone, Copy, Debug)]
pub struct Bucket;

/// A bounded homogeneous sequence.
#[derive(Clone, Copy, Debug)]
pub struct Seq;

/// A kind the SDK cannot name statically — a tuple projection or a lookup
/// result. Narrow it with [`Sym::cast`].
#[derive(Clone, Copy, Debug)]
pub struct Opaque;

impl Kind for Num {
    const NAME: &'static str = "u64";
    const PARAM: Option<ParamType> = Some(ParamType::U64);
}
impl Kind for Amount {
    const NAME: &'static str = "u128";
    const PARAM: Option<ParamType> = Some(ParamType::U128);
}
impl Kind for Blob {
    const NAME: &'static str = "bytes";
    const PARAM: Option<ParamType> = Some(ParamType::Bytes);
}
impl Kind for Addr {
    const NAME: &'static str = "address";
    const PARAM: Option<ParamType> = Some(ParamType::Address);
}
impl Kind for Key {
    const NAME: &'static str = "key";
}
impl Kind for Bucket {
    const NAME: &'static str = "bucket";
    const PARAM: Option<ParamType> = Some(ParamType::Bucket);
}
impl Kind for Seq {
    const NAME: &'static str = "list";
}
impl Kind for Opaque {
    const NAME: &'static str = "opaque";
}

/// A symbolic value of kind `K`: an expression over the traced method's
/// inputs.
///
/// Deliberately not comparable and not convertible to a primitive — see the
/// module docs. The two failures that buys are compile errors rather than
/// silent mis-declarations:
///
/// ```compile_fail
/// # use hyperscale_vm_sdk::sym::{Amount, Sym};
/// fn branch(fee: Sym<Amount>, floor: Sym<Amount>) {
///     // The DSL has no conditional; `Sym` has no `PartialOrd`.
///     if fee > floor {
///         unimplemented!()
///     }
/// }
/// ```
///
/// ```compile_fail
/// # use hyperscale_vm_sdk::sym::{Amount, Sym};
/// fn concretize(fee: Sym<Amount>) -> u128 {
///     // A declaration never sees a runtime value; there is no way down.
///     u128::from(fee)
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Sym<K> {
    expr: Expr,
    kind: PhantomData<fn() -> K>,
}

impl<K: Kind> Sym<K> {
    /// Wrap an expression at kind `K`.
    pub(crate) const fn new(expr: Expr) -> Self {
        Self {
            expr,
            kind: PhantomData,
        }
    }

    /// This value's expression, borrowed.
    pub(crate) const fn expr(&self) -> &Expr {
        &self.expr
    }

    /// Reinterpret at another kind.
    ///
    /// The evaluator checks the real kind at routing time, so a wrong cast
    /// is a deterministic rejection of the call rather than an unsound
    /// declaration. Needed wherever the DSL's own typing is dynamic:
    /// [`Sym::field`] and [`Sym::lookup`] both land in [`Opaque`].
    #[must_use]
    pub fn cast<J: Kind>(self) -> Sym<J> {
        Sym::new(self.expr)
    }

    /// The `index`-th field of a tuple.
    #[must_use]
    pub fn field(self, index: u32) -> Sym<Opaque> {
        Sym::new(Expr::Field(Box::new(self.expr), index))
    }
}

impl Sym<Bucket> {
    /// The static resource type this value edge carries.
    ///
    /// The one projection of an edge a declaration may take: the amount is
    /// dynamic and never reaches the DSL.
    #[must_use]
    pub fn resource(&self) -> Sym<Addr> {
        Sym::new(Expr::ResourceOf(Box::new(self.expr.clone())))
    }
}

impl Sym<Seq> {
    /// The value of the first `(key, value)` pair whose key matches.
    ///
    /// The DSL's stand-in for a branch: where a body would test an input
    /// and pick a target, a declaration looks the target up in a table the
    /// instance was configured with.
    #[must_use]
    pub fn lookup<K: Kind>(&self, key: &Sym<K>) -> Sym<Opaque> {
        Sym::new(Expr::Lookup {
            map: Box::new(self.expr.clone()),
            key: Box::new(key.expr.clone()),
        })
    }
}

impl Sym<Addr> {
    /// The canonical child key `owner | H(role, material…)`.
    ///
    /// Pure computation over the owner and the material, which is what lets
    /// a shard name another shard's key without reading it.
    #[must_use]
    pub fn child(&self, role: RoleId, material: &[Sym<Opaque>]) -> Sym<Key> {
        Sym::new(Expr::ChildKey {
            owner: Box::new(self.expr.clone()),
            role,
            material: material.iter().map(|m| m.expr.clone()).collect(),
        })
    }
}

/// A 128-bit order key packed from a primary sort dimension and a
/// tiebreaker.
#[must_use]
pub fn pack(hi: &Sym<Num>, lo: &Sym<Num>) -> Sym<Amount> {
    Sym::new(Expr::Pack {
        hi: Box::new(hi.expr.clone()),
        lo: Box::new(lo.expr.clone()),
    })
}

/// A `u64` literal.
#[must_use]
pub const fn lit_u64(value: u64) -> Sym<Num> {
    Sym::new(Expr::Literal(Value::U64(value)))
}

/// A `u128` literal.
#[must_use]
pub const fn lit_u128(value: u128) -> Sym<Amount> {
    Sym::new(Expr::Literal(Value::U128(value)))
}

/// A byte-string literal.
#[must_use]
pub const fn lit_bytes(value: Vec<u8>) -> Sym<Blob> {
    Sym::new(Expr::Literal(Value::Bytes(value)))
}

/// An address literal.
#[must_use]
pub const fn lit_addr(value: Address) -> Sym<Addr> {
    Sym::new(Expr::Literal(Value::Address(value)))
}

/// The nesting depth of an expression, as [`hyperscale_vm_effects::MAX_EXPR_DEPTH`]
/// counts it: a leaf is depth one, and every constructor adds one over its
/// deepest subterm.
///
/// The evaluator recurses per subterm and rejects past the bound. Computing
/// the same quantity here is what moves a pathological signature from a
/// routing-time rejection — where the contract is already published and
/// every call fails — to a build failure.
#[must_use]
pub fn expr_depth(expr: &Expr) -> usize {
    let sub = match expr {
        Expr::Literal(_)
        | Expr::Arg(_)
        | Expr::Config(_)
        | Expr::Binding(_)
        | Expr::SelfAddr
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. } => 0,
        Expr::Field(inner, _) | Expr::ResourceOf(inner) => expr_depth(inner),
        Expr::Lookup { map, key } => expr_depth(map).max(expr_depth(key)),
        Expr::Pack { hi, lo } => expr_depth(hi).max(expr_depth(lo)),
        Expr::SelfResource { material } => material.iter().map(expr_depth).max().unwrap_or(0),
        Expr::ChildKey {
            owner, material, ..
        }
        | Expr::OrderKey {
            owner, material, ..
        } => material
            .iter()
            .map(expr_depth)
            .fold(expr_depth(owner), usize::max),
    };
    sub + 1
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Expr, RoleId};

    use super::{Addr, Bucket, Sym, expr_depth, lit_u64};

    #[test]
    fn a_leaf_is_depth_one() {
        assert_eq!(expr_depth(&Expr::SelfAddr), 1);
        assert_eq!(expr_depth(lit_u64(7).expr()), 1);
    }

    #[test]
    fn depth_follows_the_deepest_subterm() {
        let owner: Sym<Addr> = Sym::new(Expr::SelfAddr);
        let bucket: Sym<Bucket> = Sym::new(Expr::Arg(0));
        // `child(self, [resource(arg0)])` — material is deeper than owner.
        let key = owner.child(RoleId(1), &[bucket.resource().cast()]);
        assert_eq!(expr_depth(key.expr()), 3);
    }
}
