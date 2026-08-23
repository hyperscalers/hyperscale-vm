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
//! no `Deref`, no arithmetic, no conversion to a primitive. A comparison
//! written in a body is *lowered* — the macro reads it syntactically and
//! builds the term — and a `Sym` that compared at Rust level would instead
//! hand the body a real `bool` to branch on, at which point the trace
//! records whichever side happened to run. Leaving the operators
//! unimplemented turns that from a wrong answer into a type error, and
//! leaves the judgment vocabulary — [`eq`], [`lt`], [`select`] and the
//! rest — as the only way to say one.
//!
//! Kinds are a convenience over a dynamically typed evaluator, not a
//! soundness claim: the evaluator type-checks every term anyway. Where the
//! static kind is genuinely unknown — a tuple projection, a lookup result —
//! the kind is [`Opaque`] and the author says which kind they meant with
//! [`Sym::cast`].

use core::marker::PhantomData;

use hyperscale_vm_effects::{Expr, ParamType, SlotId, Value};

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
pub struct U64;

/// An unsigned 128-bit integer.
///
/// Named for the width and not for what sits at it, because what sits at
/// it varies: an order key, a quantity of a resource, a configured
/// number. A kind here stands for one of the value model's own variants,
/// so it wears that variant's name.
#[derive(Clone, Copy, Debug)]
pub struct U128;

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

/// A judgment — what a predicate evaluates to.
///
/// The one kind with no [`ParamType`], and deliberately: no manifest
/// argument carries a boolean and no export is handed one. A judgment
/// lives in the declaration, where it selects; what reaches a body is
/// the value it selected.
#[derive(Clone, Copy, Debug)]
pub struct Flag;

/// A kind the SDK cannot name statically — a tuple projection or a lookup
/// result. Narrow it with [`Sym::cast`].
#[derive(Clone, Copy, Debug)]
pub struct Opaque;

impl Kind for U64 {
    const NAME: &'static str = "u64";
    const PARAM: Option<ParamType> = Some(ParamType::U64);
}
impl Kind for U128 {
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
impl Kind for Flag {
    const NAME: &'static str = "bool";
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
/// # use hyperscale_vm_sdk::sym::{Sym, U128};
/// fn branch(fee: Sym<U128>, floor: Sym<U128>) {
///     // A judgment is lowered, never evaluated; `Sym` has no `PartialOrd`.
///     if fee > floor {
///         unimplemented!()
///     }
/// }
/// ```
///
/// ```compile_fail
/// # use hyperscale_vm_sdk::sym::{Sym, U128};
/// fn concretize(fee: Sym<U128>) -> u128 {
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

    /// Whether the table holds `key` — the question [`Sym::lookup`]
    /// answers destructively.
    ///
    /// What makes a miss handleable: guarding a lookup on this is what
    /// turns a routing refusal into a default the package chose, and it
    /// works because [`select`] evaluates only the arm it takes.
    #[must_use]
    pub fn contains<K: Kind>(&self, key: &Sym<K>) -> Sym<Flag> {
        Sym::new(Expr::Contains {
            map: Box::new(self.expr.clone()),
            key: Box::new(key.expr.clone()),
        })
    }
}

impl Sym<Addr> {
    /// The canonical child key `owner | H(slot, material…)`.
    ///
    /// Pure computation over the owner and the material, which is what lets
    /// a shard name another shard's key without reading it.
    #[must_use]
    pub fn child(&self, slot: SlotId, material: &[Sym<Opaque>]) -> Sym<Key> {
        Sym::new(Expr::ChildKey {
            owner: Box::new(self.expr.clone()),
            slot,
            material: material.iter().map(|m| m.expr.clone()).collect(),
        })
    }
}

/// A 128-bit order key packed from a primary sort dimension and a
/// tiebreaker.
#[must_use]
pub fn pack(hi: &Sym<U64>, lo: &Sym<U64>) -> Sym<U128> {
    Sym::new(Expr::Pack {
        hi: Box::new(hi.expr.clone()),
        lo: Box::new(lo.expr.clone()),
    })
}

/// A non-fungible edge's projection: the resource, and the instances it
/// carries.
///
/// The one constructor of non-fungible edge content, so a produced edge
/// names the instances that actually left the collection rather than a
/// set the body chose.
#[must_use]
pub fn nf_bucket(resource: &Sym<Addr>, ids: &Sym<Opaque>) -> Sym<Opaque> {
    Sym::new(Expr::NfBucket {
        resource: Box::new(resource.expr.clone()),
        ids: Box::new(ids.expr.clone()),
    })
}

/// The instances a non-fungible edge carries, as a list.
#[must_use]
pub fn ids(bucket: &Sym<Bucket>) -> Sym<Seq> {
    Sym::new(Expr::IdsOf(Box::new(bucket.expr.clone())))
}

/// The length of a list.
///
/// What a move's cap is derived from: the count of the instances an
/// edge carries or an argument names is the walk the move performs.
#[must_use]
pub fn len(list: &Sym<Seq>) -> Sym<U64> {
    Sym::new(Expr::Len(Box::new(list.expr.clone())))
}

/// The sole element of a list — the instance an edge carrying exactly
/// one carries.
///
/// A list of any other length fails the evaluation, so an edge that
/// does not name one instance is refused where the declaration is read
/// rather than where the body reads a cell.
#[must_use]
pub fn only(list: &Sym<Seq>) -> Sym<U64> {
    Sym::new(Expr::Only(Box::new(list.expr.clone())))
}

/// A sum, over the two integer widths and refusing overflow — how a cap
/// covering more than one count is spelled.
#[must_use]
pub fn add<A: Kind, B: Kind>(left: &Sym<A>, right: &Sym<B>) -> Sym<U64> {
    Sym::new(Expr::Add(
        Box::new(left.expr.clone()),
        Box::new(right.expr.clone()),
    ))
}

/// Negation.
#[must_use]
pub fn not(value: &Sym<Flag>) -> Sym<Flag> {
    Sym::new(Expr::Not(Box::new(value.expr.clone())))
}

/// Conjunction, short-circuiting on a false left operand.
#[must_use]
pub fn and(left: &Sym<Flag>, right: &Sym<Flag>) -> Sym<Flag> {
    Sym::new(Expr::And(
        Box::new(left.expr.clone()),
        Box::new(right.expr.clone()),
    ))
}

/// Disjunction, short-circuiting on a true left operand.
#[must_use]
pub fn or(left: &Sym<Flag>, right: &Sym<Flag>) -> Sym<Flag> {
    Sym::new(Expr::Or(
        Box::new(left.expr.clone()),
        Box::new(right.expr.clone()),
    ))
}

/// Structural equality.
///
/// Generic over both kinds for the reason [`Sym::cast`] exists: the DSL's
/// own typing is dynamic where a projection or a lookup lands, and the
/// evaluator refuses a mismatch at routing whatever the static kinds
/// claimed.
#[must_use]
pub fn eq<A: Kind, B: Kind>(left: &Sym<A>, right: &Sym<B>) -> Sym<Flag> {
    Sym::new(Expr::Eq(
        Box::new(left.expr.clone()),
        Box::new(right.expr.clone()),
    ))
}

/// Strict ordering, over the two integer widths.
#[must_use]
pub fn lt<A: Kind, B: Kind>(left: &Sym<A>, right: &Sym<B>) -> Sym<Flag> {
    Sym::new(Expr::Lt(
        Box::new(left.expr.clone()),
        Box::new(right.expr.clone()),
    ))
}

/// Selection between two expressions.
///
/// Only the taken arm is evaluated, which is what lets one arm be an
/// expression the other case would refuse.
#[must_use]
pub fn select<T: Kind, E: Kind>(
    cond: &Sym<Flag>,
    then: &Sym<T>,
    otherwise: &Sym<E>,
) -> Sym<Opaque> {
    Sym::new(Expr::If {
        cond: Box::new(cond.expr.clone()),
        then: Box::new(then.expr.clone()),
        otherwise: Box::new(otherwise.expr.clone()),
    })
}

/// A sequence built element by element.
///
/// What makes a lookup table spellable by the package that owns it: the
/// rows are the package's own text rather than a list a caller supplies,
/// which is the difference between an invariant and a convention.
#[must_use]
pub fn list<K: Kind>(elements: &[Sym<K>]) -> Sym<Seq> {
    Sym::new(Expr::List(
        elements.iter().map(|e| e.expr.clone()).collect(),
    ))
}

/// A fixed-arity product built field by field; a table's row is one.
#[must_use]
pub fn tuple<K: Kind>(fields: &[Sym<K>]) -> Sym<Opaque> {
    Sym::new(Expr::Tuple(fields.iter().map(|f| f.expr.clone()).collect()))
}

/// The target instance's whole creation-fixed record — the bytes its
/// configuration leaf stores, evaluated from what admission resolved the
/// target with rather than from anything a caller supplies.
#[must_use]
pub const fn self_record() -> Sym<Opaque> {
    Sym::new(Expr::SelfRecord)
}

/// A `u64` literal.
#[must_use]
pub const fn lit_u64(value: u64) -> Sym<U64> {
    Sym::new(Expr::Literal(Value::U64(value)))
}

/// A `u128` literal.
#[must_use]
pub const fn lit_u128(value: u128) -> Sym<U128> {
    Sym::new(Expr::Literal(Value::U128(value)))
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
        | Expr::SelfRecord
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. } => 0,
        Expr::Field(inner, _)
        | Expr::ResourceOf(inner)
        | Expr::IdsOf(inner)
        | Expr::Len(inner)
        | Expr::Only(inner)
        | Expr::Not(inner) => expr_depth(inner),
        Expr::Lookup { map, key } | Expr::Contains { map, key } => {
            expr_depth(map).max(expr_depth(key))
        }
        Expr::Pack { hi, lo } => expr_depth(hi).max(expr_depth(lo)),
        Expr::Add(left, right)
        | Expr::And(left, right)
        | Expr::Or(left, right)
        | Expr::Eq(left, right)
        | Expr::Lt(left, right) => expr_depth(left).max(expr_depth(right)),
        Expr::If {
            cond,
            then,
            otherwise,
        } => expr_depth(cond)
            .max(expr_depth(then))
            .max(expr_depth(otherwise)),
        Expr::NfBucket { resource, ids } => expr_depth(resource).max(expr_depth(ids)),
        Expr::List(elements) | Expr::Tuple(elements) => {
            elements.iter().map(expr_depth).max().unwrap_or(0)
        }
        Expr::SelfResource { material, .. } => material.iter().map(expr_depth).max().unwrap_or(0),
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
    use hyperscale_vm_effects::{Expr, SlotId, Value};

    use super::{
        Addr, Bucket, Flag, Kind, Seq, Sym, and, eq, expr_depth, lit_u64, lt, not, or, select,
    };

    #[test]
    fn a_leaf_is_depth_one() {
        assert_eq!(expr_depth(&Expr::SelfAddr), 1);
        assert_eq!(expr_depth(lit_u64(7).expr()), 1);
    }

    #[test]
    fn a_judgment_claims_no_manifest_parameter() {
        // No manifest argument carries a boolean, so the kind declines to
        // claim one and the tracer's parameter check never matches it.
        assert!(Flag::PARAM.is_none());
    }

    #[test]
    fn the_judgment_constructors_build_their_terms() {
        let table: Sym<Seq> = Sym::new(Expr::Config(0));
        let key = lit_u64(7);
        let guarded = select(&table.contains(&key), &table.lookup(&key), &lit_u64(0));
        assert_eq!(
            guarded.expr(),
            &Expr::If {
                cond: Box::new(Expr::Contains {
                    map: Box::new(Expr::Config(0)),
                    key: Box::new(Expr::Literal(Value::U64(7))),
                }),
                then: Box::new(Expr::Lookup {
                    map: Box::new(Expr::Config(0)),
                    key: Box::new(Expr::Literal(Value::U64(7))),
                }),
                otherwise: Box::new(Expr::Literal(Value::U64(0))),
            }
        );
        let one_is_one = Expr::Eq(
            Box::new(Expr::Literal(Value::U64(1))),
            Box::new(Expr::Literal(Value::U64(1))),
        );
        let flag: Sym<Flag> = eq(&lit_u64(1), &lit_u64(1));
        assert_eq!(
            or(&and(&flag, &not(&flag)), &eq(&key, &key)).expr(),
            &Expr::Or(
                Box::new(Expr::And(
                    Box::new(one_is_one.clone()),
                    Box::new(Expr::Not(Box::new(one_is_one))),
                )),
                Box::new(Expr::Eq(
                    Box::new(Expr::Literal(Value::U64(7))),
                    Box::new(Expr::Literal(Value::U64(7))),
                )),
            )
        );
    }

    #[test]
    fn depth_counts_a_judgment_the_way_the_evaluator_does() {
        // Both arms are walked even though only one is evaluated: the
        // bound is on the expression a signature carries, not on the
        // path a call takes through it.
        let shallow = lit_u64(0);
        let deep = lt(&lit_u64(1), &not(&eq(&lit_u64(1), &lit_u64(1))));
        assert_eq!(expr_depth(deep.expr()), 4);
        assert_eq!(
            expr_depth(select(&eq(&lit_u64(1), &lit_u64(1)), &shallow, &deep).expr()),
            5
        );
        assert_eq!(
            expr_depth(select(&eq(&lit_u64(1), &lit_u64(1)), &deep, &shallow).expr()),
            5
        );
    }

    #[test]
    fn depth_follows_the_deepest_subterm() {
        let owner: Sym<Addr> = Sym::new(Expr::SelfAddr);
        let bucket: Sym<Bucket> = Sym::new(Expr::Arg(0));
        // `child(self, [resource(arg0)])` — material is deeper than owner.
        let key = owner.child(SlotId(1), &[bucket.resource().cast()]);
        assert_eq!(expr_depth(key.expr()), 3);
    }
}
