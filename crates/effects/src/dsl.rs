//! The restricted access DSL and its evaluator.
//!
//! An effect signature is a total function from a method's typed inputs to
//! its declared `(key, mode)` set, written in this DSL: field projections,
//! keyed lookups over input values, canonical-address computation, bounded
//! collection mapping, point and range targets. No loops, no recursion, no
//! reads of state — the evaluator takes arguments, instance configuration,
//! and a hasher, and nothing else, so evaluation is pure by construction
//! and identical on every node.

use hyperscale_hbor::Hbor;

use crate::hash::{Hash32, Hasher};
use crate::manifest::ManifestHash;
use crate::types::{
    Address, CollectionId, EdgeContent, Effect, EffectConflict, EffectSet, EffectTarget, LocalKey,
    MAX_IDS_PER_EDGE, Mode, Presence, RoleId, SubstateKey, Value, child_key, collection_id,
    order_key, resource_address,
};

/// The bound on any collection a `for-each` clause maps over. Keeps
/// signature evaluation O(manifest size) whatever the metadata declares.
pub const MAX_FOREACH_ELEMENTS: usize = 1024;

/// The bound on expression nesting. The evaluator recurses per subterm, so
/// this is what keeps a pathological signature a deterministic rejection
/// rather than a native stack abort.
pub const MAX_EXPR_DEPTH: usize = 32;

/// The bound on `for-each` nesting within one signature.
pub const MAX_CLAUSE_DEPTH: usize = 4;

/// The bound on the work one signature evaluation may do — effects
/// declared and `for-each` iterations alike.
///
/// Width and nesting compose multiplicatively — nested `for-each` clauses
/// at [`MAX_FOREACH_ELEMENTS`] each reach `1024^depth` — so the depth bound
/// alone is not a bound on work. This is, and it counts the iterations
/// rather than only the effects they land: an empty-bodied loop declares
/// nothing yet still runs its list, so an effect count would leave a nest
/// of empty loops unbounded.
pub const MAX_EFFECTS_PER_SIGNATURE: usize = 4096;

/// The bound on a range clause's entry cap.
///
/// The cap is the only part of a declaration that buys execution work
/// rather than key space: an interval's magnitude is what `footprint`
/// charges and what conflict reads, and both are indifferent to how many
/// entries sit inside it. So a cap is what a scan of the interval costs,
/// and an unbounded one would let a signature claim a page no fee prices
/// and no conflict verdict notices.
pub const MAX_RANGE_CAP: u32 = 1024;

/// A child key under the instance the method is running on.
///
/// The shape every package's own storage takes: a package declares
/// against itself, so `self` is the owner of everything it can reach.
#[must_use]
pub fn self_child(role: RoleId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        role,
        material,
    }
}

/// An expression over a method's inputs.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum Expr {
    /// A literal value.
    Literal(Value),
    /// The n-th manifest argument bound to this call.
    Arg(u32),
    /// The n-th field of the target instance's creation-fixed
    /// configuration — a locked substate, readable without a declared
    /// effect.
    Config(u32),
    /// The current `for-each` element; `0` names the innermost binding.
    Binding(u32),
    /// The target instance's own address.
    SelfAddr,
    /// Tuple field projection.
    Field(Box<Self>, u32),
    /// The static resource type of a bucket edge.
    ResourceOf(Box<Self>),
    /// The static id set of a non-fungible bucket edge, as a list.
    IdsOf(Box<Self>),
    /// A list built element by element — the dual of [`Expr::IdsOf`],
    /// for the producing side: a mint's id set is a list of fresh ids,
    /// each an expression of its own.
    List(Vec<Self>),
    /// A fixed-arity product built field by field.
    ///
    /// What names a thing that takes more than one value to name: a
    /// non-fungible badge instance is its resource and its id, and an
    /// authority expression naming one says both. Distinct from
    /// [`Expr::List`] for the reason the values are: a list is a
    /// homogeneous sequence, and these fields are not each other's kind.
    Tuple(Vec<Self>),
    /// A non-fungible bucket projection: the resource and the named
    /// instances an output edge carries.
    ///
    /// The one constructor of non-fungible edge content, so the id-set
    /// discipline is judged here and nowhere else: at most
    /// [`MAX_IDS_PER_EDGE`](crate::types::MAX_IDS_PER_EDGE) ids, each
    /// distinct — a duplicate would be one instance landing twice.
    NfBucket {
        /// The resource the edge carries.
        resource: Box<Self>,
        /// The instance ids; must evaluate to a list of `u64`s.
        ids: Box<Self>,
    },
    /// Keyed lookup over a list of `(key, value)` pair tuples; yields the
    /// value of the first pair whose key matches.
    Lookup {
        /// The list of pairs to search.
        map: Box<Self>,
        /// The key to match against each pair's first field.
        key: Box<Self>,
    },
    /// A resource the target instance mints: the resource address whose
    /// provenance is this instance.
    ///
    /// Derived rather than configured, and deliberately so — an instance's
    /// address commits its configuration, so a configured field naming a
    /// value derived from that address could not be written down. The
    /// material separates the resources one instance issues.
    SelfResource {
        /// The material separating this resource from the instance's
        /// others, canonically encoded into the derivation.
        material: Vec<Self>,
    },
    /// The canonical child key `owner | H(role, material…)`.
    ChildKey {
        /// The owning address.
        owner: Box<Self>,
        /// The child's role under the owner.
        role: RoleId,
        /// The address material, canonically encoded into the hash.
        material: Vec<Self>,
    },
    /// A deterministic fresh 64-bit id, from the transaction identity, the
    /// node index, the frame, and the slot. Slots need be unique only
    /// within one signature: the frame ordinal keeps independently
    /// authored caller and callee slots apart.
    FreshId {
        /// The creation slot within this frame.
        slot: u32,
    },
    /// The key of an object this call creates: a fresh 16-byte local id
    /// under the target instance's own prefix, from the same derivation as
    /// [`Expr::FreshId`].
    FreshKey {
        /// The creation slot within this frame.
        slot: u32,
    },
    /// A 128-bit order key packed from two 64-bit halves.
    Pack {
        /// The high half — the primary sort dimension (a price).
        hi: Box<Self>,
        /// The low half — the tiebreaker (a sequence id).
        lo: Box<Self>,
    },
    /// A 128-bit order key hashed from material: where a logical key lands
    /// in an unordered collection's order space. Salted by the owner and
    /// the collection's role, like [`Expr::ChildKey`], so a ground
    /// collision is confined to the one collection it could hurt.
    OrderKey {
        /// The collection's owner.
        owner: Box<Self>,
        /// The collection's role under the owner.
        role: RoleId,
        /// The logical key, canonically encoded into the hash.
        material: Vec<Self>,
    },
}

impl Expr {
    /// Whether evaluating this reads anything the caller supplies.
    ///
    /// An authority expression must not: an identity a caller names is an
    /// identity that caller can always present, so a method gated on one
    /// reads as guarded and admits everyone.
    #[must_use]
    pub fn reads_call_inputs(&self) -> bool {
        match self {
            Self::Arg(_) | Self::Binding(_) => true,
            Self::Literal(_)
            | Self::Config(_)
            | Self::SelfAddr
            | Self::FreshId { .. }
            | Self::FreshKey { .. } => false,
            Self::Field(inner, _) | Self::ResourceOf(inner) | Self::IdsOf(inner) => {
                inner.reads_call_inputs()
            }
            Self::Lookup { map, key } => map.reads_call_inputs() || key.reads_call_inputs(),
            Self::Pack { hi, lo } => hi.reads_call_inputs() || lo.reads_call_inputs(),
            Self::NfBucket { resource, ids } => {
                resource.reads_call_inputs() || ids.reads_call_inputs()
            }
            Self::List(elements) | Self::Tuple(elements) => {
                elements.iter().any(Self::reads_call_inputs)
            }
            Self::SelfResource { material } => material.iter().any(Self::reads_call_inputs),
            Self::ChildKey {
                owner, material, ..
            }
            | Self::OrderKey {
                owner, material, ..
            } => owner.reads_call_inputs() || material.iter().any(Self::reads_call_inputs),
        }
    }
}

/// A mode with its parameters still unevaluated.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum ModeExpr {
    /// Fresh coherent read.
    Read,
    /// Read of a locked substate; no proof obligation, no participant.
    Locked,
    /// Commutative increment or decrement; no declared amount.
    Delta,
    /// Conditional decrement of the evaluated amount.
    Reserve(Expr),
    /// Exclusive read-modify-write, and what it requires of the leaf.
    ///
    /// The requirement travels with the routed declaration, so every
    /// layer reads it off the signature rather than off a body: a caller
    /// routes on it, a wallet can say "this call creates your authority
    /// cell, and fails if you already have one", and the shard holding
    /// the cell judges it where it already judges a reservation.
    Write {
        /// What the leaf must be. `Either` is what a declaration saying
        /// nothing means.
        requires: Presence,
    },
}

/// An access target expression.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum TargetExpr {
    /// A single substate leaf; the expression must evaluate to a key.
    Point(Expr),
    /// One ordered-collection entry at a computed order key.
    Entry {
        /// The collection's owner.
        owner: Expr,
        /// The collection's role under the owner.
        collection: RoleId,
        /// The material separating this collection from the role's others,
        /// canonically encoded into its identity.
        material: Vec<Expr>,
        /// The entry's order key.
        order: Expr,
    },
    /// A declared interval of a collection's order-key space.
    Range {
        /// The collection's owner.
        owner: Expr,
        /// The collection's role under the owner.
        collection: RoleId,
        /// The material separating this collection from the role's others,
        /// canonically encoded into its identity.
        material: Vec<Expr>,
        /// Inclusive lower bound.
        lo: Expr,
        /// Inclusive upper bound.
        hi: Expr,
        /// The maximum entries execution may touch.
        cap: u32,
    },
}

/// One clause of an effect signature.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[allow(clippy::large_enum_variant)] // an access carries a target; a loop carries none
pub enum Clause {
    /// A single declared access.
    Effect {
        /// What is accessed.
        target: TargetExpr,
        /// How it is accessed.
        mode: ModeExpr,
        /// The resource the accessed cell holds, where it holds value.
        ///
        /// Carried on the clause rather than derived from the key, because
        /// a key is a hash and nothing inverts it — which is what left the
        /// kernel unable to say which resource a movement moved. Stated
        /// here, it reaches execution, where value crossing between two
        /// resources stops being expressible even by a package whose
        /// metadata was authored to allow it.
        ///
        /// Boxed because most clauses carry none, and an inline
        /// expression would widen every clause in the tree to the size of
        /// the rare one that does.
        denomination: Option<Box<Expr>>,
    },
    /// One access set per element of a bounded input collection; inside
    /// the body, the element is the innermost [`Expr::Binding`].
    ForEach {
        /// The collection to map over; must evaluate to a list.
        list: Expr,
        /// The clauses evaluated per element.
        body: Vec<Self>,
    },
}

/// Why signature evaluation rejected its inputs. Deterministic: the same
/// signature over the same inputs fails identically on every node.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    /// An argument index past the bound inputs.
    #[error("argument {0} out of range")]
    ArgOutOfRange(u32),
    /// A configuration index past the instance's configuration.
    #[error("configuration field {0} out of range")]
    ConfigOutOfRange(u32),
    /// A binding index with no enclosing `for-each`.
    #[error("binding {0} out of range")]
    BindingOutOfRange(u32),
    /// A value of the wrong kind.
    #[error("expected {expected}, found {found}")]
    TypeMismatch {
        /// The kind the expression required.
        expected: &'static str,
        /// The kind the value had.
        found: &'static str,
    },
    /// A tuple projection past the tuple's arity.
    #[error("tuple field {index} out of range (arity {arity})")]
    FieldOutOfRange {
        /// The projected index.
        index: u32,
        /// The tuple's arity.
        arity: usize,
    },
    /// A lookup key matching no pair.
    #[error("lookup key not present")]
    LookupMiss,
    /// A lookup list element that is not a `(key, value)` pair.
    #[error("lookup list element is not a pair")]
    LookupNotPairs,
    /// A `for-each` collection past [`MAX_FOREACH_ELEMENTS`].
    #[error("for-each over {len} elements exceeds the {MAX_FOREACH_ELEMENTS} bound")]
    ForEachTooLong {
        /// The collection's length.
        len: usize,
    },
    /// An expression nested past [`MAX_EXPR_DEPTH`].
    #[error("expression nests deeper than {MAX_EXPR_DEPTH}")]
    ExpressionTooDeep,
    /// `for-each` clauses nested past [`MAX_CLAUSE_DEPTH`].
    #[error("for-each clauses nest deeper than {MAX_CLAUSE_DEPTH}")]
    ClausesTooDeep,
    /// A signature whose evaluation exceeds [`MAX_EFFECTS_PER_SIGNATURE`]
    /// units of work — effects declared plus `for-each` iterations, since
    /// an empty-bodied loop declares nothing yet still iterates.
    #[error("signature evaluation exceeds {MAX_EFFECTS_PER_SIGNATURE} effects or iterations")]
    TooManyEffects,
    /// A range whose lower bound exceeds its upper bound.
    #[error("range bounds inverted: lo > hi")]
    InvalidRange,
    /// An id set past the per-edge cap.
    #[error("{len} instance ids exceed the {MAX_IDS_PER_EDGE} per-edge cap")]
    TooManyIds {
        /// The set's length.
        len: usize,
    },
    /// An id named twice in one set — one instance landing twice off a
    /// single edge.
    #[error("instance id {id} appears twice in one id set")]
    DuplicateId {
        /// The repeated id.
        id: u64,
    },
    /// Folded reserve amounts overflowing `u128`.
    #[error("declared reserve amounts overflow")]
    ReserveOverflow,
    /// Two writes on one cell requiring opposite presences.
    #[error("two writes on one cell require opposite presences")]
    PresenceConflict,
}

impl From<EffectConflict> for EvalError {
    fn from(conflict: EffectConflict) -> Self {
        match conflict {
            EffectConflict::ReserveOverflow => Self::ReserveOverflow,
            EffectConflict::Presence => Self::PresenceConflict,
        }
    }
}

/// Everything a signature evaluates over. Note what is absent: state.
#[derive(Clone, Copy, Debug)]
pub struct EvalInputs<'a> {
    /// The target instance's own address.
    pub self_addr: Address,
    /// The call's bound arguments, in parameter order.
    pub args: &'a [Value],
    /// The target instance's creation-fixed configuration.
    pub config: &'a [Value],
    /// The invoking manifest node's index; namespaces fresh IDs.
    pub node_index: u32,
    /// The frame's position under its node. A node evaluates one frame,
    /// so this is zero; it stays in the fresh-ID preimage because that
    /// derivation is what an object's address commits to.
    pub frame: u32,
    /// The transaction's identity — the signed graph's hash; the one root
    /// of every fresh-ID derivation.
    pub identity: ManifestHash,
}

const DOMAIN_FRESH: &[u8] = b"hyperscale-vm/fresh-id";

fn fresh_digest(
    hasher: &dyn Hasher,
    identity: ManifestHash,
    node_index: u32,
    frame: u32,
    slot: u32,
) -> Hash32 {
    hasher.hash(
        DOMAIN_FRESH,
        &[
            &identity.0.0,
            &node_index.to_le_bytes(),
            &frame.to_le_bytes(),
            &slot.to_le_bytes(),
        ],
    )
}

/// The deterministic fresh 64-bit id for `(transaction, node, frame,
/// slot)`.
///
/// This is the value [`Expr::FreshId`] evaluates to; the kernel derives
/// created-object ids from the same root, so declaration and execution
/// agree on every fresh key.
#[must_use]
pub fn fresh_id(
    hasher: &dyn Hasher,
    identity: ManifestHash,
    node_index: u32,
    frame: u32,
    slot: u32,
) -> u64 {
    let digest = fresh_digest(hasher, identity, node_index, frame, slot);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.0[..8]);
    u64::from_le_bytes(bytes)
}

/// The deterministic fresh local key for `(transaction, node, frame,
/// slot)` — the local half [`Expr::FreshKey`] places under the creating
/// instance's prefix.
#[must_use]
pub fn fresh_local(
    hasher: &dyn Hasher,
    identity: ManifestHash,
    node_index: u32,
    frame: u32,
    slot: u32,
) -> LocalKey {
    let digest = fresh_digest(hasher, identity, node_index, frame, slot);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    LocalKey(bytes)
}

/// Evaluate a signature's clauses to its declared effect set.
///
/// # Errors
///
/// Any [`EvalError`]; verdicts are deterministic and identical on every
/// node.
pub fn evaluate_effects(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
) -> Result<EffectSet, EvalError> {
    Ok(evaluate_declaration(clauses, inputs, hasher)?.set)
}

/// A signature evaluation's two views of the same declaration.
///
/// They are not interchangeable, and which one a consumer wants is
/// decided by whether it cares about *what* is accessed or about *the
/// order the author wrote it in*.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declaration {
    /// The declared accesses folded into a set: deduplicated, canonically
    /// ordered by `(target, mode)`, reserve amounts on one target summed.
    ///
    /// This is what routing, conflict grouping, provisioning, and
    /// footprint pricing read. Folding is load-bearing for all four — two
    /// reservations on one cell must be judged against their sum, not
    /// separately.
    pub set: EffectSet,
    /// The same accesses in clause-evaluation order, one entry per clause
    /// the evaluation reached, `for-each` bodies expanded in place.
    ///
    /// This is what capability materialization reads, because a handle's
    /// rep is its index into the materialized table and the guest's
    /// parameters are positional. Set order cannot serve: it is a
    /// comparison over hash-derived keys, so it is stable but arbitrary,
    /// and folding makes its *length* depend on whether two clauses
    /// happened to evaluate to one target.
    pub ordered: Vec<Effect>,
    /// The resource each entry of [`Declaration::ordered`] holds, where it
    /// holds value, aligned index for index with it.
    ///
    /// Parallel rather than folded into [`Effect`] because an effect is
    /// what the set is keyed by: two accesses on one cell are one target
    /// whatever else is true of them, and a denomination riding the key
    /// would split them. Aligned with `ordered` because a capability's rep
    /// is its index there, which is the one place a movement can ask what
    /// the cell it is moving into holds.
    pub denominations: Vec<Option<Address>>,
    /// Where each top-level clause's effects sit in [`Declaration::ordered`],
    /// as `(start, len)` pairs in clause order.
    ///
    /// A clause contributes one entry unless it is a `for-each`, which
    /// expands in place — so the flattened order alone cannot say which
    /// entry a given clause produced. An ABI binding names a clause, not
    /// a table position, precisely so a guest's parameter list stays a
    /// function of its own signature rather than of the instance
    /// configuration a `for-each` maps over; resolving that name is what
    /// these spans are for, and it succeeds only where the span is one.
    ///
    /// Populated by one signature's evaluation, which is the only scope a
    /// clause index means anything in. A declaration assembled by
    /// concatenating frames leaves it empty: the ABI binding is a
    /// method's, so the walk resolves it against that method's frame.
    pub clause_spans: Vec<(u32, u32)>,
}

impl Declaration {
    /// Both views from a set alone, taking canonical order as the clause
    /// order.
    ///
    /// For callers that genuinely have no clause order — hand-authored
    /// fixtures and tests. A production path that evaluates a signature
    /// has the clause order and must use [`evaluate_declaration`]:
    /// reconstructing it from the set here would reintroduce exactly the
    /// two problems the split exists to fix, since folding has already
    /// discarded both the order and any coincident clauses.
    #[must_use]
    pub fn from_set(set: EffectSet) -> Self {
        let ordered: Vec<Effect> = set.iter().collect();
        let clause_spans = (0..u32::try_from(ordered.len()).unwrap_or(u32::MAX))
            .map(|index| (index, 1))
            .collect();
        Self {
            // A set has already discarded which clause declared what, so
            // there is nothing left to say a cell holds.
            denominations: vec![None; ordered.len()],
            set,
            ordered,
            clause_spans,
        }
    }
}

impl From<EffectSet> for Declaration {
    /// See [`Declaration::from_set`] — canonical order stands in for the
    /// clause order, which is correct only where there was never a
    /// signature to evaluate.
    fn from(set: EffectSet) -> Self {
        Self::from_set(set)
    }
}

/// Evaluate a signature to both views of its declaration.
///
/// # Errors
///
/// Any [`EvalError`]; verdicts are deterministic and identical on every
/// node.
pub fn evaluate_declaration(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
) -> Result<Declaration, EvalError> {
    let mut out = Declaration::default();
    let mut bindings = Vec::new();
    let mut budget = Budget::default();
    // One clause at a time, so each one's contribution to the flattened
    // order is bracketed as it is produced.
    for clause in clauses {
        let start = out.ordered.len();
        eval_clauses(
            std::slice::from_ref(clause),
            inputs,
            hasher,
            &mut bindings,
            &mut out,
            &mut budget,
        )?;
        let len = out.ordered.len() - start;
        out.clause_spans.push((
            u32::try_from(start).map_err(|_| EvalError::TooManyEffects)?,
            u32::try_from(len).map_err(|_| EvalError::TooManyEffects)?,
        ));
    }
    Ok(out)
}

/// One signature evaluation's structural allowance: how deep the clause
/// nesting has gone, and how much work — effects declared plus `for-each`
/// iterations — it has done so far.
///
/// Counting effects alone is not a bound on work: an empty `for-each`
/// body declares nothing yet still iterates its list, so a nest of empty
/// loops would run `MAX_FOREACH_ELEMENTS` to the nesting depth while the
/// effect count never moves. Charging each iteration is what bounds that,
/// and it bounds effect-declaring loops on the same budget — the count of
/// landed effects can only be smaller than the iterations that produced
/// them.
#[derive(Default)]
struct Budget {
    clause_depth: usize,
    work: usize,
}

impl Budget {
    /// Charge one unit of evaluation work, refusing past the per-signature
    /// bound. Deterministic, so every node reaches the same verdict.
    const fn charge(&mut self) -> Result<(), EvalError> {
        self.work += 1;
        if self.work > MAX_EFFECTS_PER_SIGNATURE {
            return Err(EvalError::TooManyEffects);
        }
        Ok(())
    }
}

/// Evaluate one expression with no enclosing `for-each` bindings.
///
/// # Errors
///
/// Any [`EvalError`]; verdicts are deterministic and identical on every
/// node.
pub fn evaluate_expr(
    expr: &Expr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
) -> Result<Value, EvalError> {
    eval_expr(expr, inputs, hasher, &[], 0)
}

fn eval_clauses(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &mut Vec<Value>,
    out: &mut Declaration,
    budget: &mut Budget,
) -> Result<(), EvalError> {
    if budget.clause_depth > MAX_CLAUSE_DEPTH {
        return Err(EvalError::ClausesTooDeep);
    }
    for clause in clauses {
        match clause {
            Clause::Effect {
                target,
                mode,
                denomination,
            } => {
                let target = eval_target(target, inputs, hasher, bindings)?;
                let mode = eval_mode(mode, inputs, hasher, bindings)?;
                budget.charge()?;
                // Evaluated beside the key it belongs to and kept parallel
                // to `ordered`, because a capability's rep is its index
                // there — the same alignment the guest's handles ride.
                let held = match denomination {
                    Some(expr) => match eval_expr(expr, inputs, hasher, bindings, 0)? {
                        Value::Address(resource) => Some(resource),
                        found => {
                            return Err(EvalError::TypeMismatch {
                                expected: "resource",
                                found: found.kind(),
                            });
                        }
                    },
                    None => None,
                };
                let effect = Effect { target, mode };
                out.set.insert(effect)?;
                out.ordered.push(effect);
                out.denominations.push(held);
            }
            Clause::ForEach { list, body } => {
                let items = as_list(eval_expr(list, inputs, hasher, bindings, 0)?)?;
                if items.len() > MAX_FOREACH_ELEMENTS {
                    return Err(EvalError::ForEachTooLong { len: items.len() });
                }
                budget.clause_depth += 1;
                for item in items {
                    // The iteration is work whether or not the body declares
                    // anything, so a nest of empty loops is bounded here
                    // rather than running the product of its levels' widths.
                    budget.charge()?;
                    bindings.push(item);
                    let result = eval_clauses(body, inputs, hasher, bindings, out, budget);
                    bindings.pop();
                    result?;
                }
                budget.clause_depth -= 1;
            }
        }
    }
    Ok(())
}

fn eval_target(
    target: &TargetExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<EffectTarget, EvalError> {
    match target {
        TargetExpr::Point(expr) => {
            let key = as_key(eval_expr(expr, inputs, hasher, bindings, 0)?)?;
            Ok(EffectTarget::Point(key))
        }
        TargetExpr::Entry {
            owner,
            collection,
            material,
            order,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings, 0)?)?;
            let collection =
                eval_collection(owner, *collection, material, inputs, hasher, bindings)?;
            let order = as_u128(eval_expr(order, inputs, hasher, bindings, 0)?)?;
            Ok(EffectTarget::Entry {
                owner,
                collection,
                order,
            })
        }
        TargetExpr::Range {
            owner,
            collection,
            material,
            lo,
            hi,
            cap,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings, 0)?)?;
            let collection =
                eval_collection(owner, *collection, material, inputs, hasher, bindings)?;
            let lo = as_u128(eval_expr(lo, inputs, hasher, bindings, 0)?)?;
            let hi = as_u128(eval_expr(hi, inputs, hasher, bindings, 0)?)?;
            if lo > hi {
                return Err(EvalError::InvalidRange);
            }
            Ok(EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap: *cap,
            })
        }
    }
}

/// Fold a target's role and evaluated material into the collection
/// identity everything downstream compares.
fn eval_collection(
    owner: Address,
    role: RoleId,
    material: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<CollectionId, EvalError> {
    let encoded = eval_material(material, inputs, hasher, bindings, 0)?;
    Ok(collection_id(hasher, owner, role, &encoded))
}

fn eval_mode(
    mode: &ModeExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<Mode, EvalError> {
    match mode {
        ModeExpr::Read => Ok(Mode::Read),
        ModeExpr::Locked => Ok(Mode::Locked),
        ModeExpr::Delta => Ok(Mode::Delta),
        ModeExpr::Reserve(expr) => {
            let amount = as_u128(eval_expr(expr, inputs, hasher, bindings, 0)?)?;
            Ok(Mode::Reserve { amount })
        }
        ModeExpr::Write { requires } => Ok(Mode::Write {
            requires: *requires,
        }),
    }
}

/// A non-fungible edge's ids as a list, or the refusal a fungible one
/// earns: kind is structural, never an empty answer.
fn edge_ids(content: EdgeContent) -> Result<Value, EvalError> {
    match content {
        EdgeContent::NonFungible { ids } => {
            Ok(Value::List(ids.into_iter().map(Value::U64).collect()))
        }
        EdgeContent::Fungible => Err(EvalError::TypeMismatch {
            expected: "non-fungible bucket",
            found: "bucket",
        }),
    }
}

/// A bucket projection's parts, or the type mismatch every edge
/// projection refuses alike.
fn bucket_parts(value: Value) -> Result<(Address, EdgeContent), EvalError> {
    match value {
        Value::Bucket { resource, content } => Ok((resource, content)),
        other => Err(EvalError::TypeMismatch {
            expected: "bucket",
            found: other.kind(),
        }),
    }
}

/// Evaluate material expressions to their canonical encodings — the form
/// every derivation hashes.
fn eval_material(
    material: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    depth: usize,
) -> Result<Vec<Vec<u8>>, EvalError> {
    let mut encoded = Vec::with_capacity(material.len());
    for expr in material {
        encoded.push(eval_expr(expr, inputs, hasher, bindings, depth)?.canonical_bytes());
    }
    Ok(encoded)
}

fn eval_expr(
    expr: &Expr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    depth: usize,
) -> Result<Value, EvalError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(EvalError::ExpressionTooDeep);
    }
    let deeper = depth + 1;
    match expr {
        Expr::Literal(value) => Ok(value.clone()),
        Expr::Arg(index) => indexed(inputs.args, *index)
            .cloned()
            .ok_or(EvalError::ArgOutOfRange(*index)),
        Expr::Config(index) => indexed(inputs.config, *index)
            .cloned()
            .ok_or(EvalError::ConfigOutOfRange(*index)),
        Expr::Binding(index) => usize::try_from(*index)
            .ok()
            .and_then(|back| bindings.len().checked_sub(back + 1))
            .and_then(|position| bindings.get(position))
            .cloned()
            .ok_or(EvalError::BindingOutOfRange(*index)),
        Expr::SelfAddr => Ok(Value::Address(inputs.self_addr)),
        Expr::Field(tuple, index) => {
            let fields = as_tuple(eval_expr(tuple, inputs, hasher, bindings, deeper)?)?;
            field(&fields, *index)
        }
        Expr::ResourceOf(bucket) => {
            let (resource, _) = bucket_parts(eval_expr(bucket, inputs, hasher, bindings, deeper)?)?;
            Ok(Value::Address(resource))
        }
        Expr::IdsOf(bucket) => {
            let (_, content) = bucket_parts(eval_expr(bucket, inputs, hasher, bindings, deeper)?)?;
            edge_ids(content)
        }
        Expr::Lookup { map, key } => {
            let pairs = as_list(eval_expr(map, inputs, hasher, bindings, deeper)?)?;
            let key = eval_expr(key, inputs, hasher, bindings, deeper)?;
            lookup(pairs, &key)
        }
        Expr::SelfResource { material } => {
            let encoded = eval_material(material, inputs, hasher, bindings, deeper)?;
            Ok(Value::Address(
                resource_address(hasher, inputs.self_addr, &encoded).into(),
            ))
        }
        Expr::ChildKey {
            owner,
            role,
            material,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings, deeper)?)?;
            let encoded = eval_material(material, inputs, hasher, bindings, deeper)?;
            Ok(Value::Key(child_key(hasher, owner, *role, &encoded)))
        }
        Expr::OrderKey {
            owner,
            role,
            material,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings, deeper)?)?;
            let encoded = eval_material(material, inputs, hasher, bindings, deeper)?;
            Ok(Value::U128(order_key(hasher, owner, *role, &encoded)))
        }
        Expr::FreshId { slot } => Ok(Value::U64(fresh_id(
            hasher,
            inputs.identity,
            inputs.node_index,
            inputs.frame,
            *slot,
        ))),
        Expr::FreshKey { slot } => Ok(Value::Key(SubstateKey {
            owner: inputs.self_addr,
            local: fresh_local(
                hasher,
                inputs.identity,
                inputs.node_index,
                inputs.frame,
                *slot,
            ),
        })),
        Expr::Pack { hi, lo } => {
            let hi = as_u64(eval_expr(hi, inputs, hasher, bindings, deeper)?)?;
            let lo = as_u64(eval_expr(lo, inputs, hasher, bindings, deeper)?)?;
            Ok(Value::U128((u128::from(hi) << 64) | u128::from(lo)))
        }
        Expr::List(elements) => Ok(Value::List(eval_all(
            elements, inputs, hasher, bindings, deeper,
        )?)),
        Expr::Tuple(fields) => Ok(Value::Tuple(eval_all(
            fields, inputs, hasher, bindings, deeper,
        )?)),
        Expr::NfBucket { resource, ids } => {
            let resource = as_address(eval_expr(resource, inputs, hasher, bindings, deeper)?)?;
            let ids = id_set(as_list(eval_expr(ids, inputs, hasher, bindings, deeper)?)?)?;
            Ok(Value::Bucket {
                resource,
                content: EdgeContent::NonFungible { ids },
            })
        }
    }
}

/// Every element of a sequence expression, in order.
fn eval_all(
    elements: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    depth: usize,
) -> Result<Vec<Value>, EvalError> {
    elements
        .iter()
        .map(|element| eval_expr(element, inputs, hasher, bindings, depth))
        .collect()
}

/// One field of a tuple, by position.
fn field(fields: &[Value], index: u32) -> Result<Value, EvalError> {
    indexed(fields, index)
        .cloned()
        .ok_or(EvalError::FieldOutOfRange {
            index,
            arity: fields.len(),
        })
}

/// The value of the first pair whose key matches, over a list of
/// `(key, value)` tuples.
fn lookup(pairs: Vec<Value>, key: &Value) -> Result<Value, EvalError> {
    for pair in pairs {
        let Value::Tuple(fields) = pair else {
            return Err(EvalError::LookupNotPairs);
        };
        let [pair_key, pair_value] = fields.as_slice() else {
            return Err(EvalError::LookupNotPairs);
        };
        if pair_key == key {
            return Ok(pair_value.clone());
        }
    }
    Err(EvalError::LookupMiss)
}

/// A well-formed instance id set: every element a `u64`, at most
/// [`MAX_IDS_PER_EDGE`] of them, each distinct — a duplicate would be
/// one instance landing twice off a single edge.
fn id_set(values: Vec<Value>) -> Result<Vec<u64>, EvalError> {
    if values.len() > MAX_IDS_PER_EDGE {
        return Err(EvalError::TooManyIds { len: values.len() });
    }
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let id = as_u64(value)?;
        if ids.contains(&id) {
            return Err(EvalError::DuplicateId { id });
        }
        ids.push(id);
    }
    Ok(ids)
}

fn indexed<T>(slice: &[T], index: u32) -> Option<&T> {
    usize::try_from(index)
        .ok()
        .and_then(|index| slice.get(index))
}

fn as_u64(value: Value) -> Result<u64, EvalError> {
    match value {
        Value::U64(v) => Ok(v),
        other => Err(EvalError::TypeMismatch {
            expected: "u64",
            found: other.kind(),
        }),
    }
}

fn as_u128(value: Value) -> Result<u128, EvalError> {
    match value {
        Value::U64(v) => Ok(u128::from(v)),
        Value::U128(v) => Ok(v),
        other => Err(EvalError::TypeMismatch {
            expected: "u128",
            found: other.kind(),
        }),
    }
}

fn as_address(value: Value) -> Result<Address, EvalError> {
    match value {
        Value::Address(addr) => Ok(addr),
        other => Err(EvalError::TypeMismatch {
            expected: "address",
            found: other.kind(),
        }),
    }
}

fn as_key(value: Value) -> Result<SubstateKey, EvalError> {
    match value {
        Value::Key(key) => Ok(key),
        other => Err(EvalError::TypeMismatch {
            expected: "key",
            found: other.kind(),
        }),
    }
}

fn as_tuple(value: Value) -> Result<Vec<Value>, EvalError> {
    match value {
        Value::Tuple(fields) => Ok(fields),
        other => Err(EvalError::TypeMismatch {
            expected: "tuple",
            found: other.kind(),
        }),
    }
}

fn as_list(value: Value) -> Result<Vec<Value>, EvalError> {
    match value {
        Value::List(items) => Ok(items),
        other => Err(EvalError::TypeMismatch {
            expected: "list",
            found: other.kind(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clause, EvalError, EvalInputs, Expr, MAX_CLAUSE_DEPTH, MAX_EXPR_DEPTH,
        MAX_FOREACH_ELEMENTS, ModeExpr, TargetExpr, evaluate_declaration, evaluate_effects,
        evaluate_expr, fresh_id, fresh_local,
    };
    use crate::hash::{Hash32, TestHasher};
    use crate::manifest::ManifestHash;
    use crate::types::{
        Address, AddressClass, EdgeContent, Effect, EffectTarget, MAX_IDS_PER_EDGE, Mode, Presence,
        RoleId, Value, child_key, collection_id, order_key,
    };

    fn inputs<'a>(args: &'a [Value], config: &'a [Value]) -> EvalInputs<'a> {
        EvalInputs {
            self_addr: Address::new([7; 31], AddressClass::Component),
            args,
            config,
            node_index: 3,
            frame: 0,
            identity: ManifestHash(Hash32([9; 32])),
        }
    }

    #[test]
    fn a_declaration_keeps_clause_order_beside_the_folded_set() {
        // Two views of one evaluation, and neither reconstructs the other:
        // the set has folded away both the order and the repetition, and
        // the clause list has no notion of a canonical order at all.
        let point = |byte: u8| {
            TargetExpr::Point(Expr::Literal(Value::Key(child_key(
                &TestHasher,
                Address::new([byte; 31], AddressClass::Component),
                RoleId(1),
                &[],
            ))))
        };
        let clauses = vec![
            Clause::Effect {
                target: point(0xF0),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
            Clause::Effect {
                target: point(0x0F),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
            // The same target as the first clause: a degenerate instance
            // configuration produces exactly this shape.
            Clause::Effect {
                target: point(0xF0),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
        ];
        let ins = inputs(&[], &[]);
        let declaration = evaluate_declaration(&clauses, &ins, &TestHasher).unwrap();

        assert_eq!(declaration.ordered.len(), 3, "one entry per clause reached");
        assert_eq!(declaration.set.len(), 2, "the set folds the repeat");
        assert_eq!(
            declaration.ordered[0], declaration.ordered[2],
            "the repeated clause is the same effect twice"
        );
        // The clause order is the author's, so it survives regardless of
        // how the two keys happen to compare.
        assert_ne!(declaration.ordered[0], declaration.ordered[1]);
        assert_eq!(
            evaluate_effects(&clauses, &ins, &TestHasher).unwrap(),
            declaration.set,
            "the set-only entry point is the same fold"
        );
    }

    #[test]
    fn projections_and_lookup() {
        let args = [
            Value::Tuple(vec![
                Value::U64(1),
                Value::Address(Address::new([2; 31], AddressClass::Component)),
            ]),
            Value::List(vec![
                Value::Tuple(vec![Value::U64(10), Value::U64(100)]),
                Value::Tuple(vec![Value::U64(20), Value::U64(200)]),
            ]),
        ];
        let ins = inputs(&args, &[]);
        let field = Expr::Field(Box::new(Expr::Arg(0)), 1);
        assert_eq!(
            evaluate_expr(&field, &ins, &TestHasher),
            Ok(Value::Address(Address::new(
                [2; 31],
                AddressClass::Component
            )))
        );
        let hit = Expr::Lookup {
            map: Box::new(Expr::Arg(1)),
            key: Box::new(Expr::Literal(Value::U64(20))),
        };
        assert_eq!(evaluate_expr(&hit, &ins, &TestHasher), Ok(Value::U64(200)));
        let miss = Expr::Lookup {
            map: Box::new(Expr::Arg(1)),
            key: Box::new(Expr::Literal(Value::U64(30))),
        };
        assert_eq!(
            evaluate_expr(&miss, &ins, &TestHasher),
            Err(EvalError::LookupMiss)
        );
    }

    #[test]
    fn pack_and_fresh_derivations() {
        let ins = inputs(&[], &[]);
        let packed = Expr::Pack {
            hi: Box::new(Expr::Literal(Value::U64(5))),
            lo: Box::new(Expr::Literal(Value::U64(6))),
        };
        assert_eq!(
            evaluate_expr(&packed, &ins, &TestHasher),
            Ok(Value::U128((5u128 << 64) | 6))
        );

        let id = evaluate_expr(&Expr::FreshId { slot: 0 }, &ins, &TestHasher).unwrap();
        assert_eq!(id, Value::U64(fresh_id(&TestHasher, ins.identity, 3, 0, 0)));
        assert_ne!(
            fresh_id(&TestHasher, ins.identity, 3, 0, 0),
            fresh_id(&TestHasher, ins.identity, 3, 0, 1)
        );
        assert_ne!(
            fresh_id(&TestHasher, ins.identity, 3, 0, 0),
            fresh_id(&TestHasher, ins.identity, 4, 0, 0)
        );
        assert_ne!(
            fresh_id(&TestHasher, ins.identity, 3, 0, 0),
            fresh_id(&TestHasher, ins.identity, 3, 1, 0)
        );

        let key = evaluate_expr(&Expr::FreshKey { slot: 2 }, &ins, &TestHasher).unwrap();
        let Value::Key(key) = key else { panic!() };
        assert_eq!(key.owner, ins.self_addr);
        assert_eq!(key.local, fresh_local(&TestHasher, ins.identity, 3, 0, 2));
    }

    #[test]
    fn foreach_binds_innermost_first() {
        // For each recipient (a list of (owner, resource) pairs): a delta on
        // the recipient's vault for that resource.
        let args = [Value::List(vec![
            Value::Tuple(vec![
                Value::Address(Address::new([1; 31], AddressClass::Component)),
                Value::Address(Address::new([0xAA; 31], AddressClass::Component)),
            ]),
            Value::Tuple(vec![
                Value::Address(Address::new([2; 31], AddressClass::Component)),
                Value::Address(Address::new([0xBB; 31], AddressClass::Component)),
            ]),
        ])];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Field(Box::new(Expr::Binding(0)), 0)),
                    role: RoleId(1),
                    material: vec![Expr::Field(Box::new(Expr::Binding(0)), 1)],
                }),
                mode: ModeExpr::Delta,
                denomination: None,
            }],
        }];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        assert_eq!(set.len(), 2);
        for (owner, resource) in [([1u8; 31], [0xAAu8; 31]), ([2; 31], [0xBB; 31])] {
            let key = child_key(
                &TestHasher,
                Address::new(owner, AddressClass::Component),
                RoleId(1),
                &[
                    Value::Address(Address::new(resource, AddressClass::Component))
                        .canonical_bytes(),
                ],
            );
            assert!(set.contains(&Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Delta,
            }));
        }
    }

    /// A left-nested projection chain `Field(Field(…Arg(0)…))`.
    fn nested_projection(depth: usize) -> Expr {
        let mut expr = Expr::Arg(0);
        for _ in 0..depth {
            expr = Expr::Field(Box::new(expr), 0);
        }
        expr
    }

    #[test]
    fn expression_nesting_is_bounded() {
        // A tuple with exactly one layer per admitted projection, so what
        // rejects the deeper expression is the depth bound and not a type
        // mismatch at the bottom.
        let mut value = Value::U64(7);
        for _ in 0..MAX_EXPR_DEPTH {
            value = Value::Tuple(vec![value]);
        }
        let args = [value];
        let ins = inputs(&args, &[]);

        assert_eq!(
            evaluate_expr(&nested_projection(MAX_EXPR_DEPTH), &ins, &TestHasher),
            Ok(Value::U64(7))
        );
        assert_eq!(
            evaluate_expr(&nested_projection(MAX_EXPR_DEPTH + 1), &ins, &TestHasher),
            Err(EvalError::ExpressionTooDeep)
        );
    }

    #[test]
    fn clause_nesting_and_declared_effects_are_bounded() {
        // One element per level, so nesting is what the bound catches.
        let args = [Value::List(vec![Value::U64(0)])];
        let ins = inputs(&args, &[]);
        let effect = Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role: RoleId(1),
                material: vec![],
            }),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let nest = |depth: usize| {
            let mut clause = effect.clone();
            for _ in 0..depth {
                clause = Clause::ForEach {
                    list: Expr::Arg(0),
                    body: vec![clause],
                };
            }
            clause
        };
        assert!(evaluate_effects(&[nest(MAX_CLAUSE_DEPTH)], &ins, &TestHasher).is_ok());
        assert_eq!(
            evaluate_effects(&[nest(MAX_CLAUSE_DEPTH + 1)], &ins, &TestHasher),
            Err(EvalError::ClausesTooDeep)
        );

        // Width within the bound: two levels of 1024 declare a million
        // effects from a signature that says nothing about its own cost.
        let wide = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];
        let wide_ins = inputs(&wide, &[]);
        assert_eq!(
            evaluate_effects(&[nest(2)], &wide_ins, &TestHasher),
            Err(EvalError::TooManyEffects)
        );
    }

    #[test]
    fn foreach_is_bounded() {
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS + 1])];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            list: Expr::Arg(0),
            body: vec![],
        }];
        assert_eq!(
            evaluate_effects(&clauses, &ins, &TestHasher),
            Err(EvalError::ForEachTooLong {
                len: MAX_FOREACH_ELEMENTS + 1
            })
        );
    }

    #[test]
    fn empty_for_each_bodies_are_bounded_by_iteration_work() {
        // A nest of empty `for-each` loops declares no effect, so an effect
        // counter never moves — but each level still iterates its list, and
        // the product is the work. Without an iteration bound this runs
        // `MAX_FOREACH_ELEMENTS` to the nesting depth; with one it refuses
        // after a constant number of iterations.
        let wide = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];
        let ins = inputs(&wide, &[]);
        let mut clause = Clause::ForEach {
            list: Expr::Arg(0),
            body: Vec::new(),
        };
        for _ in 1..MAX_CLAUSE_DEPTH {
            clause = Clause::ForEach {
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        assert_eq!(
            evaluate_effects(&[clause], &ins, &TestHasher),
            Err(EvalError::TooManyEffects),
        );
    }

    #[test]
    fn a_deep_nest_over_short_lists_still_evaluates() {
        // The iteration bound is config-aware: the same structure that is
        // refused over full lists routes fine over short ones, because the
        // work is the product of the actual list lengths, not the widest
        // they could be. A signature is not rejected for a shape whose cost
        // depends on the configuration it runs under.
        let short = [Value::List(vec![Value::U64(0), Value::U64(1)])];
        let ins = inputs(&short, &[]);
        let mut clause = Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role: RoleId(1),
                material: vec![],
            }),
            mode: ModeExpr::Read,
            denomination: None,
        };
        for _ in 0..MAX_CLAUSE_DEPTH {
            clause = Clause::ForEach {
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        assert!(evaluate_effects(&[clause], &ins, &TestHasher).is_ok());
    }

    #[test]
    fn ranges_and_windows_evaluate_from_inputs() {
        let args = [Value::U64(100), Value::U64(110), Value::U64(8)];
        let ins = inputs(&args, &[]);
        let clauses = [
            Clause::Effect {
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: RoleId(4),
                    material: vec![],
                    lo: Expr::Arg(0),
                    hi: Expr::Arg(1),
                    cap: 16,
                },
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
            Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    role: RoleId(9),
                    material: vec![],
                }),
                mode: ModeExpr::Locked,
                denomination: None,
            },
        ];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        assert!(set.contains(&Effect {
            target: EffectTarget::Range {
                owner: ins.self_addr,
                collection: collection_id(&TestHasher, ins.self_addr, RoleId(4), &[]),
                lo: 100,
                hi: 110,
                cap: 16,
            },
            mode: Mode::Write {
                requires: Presence::Either
            },
        }));
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(child_key(&TestHasher, ins.self_addr, RoleId(9), &[])),
            mode: Mode::Locked,
        }));

        let inverted = [Clause::Effect {
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: RoleId(4),
                material: vec![],
                lo: Expr::Arg(1),
                hi: Expr::Arg(0),
                cap: 16,
            },
            mode: ModeExpr::Write {
                requires: Presence::Either,
            },
            denomination: None,
        }];
        assert_eq!(
            evaluate_effects(&inverted, &ins, &TestHasher),
            Err(EvalError::InvalidRange)
        );
    }

    #[test]
    fn material_separates_collections_under_one_role() {
        // One role, two materials: two collections. The identity folds the
        // owner, the role, and the evaluated material, so an entry target
        // parameterized by an argument lands in the argument's collection.
        let resource_a = Value::Address(Address::new([0xAA; 31], AddressClass::Resource));
        let resource_b = Value::Address(Address::new([0xBB; 31], AddressClass::Resource));
        let args = [resource_a.clone(), resource_b.clone()];
        let ins = inputs(&args, &[]);
        let entry_for = |slot: u32| Clause::Effect {
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: RoleId(4),
                material: vec![Expr::Arg(slot)],
                order: Expr::Literal(Value::U128(9)),
            },
            mode: ModeExpr::Write {
                requires: Presence::Either,
            },
            denomination: None,
        };
        let set = evaluate_effects(&[entry_for(0), entry_for(1)], &ins, &TestHasher).unwrap();
        let id_for = |resource: &Value| {
            collection_id(
                &TestHasher,
                ins.self_addr,
                RoleId(4),
                &[resource.canonical_bytes()],
            )
        };
        assert_eq!(set.len(), 2, "distinct material is distinct collections");
        for resource in [&resource_a, &resource_b] {
            assert!(set.contains(&Effect {
                target: EffectTarget::Entry {
                    owner: ins.self_addr,
                    collection: id_for(resource),
                    order: 9,
                },
                mode: Mode::Write {
                    requires: Presence::Either
                },
            }));
        }

        // Same derivation, different role: a third collection. The salt
        // arms are each load-bearing.
        assert_ne!(id_for(&resource_a), id_for(&resource_b));
        assert_ne!(
            collection_id(&TestHasher, ins.self_addr, RoleId(4), &[]),
            collection_id(&TestHasher, ins.self_addr, RoleId(5), &[]),
        );
        let other = Address::new([8; 31], AddressClass::Component);
        assert_ne!(
            collection_id(&TestHasher, ins.self_addr, RoleId(4), &[]),
            collection_id(&TestHasher, other, RoleId(4), &[]),
        );
    }

    #[test]
    fn order_keys_hash_the_logical_key_under_the_collections_salt() {
        let name_a = Value::U64(7);
        let name_b = Value::U64(8);
        let args = [name_a.clone(), name_b.clone()];
        let ins = inputs(&args, &[]);
        let entry_for = |slot: u32| Clause::Effect {
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: RoleId(2),
                material: vec![],
                order: Expr::OrderKey {
                    owner: Box::new(Expr::SelfAddr),
                    role: RoleId(2),
                    material: vec![Expr::Arg(slot)],
                },
            },
            mode: ModeExpr::Write {
                requires: Presence::Either,
            },
            denomination: None,
        };
        let set = evaluate_effects(&[entry_for(0), entry_for(1)], &ins, &TestHasher).unwrap();
        let order_for = |name: &Value| {
            order_key(
                &TestHasher,
                ins.self_addr,
                RoleId(2),
                &[name.canonical_bytes()],
            )
        };
        assert_eq!(set.len(), 2, "distinct keys land at distinct orders");
        for name in [&name_a, &name_b] {
            assert!(set.contains(&Effect {
                target: EffectTarget::Entry {
                    owner: ins.self_addr,
                    collection: collection_id(&TestHasher, ins.self_addr, RoleId(2), &[]),
                    order: order_for(name),
                },
                mode: Mode::Write {
                    requires: Presence::Either
                },
            }));
        }

        // Each salt arm moves the key; the domain keeps an order key from
        // ever reading as a collection identity.
        assert_ne!(order_for(&name_a), order_for(&name_b));
        assert_ne!(
            order_key(&TestHasher, ins.self_addr, RoleId(2), &[]),
            order_key(&TestHasher, ins.self_addr, RoleId(3), &[]),
        );
        let other = Address::new([8; 31], AddressClass::Component);
        assert_ne!(
            order_key(&TestHasher, ins.self_addr, RoleId(2), &[]),
            order_key(&TestHasher, other, RoleId(2), &[]),
        );
        assert_ne!(
            order_key(&TestHasher, ins.self_addr, RoleId(2), &[]).to_be_bytes(),
            collection_id(&TestHasher, ins.self_addr, RoleId(2), &[]).0,
        );
    }

    #[test]
    fn ids_of_projects_a_non_fungible_edge() {
        let bucket = Value::Bucket {
            resource: Address::new([0xE1; 31], AddressClass::Resource),
            content: EdgeContent::NonFungible { ids: vec![7, 9] },
        };
        let fungible = Value::Bucket {
            resource: Address::new([0xE1; 31], AddressClass::Resource),
            content: EdgeContent::Fungible,
        };
        let args = [bucket, fungible];
        let ins = inputs(&args, &[]);
        assert_eq!(
            evaluate_expr(&Expr::IdsOf(Box::new(Expr::Arg(0))), &ins, &TestHasher),
            Ok(Value::List(vec![Value::U64(7), Value::U64(9)])),
        );
        // A fungible edge refuses the id read: kind is structural,
        // never an empty answer.
        assert!(evaluate_expr(&Expr::IdsOf(Box::new(Expr::Arg(1))), &ins, &TestHasher).is_err());
    }

    #[test]
    fn nf_bucket_constructs_the_projection_ids_of_reads_back() {
        let resource = Address::new([0xE1; 31], AddressClass::Resource);
        // A mint's shape: the resource its own, the ids fresh.
        let minted = Expr::NfBucket {
            resource: Box::new(Expr::Arg(0)),
            ids: Box::new(Expr::List(vec![
                Expr::FreshId { slot: 0 },
                Expr::FreshId { slot: 1 },
            ])),
        };
        let args = [Value::Address(resource)];
        let ins = inputs(&args, &[]);
        let expected: Vec<u64> = (0..2)
            .map(|slot| fresh_id(&TestHasher, ins.identity, ins.node_index, ins.frame, slot))
            .collect();
        assert_eq!(
            evaluate_expr(&minted, &ins, &TestHasher),
            Ok(Value::Bucket {
                resource,
                content: EdgeContent::NonFungible { ids: expected },
            }),
        );

        // A transfer's shape: the ids named as a signed argument.
        let named = Expr::NfBucket {
            resource: Box::new(Expr::Arg(0)),
            ids: Box::new(Expr::Arg(1)),
        };
        let args = [
            Value::Address(resource),
            Value::List(vec![Value::U64(7), Value::U64(9)]),
        ];
        let ins = inputs(&args, &[]);
        let bucket = evaluate_expr(&named, &ins, &TestHasher).unwrap();
        assert_eq!(
            evaluate_expr(
                &Expr::IdsOf(Box::new(Expr::Literal(bucket))),
                &ins,
                &TestHasher
            ),
            Ok(Value::List(vec![Value::U64(7), Value::U64(9)])),
        );
    }

    #[test]
    fn an_id_set_is_bounded_and_duplicate_free() {
        let resource = Address::new([0xE1; 31], AddressClass::Resource);
        let bucket = |ids: Vec<Value>| Expr::NfBucket {
            resource: Box::new(Expr::Literal(Value::Address(resource))),
            ids: Box::new(Expr::Literal(Value::List(ids))),
        };
        let ins = inputs(&[], &[]);

        let over_cap: Vec<Value> = (0..=MAX_IDS_PER_EDGE as u64).map(Value::U64).collect();
        assert_eq!(
            evaluate_expr(&bucket(over_cap), &ins, &TestHasher),
            Err(EvalError::TooManyIds {
                len: MAX_IDS_PER_EDGE + 1
            }),
        );
        assert_eq!(
            evaluate_expr(
                &bucket(vec![Value::U64(7), Value::U64(7)]),
                &ins,
                &TestHasher
            ),
            Err(EvalError::DuplicateId { id: 7 }),
        );
        // An element that is not an id, and an id set that is not a list.
        assert!(evaluate_expr(&bucket(vec![Value::U128(7)]), &ins, &TestHasher).is_err());
        let not_a_list = Expr::NfBucket {
            resource: Box::new(Expr::Literal(Value::Address(resource))),
            ids: Box::new(Expr::Literal(Value::U64(7))),
        };
        assert!(evaluate_expr(&not_a_list, &ins, &TestHasher).is_err());
    }

    #[test]
    fn reserve_amount_comes_from_arguments() {
        let args = [
            Value::Address(Address::new([0xCC; 31], AddressClass::Component)),
            Value::U128(75),
        ];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role: RoleId(1),
                material: vec![Expr::Arg(0)],
            }),
            mode: ModeExpr::Reserve(Expr::Arg(1)),
            denomination: None,
        }];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        let expected = child_key(
            &TestHasher,
            ins.self_addr,
            RoleId(1),
            &[args[0].canonical_bytes()],
        );
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(expected),
            mode: Mode::Reserve { amount: 75 },
        }));
    }
}
