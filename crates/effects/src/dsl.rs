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
use hyperscale_vm_types::{
    Address, CellKind, CollectionId, Denomination, Effect, EffectConflict, EffectSet, EffectTarget,
    LocalKey, Mode, NotAResource, Presence, SubstateKey,
};

use crate::hash::{Hash32, Hasher};
use crate::manifest::ManifestHash;
use crate::types::{
    EdgeContent, MAX_IDS_PER_EDGE, SlotId, Value, child_key, collection_id, order_key,
    resource_address,
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
pub fn self_child(slot: SlotId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot,
        material,
    }
}

/// An expression over a method's inputs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
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
    /// The canonical child key `owner | H(slot, material…)`.
    ChildKey {
        /// The owning address.
        owner: Box<Self>,
        /// The child's slot under the owner.
        slot: SlotId,
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
    /// the collection's slot, like [`Expr::ChildKey`], so a ground
    /// collision is confined to the one collection it could hurt.
    OrderKey {
        /// The collection's owner.
        owner: Box<Self>,
        /// The collection's slot under the owner.
        slot: SlotId,
        /// The logical key, canonically encoded into the hash.
        material: Vec<Self>,
    },
    /// Negation of a judgment.
    Not(Box<Self>),
    /// Conjunction, short-circuiting: a false left operand is the answer,
    /// and the right one is never evaluated.
    And(Box<Self>, Box<Self>),
    /// Disjunction, short-circuiting on a true left operand.
    Or(Box<Self>, Box<Self>),
    /// Structural equality between two values of one kind.
    ///
    /// Tuples and lists compare element by element, which is what makes a
    /// pair equal to a pair. A bucket is refused wherever it appears in
    /// either operand: an edge projection is a routable summary of a value
    /// in flight, its amount is not in the projection, and two summaries
    /// comparing equal would answer a question about amounts it cannot
    /// see.
    Eq(Box<Self>, Box<Self>),
    /// Strict ordering, over `u64` against `u64` and `u128` against
    /// `u128` and nothing else. An address has no meaningful order, and
    /// ordering bytes invites a lexicographic key nobody meant.
    Lt(Box<Self>, Box<Self>),
    /// Whether a table holds a key — the question [`Expr::Lookup`]
    /// answers destructively. Reads the same list-of-pairs shape and
    /// shares its walk.
    Contains {
        /// The list of pairs to search.
        map: Box<Self>,
        /// The key to match against each pair's first field.
        key: Box<Self>,
    },
    /// Selection between two expressions, evaluating only the taken arm.
    ///
    /// The short-circuit is the point rather than an optimization: it is
    /// what lets a conditional guard an expression that would otherwise
    /// refuse, so `If { cond: Contains(t, k), then: Lookup(t, k), .. }`
    /// turns a hard routing refusal into something a package can handle.
    If {
        /// The judgment selecting an arm.
        cond: Box<Self>,
        /// Evaluated when the condition holds.
        then: Box<Self>,
        /// Evaluated when it does not.
        otherwise: Box<Self>,
    },
}

impl Expr {
    /// Every direct subexpression, left to right.
    ///
    /// The one statement of the tree's structure. Every structural walk —
    /// a bounds check, an input scan — folds over this, so a new variant
    /// costs exactly one arm here and cannot bury a subterm from one walk
    /// while showing it to another. Only evaluation keeps its own full
    /// match, because what it does with each position is semantic.
    pub fn children(&self) -> impl Iterator<Item = &Self> {
        let mut children: Vec<&Self> = Vec::new();
        match self {
            Self::Literal(_)
            | Self::Arg(_)
            | Self::Config(_)
            | Self::Binding(_)
            | Self::SelfAddr
            | Self::FreshId { .. }
            | Self::FreshKey { .. } => {}
            Self::Field(inner, _)
            | Self::ResourceOf(inner)
            | Self::IdsOf(inner)
            | Self::Not(inner) => children.push(inner),
            Self::Lookup {
                map: first,
                key: second,
            }
            | Self::Contains {
                map: first,
                key: second,
            }
            | Self::Pack {
                hi: first,
                lo: second,
            }
            | Self::NfBucket {
                resource: first,
                ids: second,
            }
            | Self::And(first, second)
            | Self::Or(first, second)
            | Self::Eq(first, second)
            | Self::Lt(first, second) => {
                children.push(first);
                children.push(second);
            }
            Self::If {
                cond,
                then,
                otherwise,
            } => {
                children.push(cond);
                children.push(then);
                children.push(otherwise);
            }
            Self::List(elements)
            | Self::Tuple(elements)
            | Self::SelfResource { material: elements } => children.extend(elements),
            Self::ChildKey {
                owner, material, ..
            }
            | Self::OrderKey {
                owner, material, ..
            } => {
                children.push(owner);
                children.extend(material);
            }
        }
        children.into_iter()
    }

    /// Whether this node itself is a caller-supplied input, before any
    /// subterm is asked.
    #[must_use]
    pub const fn is_input_leaf(&self) -> bool {
        matches!(self, Self::Arg(_) | Self::Binding(_))
    }

    /// Whether evaluating this reads anything the caller supplies.
    ///
    /// An authority expression must not: an identity a caller names is an
    /// identity that caller can always present, so a method gated on one
    /// reads as guarded and admits everyone.
    #[must_use]
    pub(crate) fn reads_call_inputs(&self) -> bool {
        self.is_input_leaf() || self.children().any(Self::reads_call_inputs)
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum TargetExpr {
    /// A single substate leaf; the expression must evaluate to a key.
    Point(Expr),
    /// One ordered-collection entry at a computed order key.
    Entry {
        /// The collection's owner.
        owner: Expr,
        /// The collection's slot under the owner.
        collection: SlotId,
        /// The material separating this collection from the slot's others,
        /// canonically encoded into its identity.
        material: Vec<Expr>,
        /// The entry's order key.
        order: Expr,
    },
    /// A declared interval of a collection's order-key space.
    Range {
        /// The collection's owner.
        owner: Expr,
        /// The collection's slot under the owner.
        collection: SlotId,
        /// The material separating this collection from the slot's others,
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

/// The handle type a clause's mode, target and denomination
/// materialize, when the clause pins one statically.
///
/// A `for-each` clause yields `None`: naming one as a handle parameter
/// is a deterministic refusal at materialization, so there is no single
/// type to answer with. So does a mode and target pairing no capability
/// is built for.
///
/// The denomination is read for the same reason the kernel reads it: a
/// cell that says what it holds is one value moves through, and a cell
/// that says nothing is one bytes are written to. The two share no
/// operation, so they are two types and an export borrows the one its
/// clause named.
///
/// Two callers, and neither can recover this from what it holds. The
/// publish gate holds an export's declared resource to the clause it
/// borrows, before any evaluation. Routing names the type of a handle it
/// is deliberately *not* materializing, where an engine would otherwise
/// read the type off a capability that is not there.
#[must_use]
pub const fn materialized_kind(clause: &Clause) -> Option<CellKind> {
    let Clause::Effect {
        target,
        mode,
        denomination,
        ..
    } = clause
    else {
        return None;
    };
    let holds_value = denomination.is_some();
    match (target, mode) {
        (TargetExpr::Point(_), ModeExpr::Read) => Some(if holds_value {
            CellKind::AmountRead
        } else {
            CellKind::Read
        }),
        (TargetExpr::Point(_), ModeExpr::Locked) => Some(CellKind::Locked),
        (TargetExpr::Point(_), ModeExpr::Write { .. }) => Some(if holds_value {
            CellKind::Amount
        } else {
            CellKind::Write
        }),
        (TargetExpr::Point(_), ModeExpr::Delta) => Some(CellKind::Delta),
        (TargetExpr::Point(_), ModeExpr::Reserve(_)) => Some(CellKind::Reserve),
        (TargetExpr::Entry { .. } | TargetExpr::Range { .. }, ModeExpr::Read) => {
            Some(CellKind::RangeRead)
        }
        (TargetExpr::Entry { .. } | TargetExpr::Range { .. }, ModeExpr::Write { .. }) => {
            Some(if holds_value {
                CellKind::InstanceRange
            } else {
                CellKind::RangeWrite
            })
        }
        _ => None,
    }
}

/// One clause of an effect signature.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[allow(clippy::large_enum_variant)] // an access carries a target; a loop carries none
pub enum Clause {
    /// A single declared access.
    Effect {
        /// When this clause is declared at all, or always where absent.
        ///
        /// A guard rather than a nesting block, because an ABI binding
        /// names a top-level clause index and four consumers read that
        /// index. Nesting would make it a preorder over a tree and move
        /// all four; a guard leaves every index meaning what it meant.
        /// An `if` around three accesses is three clauses carrying one
        /// condition each, and `if a { if b { … } }` guards on `And(a,
        /// b)` — so nothing about clause depth changes either.
        guard: Option<Box<Expr>>,
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
        /// When this clause is declared at all, or always where absent.
        guard: Option<Box<Expr>>,
        /// The collection to map over; must evaluate to a list.
        list: Expr,
        /// The clauses evaluated per element.
        body: Vec<Self>,
    },
}

impl Clause {
    /// The condition this clause is declared under, where it carries one.
    #[must_use]
    pub const fn guard(&self) -> Option<&Expr> {
        match self {
            Self::Effect { guard, .. } | Self::ForEach { guard, .. } => match guard {
                Some(cond) => Some(cond),
                None => None,
            },
        }
    }

    /// This clause and every clause beneath it, `for-each` bodies in
    /// place — the preorder the clause indices name.
    ///
    /// Loops are yielded like accesses, because an index names either
    /// kind: the walk that numbers clauses and the walk that judges them
    /// have to agree on what counts.
    pub fn effects(&self) -> impl Iterator<Item = &Self> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            let clause = stack.pop()?;
            if let Self::ForEach { body, .. } = clause {
                stack.extend(body.iter().rev());
            }
            Some(clause)
        })
    }
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
    /// A denomination that evaluated to an address whose class names no
    /// resource.
    #[error(transparent)]
    NotAResource(#[from] NotAResource),
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
    /// A conflict met while folding declared effects into the set.
    #[error(transparent)]
    Conflict(#[from] EffectConflict),
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
    /// The transaction's identity — the signed graph's hash; the one root
    /// of every fresh-ID derivation.
    pub identity: ManifestHash,
}

impl EvalInputs<'_> {
    /// The 64-bit id drawn at `slot` in this frame.
    fn fresh_id(&self, hasher: &dyn Hasher, slot: u32) -> u64 {
        fresh_id(hasher, self.identity, self.node_index, slot)
    }

    /// The substate key drawn at `slot`, under the target instance's own
    /// prefix — the same derivation, so an object's key and the id a body
    /// is handed for it are one draw rather than two.
    fn fresh_key(&self, hasher: &dyn Hasher, slot: u32) -> SubstateKey {
        SubstateKey {
            owner: self.self_addr,
            local: fresh_local(hasher, self.identity, self.node_index, slot),
        }
    }
}

const DOMAIN_FRESH: &[u8] = b"hyperscale-vm/fresh-id";

fn fresh_digest(hasher: &dyn Hasher, identity: ManifestHash, node_index: u32, slot: u32) -> Hash32 {
    hasher.hash(
        DOMAIN_FRESH,
        &[
            &identity.0.0,
            &node_index.to_le_bytes(),
            &slot.to_le_bytes(),
        ],
    )
}

/// The deterministic fresh 64-bit id for `(transaction, node, slot)`.
///
/// This is the value [`Expr::FreshId`] evaluates to; the kernel derives
/// created-object ids from the same root, so declaration and execution
/// agree on every fresh key.
#[must_use]
pub fn fresh_id(hasher: &dyn Hasher, identity: ManifestHash, node_index: u32, slot: u32) -> u64 {
    let digest = fresh_digest(hasher, identity, node_index, slot);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.0[..8]);
    u64::from_le_bytes(bytes)
}

/// The deterministic fresh local key for `(transaction, node, slot)` —
/// the local half [`Expr::FreshKey`] places under the creating
/// instance's prefix.
#[must_use]
pub fn fresh_local(
    hasher: &dyn Hasher,
    identity: ManifestHash,
    node_index: u32,
    slot: u32,
) -> LocalKey {
    let digest = fresh_digest(hasher, identity, node_index, slot);
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

/// One declared access, in the clause order the author wrote: the
/// effect, and what the cell it names holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredAccess {
    /// The access.
    pub effect: Effect,
    /// The resource the cell holds, where it holds value.
    ///
    /// On the entry rather than on [`Effect`] because an effect is what
    /// the set is keyed by: two accesses on one cell are one target
    /// whatever else is true of them, and a denomination riding the key
    /// would split them. Riding the ordered entry is what lets a
    /// capability's rep — its index here — answer what the cell it is
    /// moving into holds.
    pub holds: Option<Denomination>,
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
    pub ordered: Vec<DeclaredAccess>,
    /// Where each top-level clause's effects sit in [`Declaration::ordered`],
    /// as `(start, len)` pairs in clause order.
    ///
    /// A different index space from `ordered` itself: these count
    /// top-level clauses, whose `for-each` expansions occupy runs of the
    /// flattened table.
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
    /// Whether each top-level clause was declared at all, in clause order.
    ///
    /// True where the clause carries no guard, and where its guard held.
    /// This is what an [`AbiParam::Guard`] binding answers with, so the
    /// guest branches on the declaration's own evaluation rather than on
    /// a second copy of the condition — there being nothing for it to
    /// disagree with is what makes agreement structural.
    ///
    /// Not recoverable from [`Declaration::clause_spans`]: an empty
    /// `for-each` contributes no effects and was taken all the same.
    ///
    /// [`AbiParam::Guard`]: crate::metadata::AbiParam::Guard
    pub clause_taken: Vec<bool>,
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
    #[cfg(any(test, feature = "testing"))]
    pub fn from_set(set: EffectSet) -> Self {
        // A set has already discarded which clause declared what, so
        // there is nothing left to say a cell holds.
        let ordered: Vec<DeclaredAccess> = set
            .iter()
            .map(|effect| DeclaredAccess {
                effect,
                holds: None,
            })
            .collect();
        let clause_spans = (0..u32::try_from(ordered.len()).unwrap_or(u32::MAX))
            .map(|index| (index, 1))
            .collect();
        Self {
            clause_taken: vec![true; ordered.len()],
            set,
            ordered,
            clause_spans,
        }
    }

    /// The same declaration, with what each entry of
    /// [`Declaration::ordered`] holds answered per effect.
    ///
    /// The companion to [`Declaration::from_set`], and needed for the
    /// same reason: a set has discarded the clauses that would have said
    /// what a cell holds, so a caller that built one by hand is the only
    /// thing left that knows. A movement through a cell that says
    /// nothing is refused at materialization, which is what makes this
    /// the difference between a fixture that transfers and one that does
    /// not.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn denominated(mut self, holds: impl Fn(&Effect) -> Option<Denomination>) -> Self {
        for entry in &mut self.ordered {
            entry.holds = holds(&entry.effect);
        }
        self
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
        // A clause depth of zero is a clause an ABI binding can name, so
        // its verdict is one the guest may be handed. Deeper ones are
        // inside a `for-each` body, where no fixed export parameter
        // reaches them.
        let taken = match clause.guard() {
            Some(cond) => as_bool(eval_expr(cond, inputs, hasher, bindings, 0)?)?,
            None => true,
        };
        if budget.clause_depth == 0 {
            out.clause_taken.push(taken);
        }
        if !taken {
            continue;
        }
        match clause {
            Clause::Effect {
                target,
                mode,
                denomination,
                ..
            } => {
                let target = eval_target(target, inputs, hasher, bindings)?;
                let mode = eval_mode(mode, inputs, hasher, bindings)?;
                budget.charge()?;
                // Evaluated beside the key it belongs to and kept parallel
                // to `ordered`, because a capability's rep is its index
                // there — the same alignment the guest's handles ride.
                let held = match denomination {
                    Some(expr) => match eval_expr(expr, inputs, hasher, bindings, 0)? {
                        Value::Address(address) => Some(Denomination::try_from(address)?),
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
                out.ordered.push(DeclaredAccess {
                    effect,
                    holds: held,
                });
            }
            Clause::ForEach { list, body, .. } => {
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

/// Fold a target's slot and evaluated material into the collection
/// identity everything downstream compares.
fn eval_collection(
    owner: Address,
    slot: SlotId,
    material: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<CollectionId, EvalError> {
    let encoded = eval_material(material, inputs, hasher, bindings, 0)?;
    Ok(collection_id(hasher, owner, slot, &encoded))
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
fn bucket_parts(value: Value) -> Result<(Denomination, EdgeContent), EvalError> {
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
    let sub = |expr| eval_expr(expr, inputs, hasher, bindings, deeper);
    let material = |material| eval_material(material, inputs, hasher, bindings, deeper);
    let all = |elements| eval_all(elements, inputs, hasher, bindings, deeper);
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
        Expr::Field(tuple, index) => field(&as_tuple(sub(tuple)?)?, *index),
        Expr::ResourceOf(bucket) => Ok(Value::Address(bucket_parts(sub(bucket)?)?.0.into())),
        Expr::IdsOf(bucket) => edge_ids(bucket_parts(sub(bucket)?)?.1),
        Expr::Lookup { map, key } => lookup(as_list(sub(map)?)?, &sub(key)?),
        Expr::SelfResource { material: parts } => Ok(Value::Address(
            resource_address(hasher, inputs.self_addr, &material(parts)?).into(),
        )),
        Expr::ChildKey {
            owner,
            slot,
            material: parts,
        } => Ok(Value::Key(child_key(
            hasher,
            as_address(sub(owner)?)?,
            *slot,
            &material(parts)?,
        ))),
        Expr::OrderKey {
            owner,
            slot,
            material: parts,
        } => Ok(Value::U128(order_key(
            hasher,
            as_address(sub(owner)?)?,
            *slot,
            &material(parts)?,
        ))),
        Expr::FreshId { slot } => Ok(Value::U64(inputs.fresh_id(hasher, *slot))),
        Expr::FreshKey { slot } => Ok(Value::Key(inputs.fresh_key(hasher, *slot))),
        Expr::Pack { hi, lo } => {
            let hi = as_u64(sub(hi)?)?;
            let lo = as_u64(sub(lo)?)?;
            Ok(Value::U128((u128::from(hi) << 64) | u128::from(lo)))
        }
        Expr::List(elements) => Ok(Value::List(all(elements)?)),
        Expr::Tuple(fields) => Ok(Value::Tuple(all(fields)?)),
        Expr::NfBucket { resource, ids } => Ok(Value::Bucket {
            resource: Denomination::try_from(as_address(sub(resource)?)?)?,
            content: EdgeContent::NonFungible {
                ids: id_set(as_list(sub(ids)?)?)?,
            },
        }),
        Expr::Not(inner) => Ok(Value::Bool(!as_bool(sub(inner)?)?)),
        // Short-circuiting: a false `And` and a true `Or` are answered by
        // the left operand alone, and the right one is never evaluated.
        // That is what lets one arm of a judgment be an expression the
        // other case would refuse.
        Expr::And(left, right) | Expr::Or(left, right) => {
            let short = matches!(expr, Expr::Or(..));
            if as_bool(sub(left)?)? == short {
                return Ok(Value::Bool(short));
            }
            Ok(Value::Bool(as_bool(sub(right)?)?))
        }
        Expr::Eq(left, right) => equals(&sub(left)?, &sub(right)?),
        Expr::Lt(left, right) => less_than(&sub(left)?, &sub(right)?),
        Expr::Contains { map, key } => Ok(Value::Bool(
            find(as_list(sub(map)?)?, &sub(key)?)?.is_some(),
        )),
        Expr::If {
            cond,
            then,
            otherwise,
        } => sub(if as_bool(sub(cond)?)? {
            then
        } else {
            otherwise
        }),
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
    find(pairs, key)?.ok_or(EvalError::LookupMiss)
}

/// The first matching pair's value, or `None` where the table holds no
/// such key. The one walk under both [`Expr::Lookup`], which refuses a
/// miss, and [`Expr::Contains`], which reports it.
fn find(pairs: Vec<Value>, key: &Value) -> Result<Option<Value>, EvalError> {
    for pair in pairs {
        let Value::Tuple(fields) = pair else {
            return Err(EvalError::LookupNotPairs);
        };
        let [pair_key, pair_value] = fields.as_slice() else {
            return Err(EvalError::LookupNotPairs);
        };
        if pair_key == key {
            return Ok(Some(pair_value.clone()));
        }
    }
    Ok(None)
}

/// Structural equality between two values of one kind.
///
/// Kinds must agree — a `u64` and a `u128` of the same magnitude are not
/// equal, because the widening that would make them so is a comparison
/// nobody wrote. A bucket anywhere in either operand is refused.
fn equals(left: &Value, right: &Value) -> Result<Value, EvalError> {
    reject_bucket(left)?;
    reject_bucket(right)?;
    if left.kind() != right.kind() {
        return Err(EvalError::TypeMismatch {
            expected: left.kind(),
            found: right.kind(),
        });
    }
    Ok(Value::Bool(left == right))
}

/// Strict ordering over the two integer widths, and nothing else.
fn less_than(left: &Value, right: &Value) -> Result<Value, EvalError> {
    match (left, right) {
        (Value::U64(left), Value::U64(right)) => Ok(Value::Bool(left < right)),
        (Value::U128(left), Value::U128(right)) => Ok(Value::Bool(left < right)),
        (Value::U64(_), other) => Err(EvalError::TypeMismatch {
            expected: "u64",
            found: other.kind(),
        }),
        (Value::U128(_), other) => Err(EvalError::TypeMismatch {
            expected: "u128",
            found: other.kind(),
        }),
        (other, _) => Err(EvalError::TypeMismatch {
            expected: "u64 or u128",
            found: other.kind(),
        }),
    }
}

/// Refuse a bucket wherever it sits in a value, including inside a tuple
/// or a list. Walked over an explicit stack, like [`Value::depth`], for
/// the same reason.
fn reject_bucket(value: &Value) -> Result<(), EvalError> {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Bucket { .. } => {
                return Err(EvalError::TypeMismatch {
                    expected: "a comparable value",
                    found: "bucket",
                });
            }
            Value::Tuple(values) | Value::List(values) => stack.extend(values),
            _ => {}
        }
    }
    Ok(())
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

fn as_bool(value: Value) -> Result<bool, EvalError> {
    match value {
        Value::Bool(flag) => Ok(flag),
        other => Err(EvalError::TypeMismatch {
            expected: "bool",
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
    use hyperscale_vm_types::{
        Address, AddressClass, Denomination, Effect, EffectTarget, Mode, NotAResource, Presence,
        ResourceAddr,
    };

    use super::{
        Clause, EvalError, EvalInputs, Expr, MAX_CLAUSE_DEPTH, MAX_EXPR_DEPTH,
        MAX_FOREACH_ELEMENTS, ModeExpr, TargetExpr, evaluate_declaration, evaluate_effects,
        evaluate_expr, fresh_id, fresh_local,
    };
    use crate::hash::{Hash32, TestHasher};
    use crate::manifest::ManifestHash;
    use crate::resource::issued_resource;
    use crate::types::{
        EdgeContent, MAX_IDS_PER_EDGE, SlotId, Value, child_key, collection_id, order_key,
    };

    /// Every constructor, each subterm a distinct marker: the walk
    /// answers exactly the markers, in order. A new variant fails the
    /// `children` match before it reaches here; what this pins is that no
    /// arm quietly drops one of its variant's fields — the miss every
    /// structural walk would then share.
    #[test]
    fn children_reach_every_subterm() {
        let leaf = |marker: u32| Expr::Arg(marker);
        let boxed = |marker: u32| Box::new(leaf(marker));
        let cases: Vec<(Expr, Vec<u32>)> = vec![
            (Expr::Literal(Value::U64(0)), vec![]),
            (Expr::Arg(0), vec![]),
            (Expr::Config(0), vec![]),
            (Expr::Binding(0), vec![]),
            (Expr::SelfAddr, vec![]),
            (Expr::FreshId { slot: 0 }, vec![]),
            (Expr::FreshKey { slot: 0 }, vec![]),
            (Expr::Field(boxed(1), 0), vec![1]),
            (Expr::ResourceOf(boxed(1)), vec![1]),
            (Expr::IdsOf(boxed(1)), vec![1]),
            (Expr::Not(boxed(1)), vec![1]),
            (Expr::List(vec![leaf(1), leaf(2)]), vec![1, 2]),
            (Expr::Tuple(vec![leaf(1), leaf(2)]), vec![1, 2]),
            (
                Expr::SelfResource {
                    material: vec![leaf(1), leaf(2)],
                },
                vec![1, 2],
            ),
            (
                Expr::NfBucket {
                    resource: boxed(1),
                    ids: boxed(2),
                },
                vec![1, 2],
            ),
            (
                Expr::Lookup {
                    map: boxed(1),
                    key: boxed(2),
                },
                vec![1, 2],
            ),
            (
                Expr::Contains {
                    map: boxed(1),
                    key: boxed(2),
                },
                vec![1, 2],
            ),
            (
                Expr::ChildKey {
                    owner: boxed(1),
                    slot: SlotId(0),
                    material: vec![leaf(2), leaf(3)],
                },
                vec![1, 2, 3],
            ),
            (
                Expr::OrderKey {
                    owner: boxed(1),
                    slot: SlotId(0),
                    material: vec![leaf(2), leaf(3)],
                },
                vec![1, 2, 3],
            ),
            (
                Expr::Pack {
                    hi: boxed(1),
                    lo: boxed(2),
                },
                vec![1, 2],
            ),
            (Expr::And(boxed(1), boxed(2)), vec![1, 2]),
            (Expr::Or(boxed(1), boxed(2)), vec![1, 2]),
            (Expr::Eq(boxed(1), boxed(2)), vec![1, 2]),
            (Expr::Lt(boxed(1), boxed(2)), vec![1, 2]),
            (
                Expr::If {
                    cond: boxed(1),
                    then: boxed(2),
                    otherwise: boxed(3),
                },
                vec![1, 2, 3],
            ),
        ];
        for (expr, want) in cases {
            let got: Vec<u32> = expr
                .children()
                .map(|child| match child {
                    Expr::Arg(marker) => *marker,
                    other => panic!("{other:?} is not a marker"),
                })
                .collect();
            assert_eq!(got, want, "{expr:?}");
        }
    }

    fn inputs<'a>(args: &'a [Value], config: &'a [Value]) -> EvalInputs<'a> {
        EvalInputs {
            self_addr: Address::new([7; 31], AddressClass::Component),
            args,
            config,
            node_index: 3,
            identity: ManifestHash(Hash32([9; 32])),
        }
    }

    /// The routed grant is lowered through `issued_resource`, and a
    /// body's `issued(mark)` evaluates `SelfResource` over the mark as a
    /// byte literal — one address either way, because the mark's
    /// encoding into derivation material is spelled once.
    #[test]
    fn a_self_resource_over_a_mark_literal_is_the_issued_resource() {
        let context = inputs(&[], &[]);
        for mark in [&b""[..], b"unit"] {
            let material = if mark.is_empty() {
                Vec::new()
            } else {
                vec![Expr::Literal(Value::Bytes(mark.to_vec()))]
            };
            assert_eq!(
                evaluate_expr(&Expr::SelfResource { material }, &context, &TestHasher),
                Ok(Value::Address(
                    issued_resource(&TestHasher, context.self_addr, mark).into()
                )),
            );
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
                SlotId(1),
                &[],
            ))))
        };
        let clauses = vec![
            Clause::Effect {
                guard: None,
                target: point(0xF0),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
            Clause::Effect {
                guard: None,
                target: point(0x0F),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            },
            // The same target as the first clause: a degenerate instance
            // configuration produces exactly this shape.
            Clause::Effect {
                guard: None,
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
        assert_eq!(id, Value::U64(fresh_id(&TestHasher, ins.identity, 3, 0)));
        assert_ne!(
            fresh_id(&TestHasher, ins.identity, 3, 0),
            fresh_id(&TestHasher, ins.identity, 3, 1)
        );
        assert_ne!(
            fresh_id(&TestHasher, ins.identity, 3, 0),
            fresh_id(&TestHasher, ins.identity, 4, 0)
        );
        let key = evaluate_expr(&Expr::FreshKey { slot: 2 }, &ins, &TestHasher).unwrap();
        let Value::Key(key) = key else { panic!() };
        assert_eq!(key.owner, ins.self_addr);
        assert_eq!(key.local, fresh_local(&TestHasher, ins.identity, 3, 2));
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
            guard: None,
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Field(Box::new(Expr::Binding(0)), 0)),
                    slot: SlotId(1),
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
                SlotId(1),
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
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(1),
                material: vec![],
            }),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let nest = |depth: usize| {
            let mut clause = effect.clone();
            for _ in 0..depth {
                clause = Clause::ForEach {
                    guard: None,
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
            guard: None,
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
            guard: None,
            list: Expr::Arg(0),
            body: Vec::new(),
        };
        for _ in 1..MAX_CLAUSE_DEPTH {
            clause = Clause::ForEach {
                guard: None,
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
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(1),
                material: vec![],
            }),
            mode: ModeExpr::Read,
            denomination: None,
        };
        for _ in 0..MAX_CLAUSE_DEPTH {
            clause = Clause::ForEach {
                guard: None,
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
                guard: None,
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: SlotId(4),
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
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotId(9),
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
                collection: collection_id(&TestHasher, ins.self_addr, SlotId(4), &[]),
                lo: 100,
                hi: 110,
                cap: 16,
            },
            mode: Mode::Write {
                requires: Presence::Either
            },
        }));
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(child_key(&TestHasher, ins.self_addr, SlotId(9), &[])),
            mode: Mode::Locked,
        }));

        let inverted = [Clause::Effect {
            guard: None,
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: SlotId(4),
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
        // One slot, two materials: two collections. The identity folds the
        // owner, the slot, and the evaluated material, so an entry target
        // parameterized by an argument lands in the argument's collection.
        let resource_a = Value::Address(Address::new([0xAA; 31], AddressClass::Resource));
        let resource_b = Value::Address(Address::new([0xBB; 31], AddressClass::Resource));
        let args = [resource_a.clone(), resource_b.clone()];
        let ins = inputs(&args, &[]);
        let entry_for = |slot: u32| Clause::Effect {
            guard: None,
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: SlotId(4),
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
                SlotId(4),
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

        // Same derivation, different slot: a third collection. The salt
        // arms are each load-bearing.
        assert_ne!(id_for(&resource_a), id_for(&resource_b));
        assert_ne!(
            collection_id(&TestHasher, ins.self_addr, SlotId(4), &[]),
            collection_id(&TestHasher, ins.self_addr, SlotId(5), &[]),
        );
        let other = Address::new([8; 31], AddressClass::Component);
        assert_ne!(
            collection_id(&TestHasher, ins.self_addr, SlotId(4), &[]),
            collection_id(&TestHasher, other, SlotId(4), &[]),
        );
    }

    #[test]
    fn order_keys_hash_the_logical_key_under_the_collections_salt() {
        let name_a = Value::U64(7);
        let name_b = Value::U64(8);
        let args = [name_a.clone(), name_b.clone()];
        let ins = inputs(&args, &[]);
        let entry_for = |slot: u32| Clause::Effect {
            guard: None,
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: SlotId(2),
                material: vec![],
                order: Expr::OrderKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotId(2),
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
                SlotId(2),
                &[name.canonical_bytes()],
            )
        };
        assert_eq!(set.len(), 2, "distinct keys land at distinct orders");
        for name in [&name_a, &name_b] {
            assert!(set.contains(&Effect {
                target: EffectTarget::Entry {
                    owner: ins.self_addr,
                    collection: collection_id(&TestHasher, ins.self_addr, SlotId(2), &[]),
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
            order_key(&TestHasher, ins.self_addr, SlotId(2), &[]),
            order_key(&TestHasher, ins.self_addr, SlotId(3), &[]),
        );
        let other = Address::new([8; 31], AddressClass::Component);
        assert_ne!(
            order_key(&TestHasher, ins.self_addr, SlotId(2), &[]),
            order_key(&TestHasher, other, SlotId(2), &[]),
        );
        assert_ne!(
            order_key(&TestHasher, ins.self_addr, SlotId(2), &[]).to_be_bytes(),
            collection_id(&TestHasher, ins.self_addr, SlotId(2), &[]).0,
        );
    }

    #[test]
    fn ids_of_projects_a_non_fungible_edge() {
        let bucket = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]).into(),
            content: EdgeContent::NonFungible { ids: vec![7, 9] },
        };
        let fungible = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]).into(),
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
            .map(|slot| fresh_id(&TestHasher, ins.identity, ins.node_index, slot))
            .collect();
        assert_eq!(
            evaluate_expr(&minted, &ins, &TestHasher),
            Ok(Value::Bucket {
                resource: Denomination::try_from(resource).expect("resource class"),
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
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(1),
                material: vec![Expr::Arg(0)],
            }),
            mode: ModeExpr::Reserve(Expr::Arg(1)),
            denomination: None,
        }];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        let expected = child_key(
            &TestHasher,
            ins.self_addr,
            SlotId(1),
            &[args[0].canonical_bytes()],
        );
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(expected),
            mode: Mode::Reserve { amount: 75 },
        }));
    }

    /// A denomination evaluates to a resource, whoever authored the
    /// declaration: an address of any other class is refused where the
    /// clause is evaluated, naming the class it found.
    #[test]
    fn a_denomination_that_names_no_resource_is_refused() {
        let component = Address::new([0xCC; 31], AddressClass::Component);
        let args = [Value::Address(component)];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(1),
                material: vec![Expr::Arg(0)],
            }),
            mode: ModeExpr::Delta,
            denomination: Some(Box::new(Expr::Arg(0))),
        }];
        assert_eq!(
            evaluate_declaration(&clauses, &ins, &TestHasher),
            Err(EvalError::NotAResource(NotAResource {
                found: AddressClass::Component,
            })),
        );
    }

    /// The judgment vocabulary, over one set of inputs: arg 0 is a `u64`,
    /// arg 1 the same `u64` widened, arg 2 an address, arg 3 a bucket of
    /// it, and config 0 a two-row table.
    fn judgment_args() -> [Value; 4] {
        let resource = Address::new([0xAB; 31], AddressClass::Resource);
        [
            Value::U64(7),
            Value::U128(7),
            Value::Address(resource),
            Value::Bucket {
                resource: Denomination::try_from(resource).expect("resource class"),
                content: EdgeContent::Fungible,
            },
        ]
    }

    fn table() -> Value {
        Value::List(vec![
            Value::Tuple(vec![Value::U64(7), Value::U64(70)]),
            Value::Tuple(vec![Value::U64(8), Value::U64(80)]),
        ])
    }

    fn judge(expr: &Expr) -> Result<Value, EvalError> {
        let args = judgment_args();
        let config = [table()];
        evaluate_expr(expr, &inputs(&args, &config), &TestHasher)
    }

    fn lit(value: Value) -> Expr {
        Expr::Literal(value)
    }

    fn flag(value: bool) -> Expr {
        lit(Value::Bool(value))
    }

    fn num(value: u64) -> Expr {
        lit(Value::U64(value))
    }

    fn not(inner: Expr) -> Expr {
        Expr::Not(Box::new(inner))
    }

    fn and(left: Expr, right: Expr) -> Expr {
        Expr::And(Box::new(left), Box::new(right))
    }

    fn or(left: Expr, right: Expr) -> Expr {
        Expr::Or(Box::new(left), Box::new(right))
    }

    fn eq(left: Expr, right: Expr) -> Expr {
        Expr::Eq(Box::new(left), Box::new(right))
    }

    fn lt(left: Expr, right: Expr) -> Expr {
        Expr::Lt(Box::new(left), Box::new(right))
    }

    fn contains(map: Expr, key: Expr) -> Expr {
        Expr::Contains {
            map: Box::new(map),
            key: Box::new(key),
        }
    }

    fn select(cond: Expr, then: Expr, otherwise: Expr) -> Expr {
        Expr::If {
            cond: Box::new(cond),
            then: Box::new(then),
            otherwise: Box::new(otherwise),
        }
    }

    /// The kind an expression required against the kind it found.
    fn mismatch<T>(expected: &'static str, found: &'static str) -> Result<T, EvalError> {
        Err(EvalError::TypeMismatch { expected, found })
    }

    /// A judgment's verdict, for the assertions that want the answer
    /// rather than the value carrying it.
    fn judged(expr: &Expr) -> Result<bool, EvalError> {
        judge(expr).map(|value| match value {
            Value::Bool(flag) => flag,
            other => panic!("a judgment evaluated to a {}", other.kind()),
        })
    }

    #[test]
    fn negation_conjunction_and_disjunction_take_booleans() {
        assert_eq!(judged(&not(flag(true))), Ok(false));
        assert_eq!(judged(&and(flag(true), flag(false))), Ok(false));
        assert_eq!(judged(&and(flag(true), flag(true))), Ok(true));
        assert_eq!(judged(&or(flag(false), flag(true))), Ok(true));
        assert_eq!(judged(&or(flag(false), flag(false))), Ok(false));
        assert_eq!(judged(&not(num(1))), mismatch("bool", "u64"));
    }

    #[test]
    fn conjunction_and_disjunction_short_circuit() {
        // The right operand would refuse on its own, so evaluating it is
        // the only way these could fail.
        let refuses = || Expr::Arg(9);
        assert_eq!(judged(&and(flag(false), refuses())), Ok(false));
        assert_eq!(judged(&or(flag(true), refuses())), Ok(true));
        // And the same operand still refuses where the answer needs it.
        assert_eq!(
            judged(&and(flag(true), refuses())),
            Err(EvalError::ArgOutOfRange(9))
        );
    }

    #[test]
    fn equality_compares_within_one_kind() {
        assert_eq!(judged(&eq(num(7), Expr::Arg(0))), Ok(true));
        assert_eq!(judged(&eq(num(8), Expr::Arg(0))), Ok(false));
        // Tuples and lists compare structurally, which is what makes a
        // pair equal to a pair.
        let pair = |a, b| lit(Value::Tuple(vec![Value::U64(a), Value::U64(b)]));
        assert_eq!(judged(&eq(pair(1, 2), pair(1, 2))), Ok(true));
        assert_eq!(judged(&eq(pair(1, 2), pair(2, 1))), Ok(false));
        // A u64 and a u128 of one magnitude are two kinds, not one value.
        assert_eq!(
            judged(&eq(Expr::Arg(0), Expr::Arg(1))),
            mismatch("u64", "u128")
        );
    }

    #[test]
    fn equality_refuses_a_bucket_wherever_it_sits() {
        let bucket = || Expr::Arg(3);
        let refused = mismatch("a comparable value", "bucket");
        assert_eq!(judged(&eq(bucket(), bucket())), refused);
        assert_eq!(judged(&eq(bucket(), num(1))), refused);
        assert_eq!(judged(&eq(num(1), bucket())), refused);
        // Nested is the case that matters: a pair of buckets comparing
        // equal would answer a question about amounts it cannot see.
        let wrapped = || Expr::Tuple(vec![bucket(), num(1)]);
        assert_eq!(judged(&eq(wrapped(), wrapped())), refused);
        // The resource an edge carries is comparable; the edge is not.
        assert_eq!(
            judged(&eq(Expr::ResourceOf(Box::new(bucket())), Expr::Arg(2))),
            Ok(true)
        );
    }

    #[test]
    fn ordering_holds_to_one_integer_width() {
        let amount = |value: u128| lit(Value::U128(value));
        assert_eq!(judged(&lt(num(6), num(7))), Ok(true));
        assert_eq!(judged(&lt(num(7), num(7))), Ok(false));
        assert_eq!(judged(&lt(amount(6), amount(7))), Ok(true));
        // No widening: the comparison nobody wrote is not the one made.
        assert_eq!(judged(&lt(num(6), amount(7))), mismatch("u64", "u128"));
        // An address has no meaningful order.
        assert_eq!(
            judged(&lt(Expr::Arg(2), Expr::Arg(2))),
            mismatch("u64 or u128", "address")
        );
    }

    #[test]
    fn membership_answers_what_lookup_refuses() {
        assert_eq!(judged(&contains(Expr::Config(0), num(7))), Ok(true));
        assert_eq!(judged(&contains(Expr::Config(0), num(9))), Ok(false));
        assert_eq!(
            judge(&Expr::Lookup {
                map: Box::new(Expr::Config(0)),
                key: Box::new(num(9)),
            }),
            Err(EvalError::LookupMiss)
        );
        // One walk under both, so a malformed table refuses identically.
        let ragged = lit(Value::List(vec![Value::U64(1)]));
        assert_eq!(
            judged(&contains(ragged, num(1))),
            Err(EvalError::LookupNotPairs)
        );
    }

    #[test]
    fn a_conditional_evaluates_only_the_taken_arm() {
        // The untaken arm is a lookup that would refuse, which is the
        // shape a package guards on membership to handle a miss itself.
        let guarded = |key: u64| {
            select(
                contains(Expr::Config(0), num(key)),
                Expr::Lookup {
                    map: Box::new(Expr::Config(0)),
                    key: Box::new(num(key)),
                },
                num(0),
            )
        };
        assert_eq!(judge(&guarded(7)), Ok(Value::U64(70)));
        assert_eq!(judge(&guarded(9)), Ok(Value::U64(0)));
        // And the condition itself is still judged.
        assert_eq!(
            judge(&select(num(1), num(1), num(0))),
            mismatch("bool", "u64")
        );
    }

    #[test]
    fn judgments_nest_under_the_expression_bound() {
        // One negation per level over a literal, so what rejects the
        // deeper expression is the bound and not its operand.
        let nested = |depth: usize| {
            let mut expr = flag(true);
            for _ in 0..depth {
                expr = not(expr);
            }
            expr
        };
        assert_eq!(judged(&nested(MAX_EXPR_DEPTH)), Ok(true));
        assert_eq!(
            judged(&nested(MAX_EXPR_DEPTH + 1)),
            Err(EvalError::ExpressionTooDeep)
        );
    }

    #[test]
    fn a_judgment_over_an_argument_reads_call_inputs() {
        // What keeps a guarded method's rule from being one a caller can
        // always satisfy: every new variant carries the taint through.
        let arg = || Expr::Arg(0);
        for expr in [
            not(eq(arg(), num(1))),
            and(eq(arg(), num(1)), flag(true)),
            and(flag(true), eq(arg(), num(1))),
            or(eq(arg(), num(1)), flag(true)),
            eq(arg(), num(1)),
            lt(arg(), num(1)),
            contains(Expr::Config(0), arg()),
            select(flag(true), arg(), num(1)),
            select(eq(arg(), num(1)), num(1), num(1)),
        ] {
            assert!(expr.reads_call_inputs(), "{expr:?}");
        }
        assert!(!not(eq(Expr::Config(0), Expr::SelfAddr)).reads_call_inputs());
    }
}
