//! The restricted access DSL and its evaluator.
//!
//! An effect signature is a total function from a method's typed inputs to
//! its declared `(key, mode)` set, written in this DSL: field projections,
//! keyed lookups over input values, canonical-address computation, bounded
//! collection mapping, point and range targets. No loops, no recursion, no
//! reads of state — the evaluator takes arguments, the target's
//! creation-fixed record, and a hasher, and nothing else, so evaluation is
//! pure by construction and identical on every node.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeMap;

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{
    Address, CollectionId, Effect, EffectConflict, EffectSet, EffectTarget, LocalKey, Mode, Moves,
    ResourceAddr, SubstateKey, WrongClass,
};

use crate::claim::Claim;
use crate::hash::{Hash32, Hasher};
use crate::instance::InstanceMeta;
use crate::manifest::{JudgedLeaf, ManifestHash};
use crate::resource::{
    GrantedBehaviour, GrantsExpr, GrantsResolveError, ResourceGrants, ResourceKind, ResourceMeta,
};
use crate::rule::{Rule, RuleExpr, RuleLeaf};
use crate::signature::MAX_PROVEN_PER_SIGNATURE;
use crate::types::{
    EdgeContent, KERNEL_SLOT_BASE, MAX_IDS_PER_EDGE, MAX_VALUE_ITEMS, PACKAGE_SLOT_BASE, SlotId,
    Value, child_key, collection_id, granting_resource_address, order_key,
};
use crate::vocabulary::{NF_VAULT, VAULT};

/// The bound on any collection a `for-each` clause maps over.
///
/// A bound on pre-payment work: evaluation happens at admission, before
/// any fee is assured, so no charge can pay for a longer list — the
/// ceiling is sized against the admission budget. The effects an
/// iteration lands are charged by `footprint` like any others.
///
/// [`MAX_VALUE_ITEMS`] itself, because a list a loop maps over is a
/// value and a value carries its own width bound: a decoded one cannot
/// exceed this before the loop is reached. What the check below still
/// stands for is a list evaluation *built* — the ids of an edge, an
/// `Expr::List` — which no decoder saw.
pub const MAX_FOREACH_ELEMENTS: usize = MAX_VALUE_ITEMS;

/// The bound on expression nesting. A recursion bound: the evaluator
/// recurses per subterm, so this is what keeps a pathological signature
/// a deterministic rejection rather than a native stack abort.
pub const MAX_EXPR_DEPTH: usize = 32;

/// The bound on what evaluating one signature may cost: subterms
/// evaluated, plus what a walk over each value they yield visits —
/// elements, and bytes at [`BYTES_PER_WORK_UNIT`] apiece.
///
/// The clause bound beside it counts what a signature *declares*, which
/// is what the footprint prices. This counts what deciding that costs,
/// which nothing prices: a lookup over a wide table and a bare
/// comparison land the same effects at the same footprint and differ by
/// three orders of magnitude in work, and evaluation happens at
/// admission, before any fee is assured.
///
/// Measured at both ends rather than chosen. Every charge is a shape's
/// measured cost expressed in the one unit and rounded up, so the meter
/// over-charges a cheap shape and never under-charges a dear one. A scan
/// pair is the cheapest thing charged a whole unit;
/// [`BYTES_PER_WORK_UNIT`] and [`WORK_PER_DERIVATION`] are the two costs
/// that needed a divisor and a multiplier to land on the same unit.
///
/// The widest evaluation the ceiling admits derives a key over three
/// hundred and seventy-five bytes of material per element across a full
/// `for-each`; the dearest signature the corpus declares spends three
/// hundred and sixty-four units, so the ceiling clears real work by a
/// factor near two hundred. What it refuses is the shape that motivated
/// it — eight four-kilobyte literals hashed into one key per element
/// across a full loop, which asks sixty times the ceiling at the clause
/// count and footprint of a signature that hashes one scalar.
///
/// [`MAX_EFFECTS_PER_SIGNATURE`] bounds the same evaluation by shape,
/// and the two agree: the most derived effects a signature can land come
/// to about half this, so the effect count binds first for an ordinary
/// target and the work meter binds first for a scan or for wide
/// material — which is what the meter exists to bound.
pub const MAX_EVALUATION_WORK: usize = 65_536;

/// The bytes of an opaque byte string one unit of work buys.
///
/// A byte string carries length without carrying elements, so counting
/// elements alone prices a four-kilobyte literal as a scalar — while
/// encoding one into a key's material hashes every byte of it. The
/// divisor is what makes the two comparable: encoding and hashing this
/// many bytes costs about what walking one subterm costs.
const BYTES_PER_WORK_UNIT: usize = 8;

/// What one derivation costs, in units.
///
/// The terms that hash — a child key, an order key, a fresh id or key,
/// an issued resource address — cost about this many subterm walks
/// apiece, where every other term costs one. Charged apart from the
/// subterm walk because a signature is free to land one derivation per
/// effect, and at a unit apiece the meter would price a thousand hashes
/// below a thousand comparisons.
const WORK_PER_DERIVATION: usize = 8;

/// The bound on what admitting one envelope may cost, across every node
/// in it.
///
/// [`MAX_EVALUATION_WORK`] bounds one signature; a tree holds up to
/// `MAX_MANIFEST_NODES` of them, and each node's denominations and
/// output projections are evaluations of their own. Admission runs at
/// ingress over unverified bytes — before a signature is checked, before
/// the envelope is in any block, and before any fee is assured — so what
/// an envelope costs whoever receives it is the per-signature ceiling
/// multiplied by the node cap unless something counts the tree.
///
/// Sized against the widest legitimate envelope rather than scaled off
/// the figure beside it: a full tree of the dearest signature the corpus
/// declares comes to about one and a half million units, so this clears
/// the widest real envelope by half again — where the per-signature
/// ceiling alone would admit a full tree of the dearest shape that fits
/// under it, over bytes nobody had yet checked a signature over.
///
/// What binds here is `MAX_MANIFEST_NODES`, not the meter: a full tree of
/// ordinary signatures costs what it costs whatever the unit is worth, so
/// admitting less work at ingress means admitting fewer nodes rather than
/// counting the same ones more strictly.
pub const MAX_ENVELOPE_EVALUATION_WORK: usize = 2_097_152;

/// The bound on `for-each` nesting within one signature.
///
/// A recursion bound like [`MAX_EXPR_DEPTH`]: the evaluator recurses per
/// clause scope, and width under nesting is
/// [`MAX_EFFECTS_PER_SIGNATURE`]'s to bound.
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
///
/// A bound on pre-payment work, on the terms [`MAX_FOREACH_ELEMENTS`]
/// states: evaluation runs before any fee is assured, so a ceiling
/// stands here where a charge stands on what the evaluation declares.
pub const MAX_EFFECTS_PER_SIGNATURE: usize = 4096;

/// A child key under the instance the method is running on.
///
/// The shape every package's own storage takes: a package declares
/// against itself, so `self` is the owner of everything it can reach.
#[must_use]
pub fn self_child(slot: SlotId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(slot),
        material,
    }
}

/// Which slot a key is derived under: the one the declaration wrote
/// down, or the one an argument names.
///
/// Fixed on every ordinary access, and that is what gives the per-slot
/// shape table its footing — it dispatches on the constant, and the
/// bands it refuses are refused before anything runs.
///
/// A reaching access is the one place the constant gives way. A package
/// holds value at any slot of its own, so an issuer's reach that listed
/// slots would leave every bespoke vault unreachable, which is the gap
/// the reach exists to close. What keeps a caller-chosen slot from being
/// a cell nobody judged is that the table's judgment is restated where
/// the slot finally has a value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum SlotRef {
    /// The slot the declaration names.
    Fixed(SlotId),
    /// The slot this expression evaluates to, admissible only on an
    /// access that declares the prefix it reaches.
    Reached(Box<Expr>),
}

impl From<SlotId> for SlotRef {
    fn from(slot: SlotId) -> Self {
        Self::Fixed(slot)
    }
}

impl SlotRef {
    /// The slot where the declaration wrote one down.
    #[must_use]
    pub const fn fixed(&self) -> Option<SlotId> {
        match self {
            Self::Fixed(slot) => Some(*slot),
            Self::Reached(_) => None,
        }
    }

    /// The expression a reached slot is named by.
    #[must_use]
    pub const fn reached(&self) -> Option<&Expr> {
        match self {
            Self::Fixed(_) => None,
            Self::Reached(expr) => Some(expr),
        }
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
    /// configuration, read from the record admission resolved the target
    /// with rather than through a declared effect.
    Config(u32),
    /// The current `for-each` element; `0` names the innermost binding.
    Binding(u32),
    /// The target instance's own address.
    SelfAddr,
    /// The target instance's whole creation-fixed record, as the
    /// canonical bytes the configuration leaf stores.
    ///
    /// Evaluated from the record admission resolved the target with, so
    /// a caller never chooses the bytes: what instantiation writes is
    /// what the address commits, or the transaction does not admit.
    SelfRecord,
    /// Tuple field projection.
    Field(Box<Self>, u32),
    /// The static resource type of a bucket edge.
    ResourceOf(Box<Self>),
    /// The static id set of a non-fungible bucket edge, as a list.
    IdsOf(Box<Self>),
    /// The length of a list, as a `u64`.
    ///
    /// What derives a bound from what a call names: a range cap over
    /// the instances an edge carries, or the ids an argument lists, is
    /// the count of them — so a move declares exactly the walk it
    /// performs and pays for nothing wider.
    Len(Box<Self>),
    /// The sole element of a list, refusing where the list is not one
    /// long.
    ///
    /// What lets a declaration reach the instance an edge carries
    /// without a caller naming its id: the ids are already the edge's,
    /// and an edge carrying exactly one names it. An edge carrying any
    /// other number fails here, so the transaction is refused before a
    /// body reads a cell that would have been a guess.
    Only(Box<Self>),
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
    /// [`MAX_IDS_PER_EDGE`] ids, each
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
        /// The resource's kind, folded into the derivation: what the
        /// instance issues under this material is one kind of thing,
        /// fixed where the declaration named it.
        kind: ResourceKind,
        /// The material separating this resource from the instance's
        /// others, canonically encoded into the derivation.
        material: Vec<Self>,
        /// The rules the resource's address grants, resolved against the
        /// issuing instance where this evaluates.
        ///
        /// Part of the derivation rather than beside it: the address is
        /// the hash of these too, so a resource whose rules changed
        /// would be a different resource, and the tier has a minter
        /// rather than only a verifier.
        grants: GrantsExpr,
    },
    /// The canonical child key `owner | H(slot, material…)`.
    ChildKey {
        /// The owning address.
        owner: Box<Self>,
        /// The child's slot under the owner.
        slot: SlotRef,
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
    /// A sum, over `u64` against `u64` and `u128` against `u128` and
    /// nothing else, on [`Expr::Lt`]'s terms. Overflow refuses rather
    /// than wraps: a declaration is a claim about keys and counts, and a
    /// wrapped one would be a different claim made silently.
    Add(Box<Self>, Box<Self>),
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
            | Self::SelfRecord
            | Self::FreshId { .. }
            | Self::FreshKey { .. } => {}
            Self::Field(inner, _)
            | Self::ResourceOf(inner)
            | Self::IdsOf(inner)
            | Self::Len(inner)
            | Self::Only(inner)
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
            | Self::Add(first, second)
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
            | Self::SelfResource {
                material: elements, ..
            } => children.extend(elements),
            Self::ChildKey {
                owner,
                slot,
                material,
            } => {
                children.push(owner);
                children.extend(slot.reached());
                children.extend(material);
            }
            Self::OrderKey {
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
    pub fn reads_call_inputs(&self) -> bool {
        self.is_input_leaf() || self.children().any(Self::reads_call_inputs)
    }
}

/// A mode with its parameters still unevaluated.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum ModeExpr {
    /// Fresh coherent read.
    Read,
    /// Commutative increment or decrement; no declared amount.
    Delta {
        /// Which directions value may move under it. Narrowed to
        /// [`Moves::In`], it is what a method that only receives says
        /// about itself.
        moves: Moves,
    },
    /// Conditional decrement of the evaluated amount. A decrement is its
    /// definition, so its direction is [`Moves::Out`] by being itself.
    Reserve(Expr),
    /// Exclusive read-modify-write.
    ///
    /// What the leaf must be for the write to land is not the mode's to
    /// say: a presence requirement is a `Requires` clause the same
    /// declaration states — which is what a wallet reads to say "this
    /// call creates your authority cell, and fails if you already have
    /// one" — judged by the shard holding the cell, where it already
    /// judges a reservation.
    Write {
        /// Which directions value may move under it, on the terms a
        /// delta's field states them — and the one way a method that
        /// files into a collection and never takes out of it can say
        /// so, since a collection's only movement mode is this one.
        moves: Moves,
    },
}

impl ModeExpr {
    /// Which directions value moves in under this mode, or `None` where
    /// it moves none.
    ///
    /// The declared twin of [`Mode::moves`], and the two agree by being
    /// read off one vocabulary: an evaluated mode carries exactly what
    /// its expression declared.
    #[must_use]
    pub const fn moves(&self) -> Option<Moves> {
        match self {
            Self::Read => None,
            Self::Delta { moves } | Self::Write { moves } => Some(*moves),
            Self::Reserve(_) => Some(Moves::Out),
        }
    }
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
        collection: SlotRef,
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
        collection: SlotRef,
        /// The material separating this collection from the slot's others,
        /// canonically encoded into its identity.
        material: Vec<Expr>,
        /// Inclusive lower bound.
        lo: Expr,
        /// Inclusive upper bound.
        hi: Expr,
        /// The maximum entries execution may touch, evaluated like the
        /// bounds beside it.
        ///
        /// The cap is the part of a declaration that buys execution work
        /// rather than key space, and `footprint` charges it as depth —
        /// which is what makes it safe to hand to a caller: a
        /// caller-chosen cap is a caller-chosen bill, priced like the
        /// rest of the declaration and bounded by the gas limit the
        /// sender signed.
        cap: Expr,
    },
}

impl TargetExpr {
    /// Every expression this target is built from.
    pub fn parts(&self) -> impl Iterator<Item = &Expr> {
        let mut parts: Vec<&Expr> = Vec::new();
        match self {
            Self::Point(key) => parts.push(key),
            Self::Entry {
                owner,
                collection,
                material,
                order,
            } => {
                parts.push(owner);
                parts.extend(collection.reached());
                parts.extend(material);
                parts.push(order);
            }
            Self::Range {
                owner,
                collection,
                material,
                lo,
                hi,
                cap,
            } => {
                parts.push(owner);
                parts.extend(collection.reached());
                parts.extend(material);
                parts.push(lo);
                parts.push(hi);
                parts.push(cap);
            }
        }
        parts.into_iter()
    }

    /// Whether resolving this target reads anything the caller supplies.
    #[must_use]
    pub fn reads_call_inputs(&self) -> bool {
        self.parts().any(Expr::reads_call_inputs)
    }
}

/// Whether the world hands out a handle for this clause at all.
///
/// A `for-each` clause yields `false`: naming one as a handle parameter
/// is a deterministic refusal at materialization, so there is nothing
/// single for an export to borrow. So does a mode and target pairing no
/// capability is built for.
///
/// Two callers, and neither can recover this from what it holds. The
/// publish gate refuses a clause materialization could not have backed,
/// before any evaluation. Routing asks the same question of the same
/// clause, so a handle position it fills is one an engine could have
/// built.
#[must_use]
pub const fn supports(clause: &Clause) -> bool {
    let Clause::Effect { target, mode, .. } = clause else {
        return false;
    };
    matches!(
        (target, mode),
        (
            TargetExpr::Point(_),
            ModeExpr::Read | ModeExpr::Write { .. } | ModeExpr::Delta { .. } | ModeExpr::Reserve(_)
        ) | (
            TargetExpr::Entry { .. } | TargetExpr::Range { .. },
            ModeExpr::Read | ModeExpr::Write { .. }
        )
    )
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
        /// The behaviour this access reaches a foreign prefix under,
        /// where it reaches one.
        ///
        /// The justification rather than a flag, and the only thing that
        /// lets a declaration name a cell that is not its own: the target
        /// is keyed first by a resource, and the entry that resource
        /// grants for this behaviour is injected at admission and judged
        /// against what the call presented. Absent for every ordinary
        /// access, which names its own instance's prefix and answers to
        /// the movement entries instead.
        reach: Option<GrantedBehaviour>,
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
    /// A precondition, contributing no access of its own.
    ///
    /// Judged where its state lives: a presence condition at
    /// materialization, by the shard holding the leaf; an authority
    /// condition at the declaring node's call, with its presented
    /// evidence.
    Requires {
        /// When this clause is declared at all, or always where absent.
        guard: Option<Box<Expr>>,
        /// The precondition, as a rule over the three sources a leaf may
        /// read: what the call presented, a rule held in a cell, and a
        /// cell's presence. Where it is judged follows from which of
        /// those its leaves reach and is stated nowhere.
        rule: RuleExpr,
    },
    /// A claim this call proves as evidence for the intent's later nodes.
    ///
    /// Justified by a condition the same declaration carries, and the
    /// publish check refuses one that is not: proving one's own identity
    /// takes satisfying one's own stored rule, and proving a badge takes
    /// that plus holding it — the possession read keyed by the same
    /// expression, so the claim proven and the thing held are one
    /// resource because one expression writes both.
    Proves {
        /// When this clause is declared at all, or always where absent.
        guard: Option<Box<Expr>>,
        /// What is proven: the target's own address for an identity, a
        /// badge resource, or a `(badge, id)` pair for one instance.
        claim: Expr,
    },
}

impl Clause {
    /// The condition this clause is declared under, where it carries one.
    #[must_use]
    pub const fn guard(&self) -> Option<&Expr> {
        match self {
            Self::Effect { guard, .. }
            | Self::ForEach { guard, .. }
            | Self::Requires { guard, .. }
            | Self::Proves { guard, .. } => match guard {
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
    /// A reaching access whose target is keyed by nothing, so there is no
    /// resource whose entry could admit it.
    #[error("an access reaching a foreign prefix is keyed by no resource")]
    UnkeyedReach,
    /// A slot an argument named that keeps no value, so no reach can be
    /// about it.
    #[error("slot {0} keeps no value, so nothing reaches it")]
    UnreachableSlot(u64),
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
    NotAResource(#[from] WrongClass),
    /// A resource whose declared granted rules do not resolve against
    /// the instance issuing it.
    #[error(transparent)]
    GrantsUnresolvable(#[from] GrantsResolveError),
    /// A target's record that does not encode under the vocabulary's
    /// caps. Nothing admission resolves a target with can be one — a
    /// record is checked by re-encoding it — so this is spoken as a
    /// refusal rather than taken on trust.
    #[error("the target's record does not encode within the vocabulary's caps")]
    RecordMalformed,
    /// A tuple projection past the tuple's arity.
    #[error("tuple field {index} out of range (arity {arity})")]
    FieldOutOfRange {
        /// The projected index.
        index: u32,
        /// The tuple's arity.
        arity: usize,
    },
    /// A range cap past the width the interval vocabulary counts
    /// entries in.
    #[error("range cap {0} exceeds the u32 an interval counts entries in")]
    CapTooWide(u128),
    /// A sum past its operands' width.
    #[error("addition overflows the width of its operands")]
    AddOverflow,
    /// A list read for its sole element that holds some other number
    /// of them.
    #[error("a list of {len} has no sole element")]
    NotSingleton {
        /// How many elements the list held.
        len: usize,
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
    /// A declaration that evaluated to more proven claims than
    /// [`MAX_PROVEN_PER_SIGNATURE`]. Publish counts the `Proves` clauses
    /// against the same cap, so this is reachable only where one clause
    /// yields many claims — a `Proves` inside a `for-each`, multiplied by
    /// the list a caller supplied.
    #[error("the declaration proves more than {MAX_PROVEN_PER_SIGNATURE} claims")]
    ProvesPastCap,
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
    /// A signature whose evaluation spends more than
    /// [`MAX_EVALUATION_WORK`] — subterms evaluated plus what walking
    /// each value they yield costs, which is what the clause count above
    /// does not see.
    #[error("signature evaluation exceeds {MAX_EVALUATION_WORK} units of work")]
    TooMuchWork,
    /// An envelope whose nodes together spend more than
    /// [`MAX_ENVELOPE_EVALUATION_WORK`] — the bound the per-signature one
    /// above does not give, since a tree holds up to `MAX_MANIFEST_NODES`
    /// signatures and admission runs before any fee is assured.
    #[error("envelope admission exceeds {MAX_ENVELOPE_EVALUATION_WORK} units of work")]
    EnvelopeTooMuchWork,
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
    /// The target instance's creation-fixed record, as admission
    /// resolved it.
    pub record: &'a InstanceMeta,
    /// The invoking manifest node's index; namespaces fresh IDs.
    pub node_index: u32,
    /// The transaction's identity — the signed graph's hash; the one root
    /// of every fresh-ID derivation.
    pub identity: ManifestHash,
    /// The granted rules the envelope presented, each verified at the
    /// address its own record derives. Not state: a presented claim, on
    /// the terms an instance's record is.
    pub grants: &'a PresentedGrants,
    /// What admitting this envelope has spent so far. Shared by every
    /// node in one tree, so what bounds a caller is the tree rather than
    /// whichever signature it happened to reach.
    pub budget: &'a EvalBudget,
}

/// The granted rules an envelope presented, by the address each record
/// derives — first registration wins, and a false record registers a
/// different resource.
#[derive(Clone, Debug)]
pub struct PresentedGrants(BTreeMap<ResourceAddr, ResourceGrants>);

impl PresentedGrants {
    /// No records presented: what every plain graph evaluates over.
    #[must_use]
    pub fn none() -> &'static Self {
        static NONE: PresentedGrants = PresentedGrants(BTreeMap::new());
        &NONE
    }

    /// The presented records, each registered at exactly the address it
    /// derives.
    #[must_use]
    pub fn from_presented(hasher: &dyn Hasher, records: &[ResourceMeta]) -> Self {
        let mut granted = BTreeMap::new();
        for record in records {
            granted
                .entry(record.address(hasher))
                .or_insert_with(|| record.rules.clone());
        }
        Self(granted)
    }

    /// The granted rules of `resource`, where its record was presented.
    #[must_use]
    pub fn rules(&self, resource: ResourceAddr) -> Option<&ResourceGrants> {
        self.0.get(&resource)
    }
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
    pub holds: Option<ResourceAddr>,
    /// The behaviour this access reaches a foreign prefix under, carried
    /// through from the clause that declared it.
    ///
    /// One field answering three questions that would otherwise be three
    /// carve-outs: whether the access may name a prefix that is not the
    /// frame's, whether it earns the movement requirements a holder's own
    /// access earns — it does not, because every one of them would fire
    /// against the party being reached — and which entry admits it.
    pub reach: Option<Reach>,
    /// The clause this access evaluated from, numbered in the preorder
    /// walk of the method's effects — the numbering a rendered listing
    /// gives its lines, so a refusal carrying this number points at a
    /// line the author can read. Every element of a `for-each` carries
    /// its body clause's one number, because one line declared them all.
    ///
    /// `None` for an access no clause wrote: a read admission injects
    /// beside a condition, or a declaration assembled outside a
    /// signature's evaluation.
    pub clause: Option<u32>,
}

/// What lets one access name a prefix that is not the declaring
/// instance's own.
///
/// Both halves, because neither answers on its own: the behaviour says
/// which of the reached resource's entries is asked, and the resource
/// says whose. It is the resource the key was *derived from* rather than
/// one read back out of it — a key is a hash and inverts to nothing — so
/// the entry judged is always the entry of the thing actually reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reach {
    /// The authority the reach is made under.
    pub behaviour: GrantedBehaviour,
    /// The resource whose entry for it admits the reach.
    pub resource: ResourceAddr,
}

/// An evaluated condition, and the frame that states it.
///
/// The rule alone says what must hold and cannot say who asked, and a
/// key is a hash that inverts to nothing — so a reader handed a refused
/// condition can see that some leaf was wrong and never whose question
/// it was. That is the provenance an injected requirement already
/// carries at the frame, and this is what keeps it once several frames'
/// conditions are one list.
///
/// Without it the only way back is a search for a condition naming the
/// same leaf, which lands on whichever node happens to come first — so
/// a refusal can name a call that did not fail, and a rule a package
/// wrote can be read as the protocol's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// What must hold.
    pub rule: Rule<JudgedLeaf>,
    /// The manifest node whose frame states it.
    ///
    /// A frame's own evaluation is one node's and does not know its
    /// number, so it says nothing here; the lowering stamps it where
    /// the frame joins the union declaration, which is the only place
    /// several nodes' conditions meet and the only place the number
    /// answers anything.
    pub node: Option<u32>,
}

impl Condition {
    /// The condition a frame's own evaluation reaches, before it is
    /// placed.
    #[must_use]
    pub const fn declared(rule: Rule<JudgedLeaf>) -> Self {
        Self { rule, node: None }
    }
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
    /// the evaluation took, `for-each` bodies expanded in place.
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
    /// top-level clauses, whose `for-each` expansions occupy spans of the
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
    /// The evaluated conditions, in clause-evaluation order: every
    /// `Requires` clause the evaluation took and whose guard held.
    ///
    /// Contributing nothing to [`Declaration::set`] or
    /// [`Declaration::ordered`] — a condition is a judgment, not an
    /// access — and judged where each kind's state lives.
    pub conditions: Vec<Condition>,
    /// The claims this declaration proves, evaluated, an instance claim
    /// widened to its resource. What admission hands the intent's later
    /// nodes as this node's evidence.
    pub proves: Vec<Claim>,
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
    /// [`AbiParam::Guard`]: crate::AbiParam::Guard
    pub clause_taken: Vec<bool>,
    /// Where each expansion of a top-level `for-each` landed, keyed by
    /// that clause's index: a row per clause of the body, an entry per
    /// element.
    ///
    /// An entry names the position in [`Declaration::ordered`] the
    /// expansion produced, and is absent where it produced none — the
    /// site's guard did not fire, or the body clause declares no access
    /// of its own. A top-level `for-each` files its rows whether or not
    /// its *own* guard fired: one whose did not mapped over no elements,
    /// so its rows are empty and any of its sites covers nothing.
    /// Recorded rather than computed from
    /// [`Declaration::clause_spans`]: the flattened order alone cannot
    /// say which element or which site produced an entry, and a stride
    /// over it would be wrong the moment two sites are guarded
    /// differently.
    ///
    /// This is what an [`AbiParam::Handle`] binding resolves through, so
    /// the index a body walks is the *element* — every site in one body
    /// counts the same elements, and a site that did not fire reads
    /// absent rather than shortening the walk.
    ///
    /// [`AbiParam::Handle`]: crate::AbiParam::Handle
    pub expansions: BTreeMap<u32, Vec<Vec<Option<u32>>>>,
}

impl Declaration {
    /// What the conditions require, for a reader judging them rather
    /// than attributing them.
    ///
    /// The rules alone are what a judge needs; who asked is what a
    /// refusal needs, and the two readers are different enough that
    /// asking for one should not mean walking past the other.
    pub fn required(&self) -> impl Iterator<Item = &Rule<JudgedLeaf>> {
        self.conditions.iter().map(|condition| &condition.rule)
    }

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
                reach: None,
                effect,
                holds: None,
                clause: None,
            })
            .collect();
        let clause_spans = (0..u32::try_from(ordered.len()).unwrap_or(u32::MAX))
            .map(|index| (index, 1))
            .collect();
        Self {
            clause_taken: vec![true; ordered.len()],
            conditions: Vec::new(),
            proves: Vec::new(),
            set,
            ordered,
            clause_spans,
            expansions: BTreeMap::new(),
        }
    }

    /// The elements `site` of top-level `for-each` clause `clause`
    /// covers: one per element of the list it mapped, at the position in
    /// [`Declaration::ordered`] that expansion produced, or absent where
    /// it produced none.
    ///
    /// `None` where the clause is not a top-level `for-each` or the site
    /// is past its body — both of which the publish gate has already
    /// refused, so reaching one here is a defect rather than a package.
    #[must_use]
    pub fn elements(&self, clause: u32, site: u32) -> Option<&[Option<u32>]> {
        self.expansions
            .get(&clause)?
            .get(usize::try_from(site).ok()?)
            .map(Vec::as_slice)
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
    pub fn denominated(mut self, holds: impl Fn(&Effect) -> Option<ResourceAddr>) -> Self {
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
    let budget = Budget::new(inputs.budget);
    // One clause at a time, so each one's contribution to the flattened
    // order is bracketed as it is produced.
    for (index, clause) in clauses.iter().enumerate() {
        let start = out.ordered.len();
        // The clause's own index, so a `for-each` files its expansion
        // map under the number an ABI binding names it by.
        budget
            .clause
            .set(u32::try_from(index).map_err(|_| EvalError::TooManyEffects)?);
        eval_clauses(
            std::slice::from_ref(clause),
            inputs,
            hasher,
            &mut bindings,
            &mut out,
            &budget,
        )?;
        let len = out.ordered.len() - start;
        out.clause_spans.push((
            u32::try_from(start).map_err(|_| EvalError::TooManyEffects)?,
            u32::try_from(len).map_err(|_| EvalError::TooManyEffects)?,
        ));
    }
    Ok(out)
}

/// What admitting one envelope has spent, across every node in it.
///
/// The meter every signature in one tree reports into, where [`Budget`]
/// is the meter for one of them. Two ceilings rather than one because
/// they answer different questions: a per-signature bound is what a
/// package may declare, and this is what a caller may ask a node to
/// spend deciding a whole envelope. Sharing one figure would refuse a
/// wide manifest of ordinary calls; scaling one by the node cap would
/// admit a narrow one whose every node is the expensive shape.
#[derive(Debug, Default)]
pub struct EvalBudget {
    spent: Cell<usize>,
}

impl EvalBudget {
    /// Charge `units` against the envelope, refusing past the tree-wide
    /// bound. Deterministic, so every node reaches the same verdict.
    ///
    /// Reachable from admission as well as from evaluation: not every
    /// per-node cost an envelope pays is an expression, and the ones
    /// that are not are charged here rather than left uncounted.
    ///
    /// # Errors
    ///
    /// [`EvalError::EnvelopeTooMuchWork`] past the tree-wide bound.
    pub(crate) fn spend(&self, units: usize) -> Result<(), EvalError> {
        self.spent.set(self.spent.get().saturating_add(units));
        if self.spent.get() > MAX_ENVELOPE_EVALUATION_WORK {
            return Err(EvalError::EnvelopeTooMuchWork);
        }
        Ok(())
    }
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
///
/// Shared rather than threaded by `&mut`: an expression's evaluation is a
/// walk of closures over its subterms, and a subterm charges like
/// anything else — so the meter every arm reaches is one both halves of
/// the evaluation hold at once.
struct Budget<'a> {
    clause_depth: Cell<usize>,
    work: Cell<usize>,
    spent: Cell<usize>,
    /// The top-level clause being evaluated, which is the index a
    /// `for-each`'s expansion map is filed under.
    clause: Cell<u32>,
    /// The current clause's number in the preorder walk of the method's
    /// effects — the numbering a rendered listing gives its lines. It
    /// counts clause *text*: a loop's body numbers once however many
    /// elements the loop maps over, and a clause whose guard did not
    /// fire keeps its number, because the line exists whether or not it
    /// declared anything this run.
    preorder: Cell<u32>,
    /// The envelope meter every signature in one tree reports into.
    envelope: &'a EvalBudget,
}

impl<'a> Budget<'a> {
    /// A fresh signature allowance, reporting into `envelope`.
    fn new(envelope: &'a EvalBudget) -> Self {
        Self {
            clause_depth: Cell::default(),
            work: Cell::default(),
            spent: Cell::default(),
            clause: Cell::default(),
            preorder: Cell::default(),
            envelope,
        }
    }

    /// Charge one clause or one `for-each` iteration, refusing past the
    /// per-signature bound. Deterministic, so every node reaches the same
    /// verdict.
    fn charge(&self) -> Result<(), EvalError> {
        self.work.set(self.work.get() + 1);
        if self.work.get() > MAX_EFFECTS_PER_SIGNATURE {
            return Err(EvalError::TooManyEffects);
        }
        Ok(())
    }

    /// Charge `units` of expression work: one per subterm evaluated, and
    /// what [`walked`] measures for each value one yields.
    ///
    /// The counter beside [`Self::charge`] rather than the same one,
    /// because they bound different things. A clause count bounds the
    /// *shape* a signature declares, which is what the footprint prices;
    /// this bounds what evaluating that shape costs, which nothing
    /// prices — a table scan and a bare comparison land the same effects
    /// at the same footprint, and only this tells them apart.
    fn spend(&self, units: usize) -> Result<(), EvalError> {
        self.spent.set(self.spent.get().saturating_add(units));
        if self.spent.get() > MAX_EVALUATION_WORK {
            return Err(EvalError::TooMuchWork);
        }
        self.envelope.spend(units)
    }
}

/// One element's pass over a `for-each` body, noting where each of the
/// body's clauses landed in the flattened order.
///
/// The body is walked clause by clause rather than in one call, because
/// what a site needs is which *body position* produced an entry — and the
/// flattened order on its own cannot say. A clause that declares no
/// access of its own records nothing: a condition, a nested loop, or an
/// effect whose guard did not fire, all of which read absent at this
/// element.
fn eval_expansion(
    body: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &mut Vec<Value>,
    out: &mut Declaration,
    budget: &Budget<'_>,
    mut rows: Option<&mut Vec<Vec<Option<u32>>>>,
) -> Result<(), EvalError> {
    for (site, clause) in body.iter().enumerate() {
        let before = out.ordered.len();
        eval_clauses(
            std::slice::from_ref(clause),
            inputs,
            hasher,
            bindings,
            out,
            budget,
        )?;
        let Some(rows) = rows.as_deref_mut() else {
            continue;
        };
        let landed = match clause {
            Clause::Effect { .. } if out.ordered.len() == before + 1 => u32::try_from(before).ok(),
            _ => None,
        };
        rows[site].push(landed);
    }
    Ok(())
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
    let budget = Budget::new(inputs.budget);
    forced(eval_expr(expr, inputs, hasher, &[], 0, &budget)?, &budget)
}

fn eval_clauses(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &mut Vec<Value>,
    out: &mut Declaration,
    budget: &Budget<'_>,
) -> Result<(), EvalError> {
    if budget.clause_depth.get() > MAX_CLAUSE_DEPTH {
        return Err(EvalError::ClausesTooDeep);
    }
    for clause in clauses {
        // The line this clause is, in the numbering a rendered listing
        // gives it. Taken before the guard, because the line keeps its
        // number whether or not it declared anything this run.
        let number = budget.preorder.get();
        budget.preorder.set(number.saturating_add(1));
        // A clause depth of zero is a clause an ABI binding can name, so
        // its verdict is one the guest may be handed. Deeper ones are
        // inside a `for-each` body, where no fixed export parameter
        // reaches them.
        let taken = match clause.guard() {
            Some(cond) => as_bool(&*eval_expr(cond, inputs, hasher, bindings, 0, budget)?)?,
            None => true,
        };
        if budget.clause_depth.get() == 0 {
            out.clause_taken.push(taken);
        }
        if !taken {
            // A loop whose guard did not fire mapped over no elements,
            // which is the expansion it has: a site of none rather than
            // no run, so a binding that names it reads what a list of
            // none leaves rather than refusing the call. Its body's
            // lines keep their numbers all the same.
            if let Clause::ForEach { body, .. } = clause {
                budget
                    .preorder
                    .set(budget.preorder.get().saturating_add(preorder_len(body)));
                if budget.clause_depth.get() == 0 {
                    out.expansions
                        .insert(budget.clause.get(), vec![Vec::new(); body.len()]);
                }
            }
            continue;
        }
        match clause {
            Clause::Effect {
                target: declared,
                mode,
                denomination,
                reach,
                ..
            } => {
                let target = eval_target(declared, inputs, hasher, bindings, budget)?;
                let mode = eval_mode(mode, inputs, hasher, bindings, budget)?;
                budget.charge()?;
                // Evaluated beside the key it belongs to and kept parallel
                // to `ordered`, because a capability's rep is its index
                // there — the same alignment the guest's handles ride.
                let held = denomination
                    .as_ref()
                    .map(|expr| eval_denomination(expr, inputs, hasher, bindings, budget))
                    .transpose()?;
                // A reach is keyed first by the resource whose entry
                // admits it — held to that shape at publish — so the
                // resource is the first material term, evaluated here
                // where the declaration is.
                let reached = eval_reach(*reach, declared, inputs, hasher, bindings, budget)?;
                let effect = Effect { target, mode };
                out.set.insert(effect)?;
                out.ordered.push(DeclaredAccess {
                    effect,
                    holds: held,
                    reach: reached,
                    clause: Some(number),
                });
            }
            Clause::Requires { rule, .. } => {
                budget.charge()?;
                if let Some(judged) = eval_condition(rule, inputs, hasher, bindings, budget)? {
                    out.conditions.push(Condition::declared(judged));
                }
            }
            Clause::Proves { claim, .. } => {
                budget.charge()?;
                let value = eval_expr(claim, inputs, hasher, bindings, 0, budget)?;
                let proven = Claim::of(&value).ok_or_else(|| EvalError::TypeMismatch {
                    expected: "claim",
                    found: value.kind(),
                })?;
                // A claim about something that is not a badge is a claim
                // about somebody acting as themselves, and the only such
                // claim a declaration may prove is its own target's,
                // spelled as itself: any other expression evaluating to
                // a callable address would be forgeable — satisfying
                // one's own stored rule is no feat — so the refusal is
                // structural rather than the publish check's alone.
                if proven.badge().is_none() && !matches!(claim, Expr::SelfAddr) {
                    return Err(EvalError::TypeMismatch {
                        expected: "badge",
                        found: "identity",
                    });
                }
                let claim = proven;
                out.proves.push(claim);
                // An instance holder holds the badge, so presenting one
                // satisfies a rule naming the resource as well as a rule
                // naming the instance. The widening happens where it is proven,
                // where possession was verified, which is what keeps the
                // judge an equality walk.
                if claim.instance.is_some() {
                    out.proves.push(Claim::of_subject(claim.subject));
                }
                // The cap is on the claims, and publish counting the
                // clauses cannot see how many a loop yields — so the set
                // every presenting node will copy is held to it here,
                // where the multiplication happens.
                if out.proves.len() > MAX_PROVEN_PER_SIGNATURE {
                    return Err(EvalError::ProvesPastCap);
                }
            }
            Clause::ForEach { list, body, .. } => {
                eval_foreach(list, body, inputs, hasher, bindings, out, budget)?;
            }
        }
    }
    Ok(())
}

/// One `for-each` clause: evaluate the collection, map the body over
/// each element, and file the top-level expansion map.
fn eval_foreach(
    list: &Expr,
    body: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &mut Vec<Value>,
    out: &mut Declaration,
    budget: &Budget<'_>,
) -> Result<(), EvalError> {
    // The one place a borrow cannot reach: the loop pushes each
    // element onto `bindings`, which a list read out of an
    // enclosing binding would itself be borrowed from. Owned
    // once per loop, and charged for the copy.
    let items = as_list(forced(
        eval_expr(list, inputs, hasher, bindings, 0, budget)?,
        budget,
    )?)?;
    if items.len() > MAX_FOREACH_ELEMENTS {
        return Err(EvalError::ForEachTooLong { len: items.len() });
    }
    // Only a top-level loop is one an ABI binding can name, so
    // only that one records where its expansions landed.
    let mut rows =
        (budget.clause_depth.get() == 0).then(|| vec![Vec::with_capacity(items.len()); body.len()]);
    let clause = budget.clause.get();
    // The body's lines number once, however many elements the
    // loop maps over: each pass restarts at the first body
    // line, and the walk resumes past the whole body.
    let body_lines = budget.preorder.get();
    budget.clause_depth.set(budget.clause_depth.get() + 1);
    for item in items {
        // The iteration is work whether or not the body declares
        // anything, so a nest of empty loops is bounded here
        // rather than running the product of its levels' widths.
        budget.charge()?;
        budget.preorder.set(body_lines);
        bindings.push(item);
        let result = eval_expansion(body, inputs, hasher, bindings, out, budget, rows.as_mut());
        bindings.pop();
        result?;
    }
    budget.clause_depth.set(budget.clause_depth.get() - 1);
    budget
        .preorder
        .set(body_lines.saturating_add(preorder_len(body)));
    if let Some(rows) = rows {
        out.expansions.insert(clause, rows);
    }
    Ok(())
}

/// How many lines `clauses` occupies in the preorder numbering a
/// rendered listing gives a method's effects: one per clause, plus each
/// `for-each` body's own, counted once.
pub(crate) fn preorder_len(clauses: &[Clause]) -> u32 {
    clauses
        .iter()
        .map(|clause| match clause {
            Clause::ForEach { body, .. } => 1u32.saturating_add(preorder_len(body)),
            _ => 1,
        })
        .fold(0, u32::saturating_add)
}

/// The resource a value cell's clause declares the cell holds.
fn eval_denomination(
    expr: &Expr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<ResourceAddr, EvalError> {
    let value = eval_expr(expr, inputs, hasher, bindings, 0, budget)?;
    let Value::Address(address) = *value else {
        return Err(EvalError::TypeMismatch {
            expected: "resource",
            found: value.kind(),
        });
    };
    Ok(ResourceAddr::try_from(address)?)
}

/// The authority a reaching access acts under, over the resource its
/// own key was derived from.
///
/// The resource is the first material term — held to that shape at
/// publish — so what the entry is asked about is always what the access
/// actually reaches.
fn eval_reach(
    reach: Option<GrantedBehaviour>,
    declared: &TargetExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<Option<Reach>, EvalError> {
    let Some(behaviour) = reach else {
        return Ok(None);
    };
    let keyed = keying_resource(declared).ok_or(EvalError::UnkeyedReach)?;
    let resource = eval_denomination(keyed, inputs, hasher, bindings, budget)?;
    Ok(Some(Reach {
        behaviour,
        resource,
    }))
}

/// The slot a target names, and the material keying it there.
///
/// Both point shapes and both collection shapes carry one: a child key
/// spells the slot beside its material, and a collection carries it as
/// the identity its entries hang under. A fresh key is the exception and
/// answers `None` — it is a local id minted under the owner rather than
/// a child of any slot, so there is nothing for the vocabulary to be
/// about.
#[must_use]
pub fn slot_of(target: &TargetExpr) -> Option<(&SlotRef, &[Expr])> {
    match target {
        TargetExpr::Point(Expr::ChildKey { slot, material, .. }) => Some((slot, material)),
        TargetExpr::Point(_) => None,
        TargetExpr::Entry {
            collection,
            material,
            ..
        }
        | TargetExpr::Range {
            collection,
            material,
            ..
        } => Some((collection, material)),
    }
}

/// The expression a target's key is derived from first.
///
/// What a reach is admitted by: a reaching target is keyed first by the
/// resource whose entry admits it, held to that shape at publish. A
/// fresh key is minted under its owner rather than derived from
/// anything, so it is keyed by nothing and can never be reached.
#[must_use]
pub fn keying_resource(target: &TargetExpr) -> Option<&Expr> {
    let material = match target {
        TargetExpr::Point(Expr::ChildKey { material, .. })
        | TargetExpr::Entry { material, .. }
        | TargetExpr::Range { material, .. } => material,
        TargetExpr::Point(_) => return None,
    };
    material.first()
}

fn eval_condition(
    rule: &RuleExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<Option<Rule<JudgedLeaf>>, EvalError> {
    // Leaf for leaf, so the tree the signature declared is the tree the
    // kernel judges: the shape is fixed at publish and only the leaves
    // evaluate, which is what lets the authored caps stand for both.
    rule.map_leaves(&mut |leaf| match leaf {
        RuleLeaf::Presence { target, expect } => Ok(JudgedLeaf::Presence {
            target: eval_target(target, inputs, hasher, bindings, budget)?,
            expect: *expect,
        }),
        RuleLeaf::Claim(expr) => {
            let value = eval_expr(expr, inputs, hasher, bindings, 0, budget)?;
            Claim::of(&value)
                .map(JudgedLeaf::Claim)
                .ok_or_else(|| EvalError::TypeMismatch {
                    expected: "claim",
                    found: value.kind(),
                })
        }
        RuleLeaf::Stored { cell } => Ok(JudgedLeaf::Stored {
            cell: as_key(&*eval_expr(cell, inputs, hasher, bindings, 0, budget)?)?,
        }),
    })
    .map(Some)
}

fn eval_target(
    target: &TargetExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<EffectTarget, EvalError> {
    match target {
        TargetExpr::Point(expr) => {
            let key = as_key(&*eval_expr(expr, inputs, hasher, bindings, 0, budget)?)?;
            Ok(EffectTarget::Point(key))
        }
        TargetExpr::Entry {
            owner,
            collection,
            material,
            order,
        } => {
            let owner = as_address(&*eval_expr(owner, inputs, hasher, bindings, 0, budget)?)?;
            let collection = eval_collection(
                owner, collection, material, inputs, hasher, bindings, budget,
            )?;
            let order = as_u128(&*eval_expr(order, inputs, hasher, bindings, 0, budget)?)?;
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
            let owner = as_address(&*eval_expr(owner, inputs, hasher, bindings, 0, budget)?)?;
            let collection = eval_collection(
                owner, collection, material, inputs, hasher, bindings, budget,
            )?;
            let lo = as_u128(&*eval_expr(lo, inputs, hasher, bindings, 0, budget)?)?;
            let hi = as_u128(&*eval_expr(hi, inputs, hasher, bindings, 0, budget)?)?;
            if lo > hi {
                return Err(EvalError::InvalidRange);
            }
            let cap = as_cap(&*eval_expr(cap, inputs, hasher, bindings, 0, budget)?)?;
            Ok(EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            })
        }
    }
}

/// Fold a target's slot and evaluated material into the collection
/// identity everything downstream compares.
fn eval_collection(
    owner: Address,
    slot: &SlotRef,
    material: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<CollectionId, EvalError> {
    let slot = eval_slot(slot, false, inputs, hasher, bindings, 0, budget)?;
    let encoded = eval_material(material, inputs, hasher, bindings, 0, budget)?;
    budget.spend(WORK_PER_DERIVATION)?;
    Ok(collection_id(hasher, owner, slot, &encoded))
}

/// The slot a key is derived under, and — where an argument named it —
/// the band that argument may reach.
///
/// This is the one place the per-slot shape table's judgment is
/// restated. The table has its footing in the slot being a constant, so
/// a slot that is not one is held here instead, and to the narrowest
/// form of the same sentence: an argument may name a cell **value is
/// kept at** and nothing else. Which is what a reach can be about — the
/// authority admitting it is a resource's, and the only cells a
/// resource's entries govern are the ones holding it.
///
/// So the vocabulary's two value cells, told apart by the shape asking
/// (a balance is a leaf, instances are a collection), or one of the
/// reached package's own slots. Everything below the package band that
/// is not one of the two names a cell the kernel derives for its own
/// purposes — a record, a configuration, a governing rule, a halt flag —
/// and none of them holds value, so none of them is somebody's to reach.
fn eval_slot(
    slot: &SlotRef,
    point: bool,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    depth: usize,
    budget: &Budget<'_>,
) -> Result<SlotId, EvalError> {
    let expr = match slot {
        SlotRef::Fixed(slot) => return Ok(*slot),
        SlotRef::Reached(expr) => expr,
    };
    let named = as_u64(&*eval_expr(expr, inputs, hasher, bindings, depth, budget)?)?;
    let slot = u16::try_from(named)
        .map(SlotId)
        .map_err(|_| EvalError::UnreachableSlot(named))?;
    let holds_value = if slot.0 >= PACKAGE_SLOT_BASE {
        slot.0 < KERNEL_SLOT_BASE
    } else if point {
        slot == VAULT
    } else {
        slot == NF_VAULT
    };
    if holds_value {
        Ok(slot)
    } else {
        Err(EvalError::UnreachableSlot(named))
    }
}

/// The address of a resource the target instance issues: the derivation
/// over its material, folding the rules its declaration grants.
///
/// The granted set resolves here rather than at publish because its
/// leaves name the issuing instance — a badge that instance also issues,
/// a field of the configuration its address commits — none of which
/// exist until a target is resolved.
fn self_resource(
    hasher: &dyn Hasher,
    inputs: &EvalInputs<'_>,
    kind: ResourceKind,
    material: &[Vec<u8>],
    grants: &GrantsExpr,
) -> Result<Value, EvalError> {
    let rules = grants.resolve(hasher, inputs.self_addr, &inputs.record.config)?;
    Ok(Value::Address(
        granting_resource_address(hasher, inputs.self_addr, kind, &rules, material).into(),
    ))
}

fn eval_mode(
    mode: &ModeExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    budget: &Budget<'_>,
) -> Result<Mode, EvalError> {
    match mode {
        ModeExpr::Read => Ok(Mode::Read),
        ModeExpr::Delta { moves } => Ok(Mode::Delta { moves: *moves }),
        ModeExpr::Reserve(expr) => {
            let amount = as_u128(&*eval_expr(expr, inputs, hasher, bindings, 0, budget)?)?;
            Ok(Mode::Reserve { amount })
        }
        ModeExpr::Write { moves } => Ok(Mode::Write { moves: *moves }),
    }
}

/// A non-fungible edge's ids as a list, or the refusal a fungible one
/// earns: kind is structural, never an empty answer.
fn edge_ids(content: &EdgeContent) -> Result<Value, EvalError> {
    match content {
        EdgeContent::NonFungible { ids } => {
            Ok(Value::List(ids.iter().copied().map(Value::U64).collect()))
        }
        EdgeContent::Fungible => Err(EvalError::TypeMismatch {
            expected: "non-fungible bucket",
            found: "bucket",
        }),
    }
}

/// How many elements a list holds, saturating at the width a count is
/// read in.
fn count(elements: &[Value]) -> Value {
    Value::U64(u64::try_from(elements.len()).unwrap_or(u64::MAX))
}

/// The one element a list holds, or the refusal naming how many it held
/// instead.
const fn sole(elements: &[Value]) -> Result<&Value, EvalError> {
    match elements {
        [only] => Ok(only),
        _ => Err(EvalError::NotSingleton {
            len: elements.len(),
        }),
    }
}

/// A bucket projection's parts, or the type mismatch every edge
/// projection refuses alike.
const fn bucket_parts(value: &Value) -> Result<(ResourceAddr, &EdgeContent), EvalError> {
    match value {
        Value::Bucket { resource, content } => Ok((*resource, content)),
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
    budget: &Budget<'_>,
) -> Result<Vec<Vec<u8>>, EvalError> {
    let mut encoded = Vec::with_capacity(material.len());
    for expr in material {
        let value = eval_expr(expr, inputs, hasher, bindings, depth, budget)?;
        // Encoding walks the value, and a walk is charged where it
        // happens: the term paid for building the value, not for this.
        budget.spend(walked(&value))?;
        encoded.push(value.canonical_bytes());
    }
    Ok(encoded)
}

/// The call's argument at `index`.
fn arg<'a>(inputs: &'a EvalInputs<'_>, index: u32) -> Result<&'a Value, EvalError> {
    indexed(inputs.args, index).ok_or(EvalError::ArgOutOfRange(index))
}

/// The target's configuration field at `index`.
fn config<'a>(inputs: &'a EvalInputs<'_>, index: u32) -> Result<&'a Value, EvalError> {
    indexed(&inputs.record.config, index).ok_or(EvalError::ConfigOutOfRange(index))
}

/// The `for-each` element `index` levels out from the innermost loop.
fn binding(bindings: &[Value], index: u32) -> Result<&Value, EvalError> {
    usize::try_from(index)
        .ok()
        .and_then(|back| bindings.len().checked_sub(back + 1))
        .and_then(|position| bindings.get(position))
        .ok_or(EvalError::BindingOutOfRange(index))
}

/// What a walk over a value visits, in the units [`Budget::spend`]
/// charges: its own leaves, every element beneath them, and every
/// [`BYTES_PER_WORK_UNIT`] of an opaque byte string.
///
/// A scalar is one; a list is one per element and one for itself; a byte
/// string is what its length costs. So a walk that copies, compares or
/// encodes a value pays what the walk costs rather than what its
/// outermost shape suggests.
fn walked(value: &Value) -> usize {
    let mut total = 0;
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        total += 1;
        match value {
            Value::Bytes(bytes) => total += bytes.len() / BYTES_PER_WORK_UNIT,
            Value::Tuple(values) | Value::List(values) => stack.extend(values),
            _ => {}
        }
    }
    total
}

/// An evaluated value the caller keeps, charged for the copy that keeping
/// it costs.
///
/// A borrowed value is copied here, which is the one place the copy
/// happens and so the one place it is priced. An owned one was built by
/// the term that answered it and paid there.
fn forced(value: Cow<'_, Value>, budget: &Budget<'_>) -> Result<Value, EvalError> {
    match value {
        Cow::Borrowed(value) => {
            budget.spend(walked(value))?;
            Ok(value.clone())
        }
        Cow::Owned(value) => Ok(value),
    }
}

/// How many hashes a term runs, which is the part of its cost that no
/// walk over its subterms accounts for.
///
/// Every variant named rather than a default, so a term added to the
/// vocabulary has to answer for what it hashes: a wildcard would price
/// the next hashing term at nothing, and nothing about the answer it
/// gives would look wrong.
const fn derivations(expr: &Expr) -> usize {
    match expr {
        // The granted tree resolves to an address, and the resource
        // address derives over that.
        Expr::SelfResource { .. } => 2,
        Expr::ChildKey { .. }
        | Expr::OrderKey { .. }
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. } => 1,
        Expr::Literal(..)
        | Expr::Arg(..)
        | Expr::Config(..)
        | Expr::Binding(..)
        | Expr::SelfAddr
        | Expr::SelfRecord
        | Expr::Field(..)
        | Expr::ResourceOf(..)
        | Expr::IdsOf(..)
        | Expr::Len(..)
        | Expr::Only(..)
        | Expr::List(..)
        | Expr::Tuple(..)
        | Expr::NfBucket { .. }
        | Expr::Lookup { .. }
        | Expr::Pack { .. }
        | Expr::Add(..)
        | Expr::Not(..)
        | Expr::And(..)
        | Expr::Or(..)
        | Expr::Eq(..)
        | Expr::Lt(..)
        | Expr::Contains { .. }
        | Expr::If { .. } => 0,
    }
}

#[allow(clippy::too_many_lines)] // one dispatch over the term vocabulary
fn eval_expr<'a>(
    expr: &'a Expr,
    inputs: &'a EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &'a [Value],
    depth: usize,
    budget: &Budget<'_>,
) -> Result<Cow<'a, Value>, EvalError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(EvalError::ExpressionTooDeep);
    }
    // One per subterm, before anything is read: an expression tree is
    // walked whatever its arms turn out to hold. A term that hashes pays
    // for the hash here too, so that it is charged whether or not the
    // arm below reaches one.
    budget.spend(1 + derivations(expr) * WORK_PER_DERIVATION)?;
    let deeper = depth + 1;
    let sub = |expr: &'a Expr| eval_expr(expr, inputs, hasher, bindings, deeper, budget);
    let material = |material| eval_material(material, inputs, hasher, bindings, deeper, budget);
    let all = |elements| eval_all(elements, inputs, hasher, bindings, deeper, budget);
    let built = match expr {
        // The four terms handed a value rather than deriving one, and the
        // conditional that forwards whichever branch it took. Each answers
        // a borrow, so reading a value copies nothing — the copy is
        // charged wherever a caller forces one.
        Expr::Literal(value) => return Ok(Cow::Borrowed(value)),
        Expr::Arg(index) => return Ok(Cow::Borrowed(arg(inputs, *index)?)),
        Expr::Config(index) => return Ok(Cow::Borrowed(config(inputs, *index)?)),
        Expr::Binding(index) => return Ok(Cow::Borrowed(binding(bindings, *index)?)),
        Expr::If {
            cond,
            then,
            otherwise,
        } => {
            return sub(if as_bool(&*sub(cond)?)? {
                then
            } else {
                otherwise
            });
        }
        Expr::SelfAddr => Value::Address(inputs.self_addr),
        Expr::SelfRecord => inputs
            .record
            .leaf_bytes()
            .map(Value::Bytes)
            .map_err(|_| EvalError::RecordMalformed)?,
        // The projections read their operand in place and copy out the
        // one part they answer, never the container around it — the same
        // shape [`Expr::Lookup`] takes over a table.
        Expr::Field(tuple, index) => {
            let tuple = sub(tuple)?;
            let field = field(fields(&tuple)?, *index)?;
            budget.spend(walked(field))?;
            field.clone()
        }
        Expr::ResourceOf(bucket) => Value::Address(bucket_parts(&*sub(bucket)?)?.0.into()),
        Expr::IdsOf(bucket) => edge_ids(bucket_parts(&*sub(bucket)?)?.1)?,
        Expr::Len(list) => count(elements(&*sub(list)?)?),
        Expr::Only(list) => {
            let list = sub(list)?;
            let only = sole(elements(&list)?)?;
            budget.spend(walked(only))?;
            only.clone()
        }
        Expr::Lookup { map, key } => {
            let map = sub(map)?;
            let hit = find(elements(&map)?, &*sub(key)?, budget)?.ok_or(EvalError::LookupMiss)?;
            // The one entry the scan hands out, copied out of the table
            // rather than along with it.
            budget.spend(walked(hit))?;
            hit.clone()
        }
        Expr::SelfResource {
            kind,
            material: parts,
            grants,
        } => self_resource(hasher, inputs, *kind, &material(parts)?, grants)?,
        Expr::ChildKey {
            owner,
            slot,
            material: parts,
        } => Value::Key(child_key(
            hasher,
            as_address(&*sub(owner)?)?,
            eval_slot(slot, true, inputs, hasher, bindings, deeper, budget)?,
            &material(parts)?,
        )),
        Expr::OrderKey {
            owner,
            slot,
            material: parts,
        } => Value::U128(order_key(
            hasher,
            as_address(&*sub(owner)?)?,
            *slot,
            &material(parts)?,
        )),
        Expr::FreshId { slot } => Value::U64(inputs.fresh_id(hasher, *slot)),
        Expr::FreshKey { slot } => Value::Key(inputs.fresh_key(hasher, *slot)),
        Expr::Pack { hi, lo } => {
            let hi = as_u64(&*sub(hi)?)?;
            let lo = as_u64(&*sub(lo)?)?;
            Value::U128((u128::from(hi) << 64) | u128::from(lo))
        }
        Expr::List(elements) => Value::List(all(elements)?),
        Expr::Tuple(fields) => Value::Tuple(all(fields)?),
        Expr::NfBucket { resource, ids } => Value::Bucket {
            resource: ResourceAddr::try_from(as_address(&*sub(resource)?)?)?,
            content: EdgeContent::NonFungible {
                ids: id_set(elements(&*sub(ids)?)?)?,
            },
        },
        Expr::Not(inner) => Value::Bool(!as_bool(&*sub(inner)?)?),
        // Short-circuiting: a false `And` and a true `Or` are answered by
        // the left operand alone, and the right one is never evaluated.
        // That is what lets one arm of a judgment be an expression the
        // other case would refuse.
        Expr::And(left, right) | Expr::Or(left, right) => {
            let short = matches!(expr, Expr::Or(..));
            if as_bool(&*sub(left)?)? == short {
                Value::Bool(short)
            } else {
                Value::Bool(as_bool(&*sub(right)?)?)
            }
        }
        Expr::Add(left, right) => add(&*sub(left)?, &*sub(right)?)?,
        // The one operator that walks its operands rather than reading a
        // scalar off them: equality is structural, and refusing a bucket
        // is a second walk over both. Charged here, because a borrowed
        // operand was handed over for one unit and this is what reading
        // it costs.
        Expr::Eq(left, right) => {
            let (left, right) = (sub(left)?, sub(right)?);
            budget.spend(walked(&left) + walked(&right))?;
            equals(&left, &right)?
        }
        Expr::Lt(left, right) => less_than(&*sub(left)?, &*sub(right)?)?,
        Expr::Contains { map, key } => {
            let map = sub(map)?;
            Value::Bool(find(elements(&map)?, &*sub(key)?, budget)?.is_some())
        }
    };
    // A term that built a value pays for what it built: what the term
    // above will walk is what this one produced. A term that borrowed one
    // built nothing, and pays wherever the borrow is forced.
    budget.spend(walked(&built))?;
    Ok(Cow::Owned(built))
}

/// Every element of a sequence expression, in order.
fn eval_all(
    elements: &[Expr],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
    depth: usize,
    budget: &Budget<'_>,
) -> Result<Vec<Value>, EvalError> {
    elements
        .iter()
        .map(|element| {
            // An element escapes into the list the caller builds, so the
            // copy that puts it there is charged here.
            forced(
                eval_expr(element, inputs, hasher, bindings, depth, budget)?,
                budget,
            )
        })
        .collect()
}

/// One field of a tuple, by position.
fn field(fields: &[Value], index: u32) -> Result<&Value, EvalError> {
    indexed(fields, index).ok_or(EvalError::FieldOutOfRange {
        index,
        arity: fields.len(),
    })
}

/// The first matching pair's value, or `None` where the table holds no
/// such key. The one walk under both [`Expr::Lookup`], which refuses a
/// miss, and [`Expr::Contains`], which reports it.
fn find<'a>(
    pairs: &'a [Value],
    key: &Value,
    budget: &Budget<'_>,
) -> Result<Option<&'a Value>, EvalError> {
    for pair in pairs {
        // Per pair examined. A scan is the one operation whose cost is
        // the table's rather than the expression's, and charging it here
        // is what makes the ceiling a bound on work instead of on the
        // number of scans a signature spells.
        budget.spend(1)?;
        let Value::Tuple(fields) = pair else {
            return Err(EvalError::LookupNotPairs);
        };
        let [pair_key, pair_value] = fields.as_slice() else {
            return Err(EvalError::LookupNotPairs);
        };
        if pair_key == key {
            return Ok(Some(pair_value));
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

/// A sum over the two integer widths, and nothing else, refusing
/// overflow.
fn add(left: &Value, right: &Value) -> Result<Value, EvalError> {
    match (left, right) {
        (Value::U64(left), Value::U64(right)) => left
            .checked_add(*right)
            .map(Value::U64)
            .ok_or(EvalError::AddOverflow),
        (Value::U128(left), Value::U128(right)) => left
            .checked_add(*right)
            .map(Value::U128)
            .ok_or(EvalError::AddOverflow),
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
fn id_set(values: &[Value]) -> Result<Vec<u64>, EvalError> {
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

const fn as_u64(value: &Value) -> Result<u64, EvalError> {
    match value {
        Value::U64(v) => Ok(*v),
        other => Err(EvalError::TypeMismatch {
            expected: "u64",
            found: other.kind(),
        }),
    }
}

/// A range cap, in the width the interval vocabulary counts entries in.
///
/// What bounds an evaluated cap is the fee its depth charge earns and
/// the gas limit that pays it — but the count itself is a `u32` end to
/// end, so a wider one is a refusal here rather than a truncation
/// downstream.
fn as_cap(value: &Value) -> Result<u32, EvalError> {
    let cap = as_u128(value)?;
    u32::try_from(cap).map_err(|_| EvalError::CapTooWide(cap))
}

fn as_u128(value: &Value) -> Result<u128, EvalError> {
    match value {
        Value::U64(v) => Ok(u128::from(*v)),
        Value::U128(v) => Ok(*v),
        other => Err(EvalError::TypeMismatch {
            expected: "u128",
            found: other.kind(),
        }),
    }
}

const fn as_address(value: &Value) -> Result<Address, EvalError> {
    match value {
        Value::Address(addr) => Ok(*addr),
        other => Err(EvalError::TypeMismatch {
            expected: "address",
            found: other.kind(),
        }),
    }
}

const fn as_key(value: &Value) -> Result<SubstateKey, EvalError> {
    match value {
        Value::Key(key) => Ok(*key),
        other => Err(EvalError::TypeMismatch {
            expected: "key",
            found: other.kind(),
        }),
    }
}

const fn as_bool(value: &Value) -> Result<bool, EvalError> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        other => Err(EvalError::TypeMismatch {
            expected: "bool",
            found: other.kind(),
        }),
    }
}

/// A tuple's fields read in place.
fn fields(value: &Value) -> Result<&[Value], EvalError> {
    match value {
        Value::Tuple(fields) => Ok(fields),
        other => Err(EvalError::TypeMismatch {
            expected: "tuple",
            found: other.kind(),
        }),
    }
}

/// A list's elements read in place, for a source the caller still holds.
/// The borrowing counterpart of [`as_list`], which is for one it does not.
fn elements(value: &Value) -> Result<&[Value], EvalError> {
    match value {
        Value::List(items) => Ok(items),
        other => Err(EvalError::TypeMismatch {
            expected: "list",
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
        Address, AddressClass, Effect, EffectTarget, MAX_MANIFEST_NODES, Mode, Moves, Presence,
        ResourceAddr, WrongClass,
    };

    use super::{
        Clause, EvalBudget, EvalError, EvalInputs, Expr, KERNEL_SLOT_BASE, MAX_CLAUSE_DEPTH,
        MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, MAX_PROVEN_PER_SIGNATURE, MAX_VALUE_ITEMS, ModeExpr,
        NF_VAULT, PACKAGE_SLOT_BASE, SlotRef, TargetExpr, VAULT, evaluate_declaration,
        evaluate_effects, evaluate_expr, fresh_id, fresh_local,
    };
    use crate::hash::{Hash32, TestHasher};
    use crate::instance::InstanceMeta;
    use crate::manifest::ManifestHash;
    use crate::metadata::PackageHash;
    use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind, issued_resource};
    use crate::types::{
        EdgeContent, MAX_IDS_PER_EDGE, MAX_VALUE_BYTES, SlotId, Value, child_key, collection_id,
        order_key,
    };
    use crate::vocabulary::{AUTH, CONFIG, HALT, INSTANCE, RESOURCE};

    /// Every constructor, each subterm a distinct marker: the walk
    /// answers exactly the markers, in order. A new variant fails the
    /// `children` match before it reaches here; what this pins is that no
    /// arm quietly drops one of its variant's fields — the miss every
    /// structural walk would then share.
    #[test]
    #[allow(clippy::too_many_lines)] // one row per constructor
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
            (Expr::Len(boxed(1)), vec![1]),
            (Expr::Not(boxed(1)), vec![1]),
            (Expr::List(vec![leaf(1), leaf(2)]), vec![1, 2]),
            (Expr::Tuple(vec![leaf(1), leaf(2)]), vec![1, 2]),
            (
                Expr::SelfResource {
                    kind: ResourceKind::Fungible,
                    material: vec![leaf(1), leaf(2)],
                    grants: GrantsExpr::new(),
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
                    slot: SlotRef::Fixed(SlotId(0)),
                    material: vec![leaf(2), leaf(3)],
                },
                vec![1, 2, 3],
            ),
            (
                Expr::ChildKey {
                    owner: boxed(1),
                    slot: SlotRef::Reached(boxed(2)),
                    material: vec![leaf(3)],
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
            (Expr::Add(boxed(1), boxed(2)), vec![1, 2]),
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

    // Leaked so the borrow outlives the call: a record is owned, and
    // every case here wants one built from its own configuration rather
    // than threaded in from the caller. Bounded by the number of tests.
    // The envelope meter goes the same way, one per call, so each case
    // measures a signature rather than what the case before it spent.
    fn inputs<'a>(args: &'a [Value], config: &'a [Value]) -> EvalInputs<'a> {
        let record: &'a InstanceMeta = Box::leak(Box::new(InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: config.to_vec(),
            salt: Hash32([2; 32]),
        }));
        EvalInputs {
            self_addr: Address::new([7; 31], AddressClass::Component),
            args,
            record,
            node_index: 3,
            identity: ManifestHash(Hash32([9; 32])),
            grants: super::PresentedGrants::none(),
            budget: Box::leak(Box::new(EvalBudget::default())),
        }
    }

    /// The target's own record evaluates to the bytes its configuration
    /// leaf stores — drawn from what admission resolved the target with,
    /// never from anything a caller supplies.
    #[test]
    fn the_self_record_evaluates_to_the_leaf_bytes() {
        let context = inputs(&[], &[Value::U64(7)]);
        assert_eq!(
            evaluate_expr(&Expr::SelfRecord, &context, &TestHasher),
            Ok(Value::Bytes(context.record.leaf_bytes().unwrap()))
        );
    }

    /// A slot an argument names resolves to a cell value is kept at,
    /// and to nothing else.
    ///
    /// The one place the per-slot shape table's judgment is restated,
    /// so it is held to the same band from the other side: the
    /// vocabulary's two value cells told apart by the shape asking, a
    /// package's own slots, and a refusal everywhere else — the
    /// vocabulary's other cells among them, since a record, a
    /// configuration leaf, a governing rule and a halt flag hold no
    /// value and so are nobody's to reach.
    #[test]
    fn a_slot_an_argument_names_reaches_value_and_nothing_else() {
        let keyed = || {
            vec![Expr::Literal(Value::Address(Address::new(
                [7; 31],
                AddressClass::Resource,
            )))]
        };
        let reaching = |slot: u64, point: bool| {
            let target = if point {
                TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Reached(Box::new(Expr::Arg(0))),
                    material: keyed(),
                })
            } else {
                TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: SlotRef::Reached(Box::new(Expr::Arg(0))),
                    material: keyed(),
                    lo: Expr::Literal(Value::U128(0)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Literal(Value::U64(1)),
                }
            };
            let clauses = vec![Clause::Effect {
                reach: Some(GrantedBehaviour::Recall),
                guard: None,
                target,
                mode: ModeExpr::Read,
                denomination: None,
            }];
            let args = [Value::U64(slot)];
            let context = inputs(&args, &[]);
            evaluate_declaration(&clauses, &context, &TestHasher).map(|_| ())
        };

        assert_eq!(reaching(u64::from(VAULT.0), true), Ok(()));
        assert_eq!(reaching(u64::from(NF_VAULT.0), false), Ok(()));
        assert_eq!(reaching(u64::from(PACKAGE_SLOT_BASE), true), Ok(()));
        assert_eq!(reaching(u64::from(PACKAGE_SLOT_BASE), false), Ok(()));
        assert_eq!(
            reaching(u64::from(KERNEL_SLOT_BASE - 1), true),
            Ok(()),
            "the band a package numbers in runs to the kernel's"
        );

        // A balance is a leaf and instances are a collection, so each
        // vocabulary cell is reachable only in the shape it has.
        for (slot, point) in [(VAULT, false), (NF_VAULT, true)] {
            assert_eq!(
                reaching(u64::from(slot.0), point),
                Err(EvalError::UnreachableSlot(u64::from(slot.0)))
            );
        }
        // Every other cell the vocabulary names holds a fact rather than
        // value, and the kernel's own band above holds neither.
        for slot in [CONFIG, AUTH, RESOURCE, INSTANCE, HALT] {
            for point in [true, false] {
                assert_eq!(
                    reaching(u64::from(slot.0), point),
                    Err(EvalError::UnreachableSlot(u64::from(slot.0))),
                    "{slot:?}"
                );
            }
        }
        for slot in [u64::from(KERNEL_SLOT_BASE), u64::from(u16::MAX), 1 << 20] {
            assert_eq!(reaching(slot, true), Err(EvalError::UnreachableSlot(slot)));
        }
    }

    /// A `Requires` clause evaluates into the declaration's condition
    /// list and contributes no access: its span is empty, its guard is
    /// honoured, and its leaves resolve to the claims and cells the
    /// kernel judges.
    #[test]
    fn a_requires_clause_evaluates_to_a_condition_and_no_access() {
        use crate::claim::Claim;
        use crate::manifest::JudgedLeaf;
        use crate::rule::{Rule, RuleExpr, RuleLeaf};

        let context = inputs(&[Value::Bool(false)], &[]);
        let key = child_key(&TestHasher, context.self_addr, SlotId(4), &[]);
        let target = || TargetExpr::Point(Expr::Literal(Value::Key(key)));
        let clauses = vec![
            Clause::Effect {
                reach: None,
                guard: None,
                target: target(),
                mode: ModeExpr::Read,
                denomination: None,
            },
            Clause::Requires {
                guard: None,
                rule: RuleExpr::Require(RuleLeaf::Presence {
                    target: Box::new(target()),
                    expect: Presence::Present,
                }),
            },
            Clause::Requires {
                guard: None,
                rule: RuleExpr::CountOf {
                    count: 1,
                    rules: vec![
                        RuleExpr::claim(Expr::SelfAddr),
                        RuleExpr::Require(RuleLeaf::Stored {
                            cell: Expr::Literal(Value::Key(key)),
                        }),
                    ],
                },
            },
            // Guarded out: evaluated conditions carry only what fired.
            Clause::Requires {
                guard: Some(Box::new(Expr::Arg(0))),
                rule: RuleExpr::Require(RuleLeaf::Presence {
                    target: Box::new(target()),
                    expect: Presence::Absent,
                }),
            },
        ];
        let declaration = evaluate_declaration(&clauses, &context, &TestHasher).unwrap();

        // One access; the conditions contribute nothing to either view.
        assert_eq!(declaration.set.len(), 1);
        assert_eq!(declaration.ordered.len(), 1);
        assert_eq!(
            declaration.clause_spans,
            vec![(0, 1), (1, 0), (1, 0), (1, 0)]
        );
        assert_eq!(declaration.clause_taken, vec![true, true, true, false]);

        let identity = Claim::of_subject(context.self_addr);
        assert_eq!(
            declaration.required().cloned().collect::<Vec<_>>(),
            vec![
                Rule::Require(JudgedLeaf::Presence {
                    target: EffectTarget::Point(key),
                    expect: Presence::Present,
                }),
                Rule::CountOf {
                    count: 1,
                    rules: vec![
                        Rule::Require(JudgedLeaf::Claim(identity)),
                        Rule::Require(JudgedLeaf::Stored { cell: key }),
                    ],
                },
            ]
        );

        // A claim leaf must evaluate to a claim; a number is refused
        // with the evaluator's own mismatch.
        let refused = evaluate_declaration(
            &[Clause::Requires {
                guard: None,
                rule: RuleExpr::claim(Expr::Literal(Value::U64(7))),
            }],
            &context,
            &TestHasher,
        );
        assert_eq!(
            refused,
            Err(EvalError::TypeMismatch {
                expected: "claim",
                found: "u64",
            })
        );
    }

    /// The routed grant is lowered through `issued_resource`, and a
    /// body's `issued(Resource)` evaluates `SelfResource` over that
    /// declaration's mark as a byte literal — one address either way,
    /// because the mark's encoding into derivation material is spelled
    /// once, as the one part it always is.
    #[test]
    fn a_self_resource_over_a_mark_literal_is_the_issued_resource() {
        let context = inputs(&[], &[]);
        for kind in [ResourceKind::Fungible, ResourceKind::NonFungible] {
            for mark in [&b"unit"[..], b"owner-badge"] {
                let material = vec![Expr::Literal(Value::Bytes(mark.to_vec()))];
                assert_eq!(
                    evaluate_expr(
                        &Expr::SelfResource {
                            kind,
                            material,
                            grants: GrantsExpr::new(),
                        },
                        &context,
                        &TestHasher
                    ),
                    Ok(Value::Address(
                        issued_resource(&TestHasher, context.self_addr, kind, mark).into()
                    )),
                );
            }
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
                reach: None,
                guard: None,
                target: point(0xF0),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            },
            Clause::Effect {
                reach: None,
                guard: None,
                target: point(0x0F),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            },
            // The same target as the first clause: a degenerate instance
            // configuration produces exactly this shape.
            Clause::Effect {
                reach: None,
                guard: None,
                target: point(0xF0),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            },
        ];
        let ins = inputs(&[], &[]);
        let declaration = evaluate_declaration(&clauses, &ins, &TestHasher).unwrap();

        assert_eq!(declaration.ordered.len(), 3, "one entry per clause taken");
        assert_eq!(declaration.set.len(), 2, "the set folds the repeat");
        assert_eq!(
            declaration.ordered[0].effect, declaration.ordered[2].effect,
            "the repeated clause is the same effect twice"
        );
        assert_eq!(
            (declaration.ordered[0].clause, declaration.ordered[2].clause),
            (Some(0), Some(2)),
            "each entry keeps the line that declared it"
        );
        // The clause order is the author's, so it survives regardless of
        // how the two keys happen to compare.
        assert_ne!(declaration.ordered[0].effect, declaration.ordered[1].effect);
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
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Field(Box::new(Expr::Binding(0)), 0)),
                    slot: SlotRef::Fixed(SlotId(1)),
                    material: vec![Expr::Field(Box::new(Expr::Binding(0)), 1)],
                }),
                mode: ModeExpr::Delta { moves: Moves::Both },
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
                mode: Mode::Delta { moves: Moves::Both },
            }));
        }
    }

    #[test]
    fn a_foreach_records_where_each_expansion_landed() {
        // Three elements over a body of two sites, the second guarded on
        // the element itself: what site 1 covers is three
        // entries, two of them absent, aligned with site 0's three.
        let args = [Value::List(vec![
            Value::U64(0),
            Value::U64(1),
            Value::U64(0),
        ])];
        let ins = inputs(&args, &[]);
        let vault = |material: Vec<Expr>| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(1)),
                material,
            })
        };
        let clauses = [Clause::ForEach {
            guard: None,
            list: Expr::Arg(0),
            body: vec![
                Clause::Effect {
                    reach: None,
                    guard: None,
                    target: vault(vec![Expr::Binding(0)]),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                },
                Clause::Effect {
                    reach: None,
                    guard: Some(Box::new(Expr::Eq(
                        Box::new(Expr::Binding(0)),
                        Box::new(Expr::Literal(Value::U64(1))),
                    ))),
                    target: vault(vec![Expr::Binding(0), Expr::Literal(Value::U64(7))]),
                    mode: ModeExpr::Delta { moves: Moves::Both },
                    denomination: None,
                },
            ],
        }];
        let declaration = evaluate_declaration(&clauses, &ins, &TestHasher).unwrap();

        // Elements 0 and 2 name one key, so the *set* folds them; the
        // ordered view keeps one entry per expansion that landed.
        assert_eq!(declaration.ordered.len(), 4);
        assert_eq!(declaration.clause_spans, vec![(0, 4)]);
        // The bare site fired every time; the guarded one only for the
        // element that is not zero.
        assert_eq!(
            declaration.elements(0, 0),
            Some([Some(0), Some(1), Some(3)].as_slice())
        );
        assert_eq!(
            declaration.elements(0, 1),
            Some([None, Some(2), None].as_slice())
        );
        // A site the body does not have, and a clause that is not a loop.
        assert_eq!(declaration.elements(0, 2), None);
        assert_eq!(declaration.elements(1, 0), None);
    }

    #[test]
    fn a_guarded_out_foreach_files_a_site_of_none() {
        // The loop's own guard, not the body's: what it maps over is
        // nothing, so every site over it covers nothing — a width of
        // none rather than no site at all, which is what a binding naming
        // it resolves through.
        let args = [Value::List(vec![Value::U64(1), Value::U64(2)])];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            guard: Some(Box::new(Expr::Literal(Value::Bool(false)))),
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(1)),
                    material: vec![Expr::Binding(0)],
                }),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
        }];
        let declaration = evaluate_declaration(&clauses, &ins, &TestHasher).unwrap();

        assert_eq!(declaration.clause_taken, vec![false]);
        assert!(declaration.ordered.is_empty());
        assert_eq!(declaration.elements(0, 0), Some([].as_slice()));
        // And still nothing for a site the body does not have.
        assert_eq!(declaration.elements(0, 1), None);
    }

    #[test]
    fn a_nested_foreach_records_nothing_of_its_own() {
        // Only a top-level loop is one an ABI binding names, and a body
        // clause that is itself a loop declares no access of its own —
        // so the outer run's row for it is absent whatever the inner one
        // did.
        let args = [
            Value::List(vec![Value::U64(1), Value::U64(2)]),
            Value::List(vec![Value::U64(9)]),
        ];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            guard: None,
            list: Expr::Arg(0),
            body: vec![Clause::ForEach {
                guard: None,
                list: Expr::Arg(1),
                body: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(SlotId(1)),
                        material: vec![Expr::Binding(1), Expr::Binding(0)],
                    }),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                }],
            }],
        }];
        let declaration = evaluate_declaration(&clauses, &ins, &TestHasher).unwrap();

        assert_eq!(declaration.ordered.len(), 2);
        assert_eq!(declaration.elements(0, 0), Some([None, None].as_slice()));
        assert!(
            declaration.expansions.len() == 1,
            "only the outer loop files a map"
        );
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
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(1)),
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

    /// A `for-each` over the widest list, each element guarded by a scan
    /// of a table of `entries` pairs.
    ///
    /// Every element the loop binds is zero, and the table is keyed so
    /// that the one pair matching zero sits at `at` — which is therefore
    /// how far each scan runs. A scan stopping at the first pair says
    /// nothing about the width of the table it stopped in.
    fn scan_over(entries: usize, at: usize) -> [Clause; 1] {
        let table = Expr::Literal(Value::List(
            (0..entries)
                .map(|i| {
                    let key = if i == at { 0 } else { i as u64 + 1 };
                    Value::Tuple(vec![Value::U64(key), Value::U64(0)])
                })
                .collect(),
        ));
        [Clause::ForEach {
            guard: None,
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                reach: None,
                guard: Some(Box::new(Expr::Contains {
                    map: Box::new(table),
                    key: Box::new(Expr::Binding(0)),
                })),
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(16)),
                    material: vec![Expr::Binding(0)],
                }),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
        }]
    }

    /// A scan costs what it scans, and the ceiling is on the work rather
    /// than on the number of scans a signature spells.
    ///
    /// The clause count sees a loop and one guarded access either way, and
    /// the footprint prices the accesses it lands — so without this the
    /// two evaluations below are the same transaction at the same price
    /// and a thousandfold apart in what a node spends deciding them,
    /// before any fee is assured.
    #[test]
    fn a_scan_is_charged_for_what_it_walks() {
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];
        let ins = inputs(&args, &[]);

        // A table a body could plausibly carry, walked whole once per
        // element.
        assert!(evaluate_effects(&scan_over(32, 31), &ins, &TestHasher).is_ok());
        // A wide one, at the same clause count and the same footprint.
        assert_eq!(
            evaluate_effects(
                &scan_over(MAX_VALUE_ITEMS, MAX_VALUE_ITEMS - 1),
                &ins,
                &TestHasher
            ),
            Err(EvalError::TooMuchWork)
        );
    }

    /// A table is read rather than copied, so what a signature may declare
    /// is a statement about work and not about the evaluator.
    ///
    /// The width the case above refuses, scanned to a match on the first
    /// pair. The two differ in how far the scan runs and in nothing else —
    /// same table, same loop, same footprint — so a charge that separates
    /// them is measuring the walk, and one that does not is measuring a
    /// copy the evaluation need never make.
    #[test]
    fn a_table_is_read_rather_than_copied() {
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];
        let ins = inputs(&args, &[]);

        assert!(evaluate_effects(&scan_over(MAX_VALUE_ITEMS, 0), &ins, &TestHasher).is_ok());
    }

    /// The ceiling a caller meets is the envelope's, not one node's.
    ///
    /// Every evaluation below is admissible on its own — the
    /// per-signature bound sees a signature it is happy with each time —
    /// and a manifest holds up to `MAX_MANIFEST_NODES` of them. Admission
    /// runs at ingress over unverified bytes, before any fee is assured,
    /// so what a node is asked to spend is the tree's total, and only a
    /// meter shared across it can say so.
    #[test]
    fn an_envelope_is_bounded_across_the_nodes_it_holds() {
        let node = [Clause::ForEach {
            guard: None,
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                reach: None,
                guard: Some(Box::new(Expr::Contains {
                    map: Box::new(Expr::Literal(Value::List(vec![Value::Tuple(vec![
                        Value::U64(1),
                        Value::U64(0),
                    ])]))),
                    key: Box::new(Expr::Binding(0)),
                })),
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(16)),
                    material: vec![Expr::Binding(0)],
                }),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
        }];
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];

        // One node of it, on a meter of its own.
        let alone = inputs(&args, &[]);
        assert!(evaluate_effects(&node, &alone, &TestHasher).is_ok());

        // The same node again and again, on the meter a tree shares.
        let record = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: Vec::new(),
            salt: Hash32([2; 32]),
        };
        let budget = EvalBudget::default();
        let shared = EvalInputs {
            self_addr: Address::new([7; 31], AddressClass::Component),
            args: &args,
            record: &record,
            node_index: 3,
            identity: ManifestHash(Hash32([9; 32])),
            grants: super::PresentedGrants::none(),
            budget: &budget,
        };
        let mut nodes = 0;
        while evaluate_effects(&node, &shared, &TestHasher).is_ok() {
            nodes += 1;
            assert!(nodes < MAX_MANIFEST_NODES, "the node cap is not the bound");
        }
        assert!(nodes > 1, "a tree-wide bound, not a per-signature one");
        assert_eq!(
            evaluate_effects(&node, &shared, &TestHasher),
            Err(EvalError::EnvelopeTooMuchWork)
        );
    }

    /// A byte string costs what its length costs, not what a scalar
    /// does.
    ///
    /// The one leaf that carries length without carrying elements, and
    /// the one the DSL hands straight to a hash: a key's material is
    /// encoded per iteration, so a wide literal under a loop walks
    /// megabytes at the clause count and footprint of a loop over a
    /// scalar. Counting elements alone prices the two the same.
    #[test]
    fn a_byte_string_is_charged_for_its_length() {
        let over = |len: usize| {
            [Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(SlotId(16)),
                        material: vec![Expr::Binding(0), Expr::Literal(Value::Bytes(vec![0; len]))],
                    }),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                }],
            }]
        };
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS])];
        let ins = inputs(&args, &[]);

        // A mark a body could plausibly carry, hashed once per element.
        assert!(evaluate_effects(&over(32), &ins, &TestHasher).is_ok());
        // The widest a value admits, at the same clause count and the
        // same footprint.
        assert_eq!(
            evaluate_effects(&over(MAX_VALUE_BYTES), &ins, &TestHasher),
            Err(EvalError::TooMuchWork)
        );
    }

    /// An equality costs what it walks, and the ceiling is on the work
    /// rather than on the number of comparisons a signature spells.
    ///
    /// The one operator whose cost is its operands' rather than its own:
    /// every other reads a scalar off a value it was handed, where
    /// equality visits every leaf under both — and refusing a bucket
    /// visits them again. So a wide operand under a loop walks megabytes
    /// at the clause count and footprint of a loop comparing a scalar,
    /// and the two below differ in the operand's width and in nothing
    /// else.
    #[test]
    fn an_equality_is_charged_for_what_it_walks() {
        let clauses = [Clause::ForEach {
            guard: None,
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                reach: None,
                guard: Some(Box::new(Expr::Eq(
                    Box::new(Expr::Arg(1)),
                    Box::new(Expr::Arg(1)),
                ))),
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(16)),
                    material: vec![Expr::Binding(0)],
                }),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
        }];
        let elements = Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS]);

        // A value a caller could plausibly pass, compared once per
        // element.
        let narrow = [elements.clone(), Value::Bytes(vec![0; 32])];
        assert!(evaluate_effects(&clauses, &inputs(&narrow, &[]), &TestHasher).is_ok());
        // The widest a list admits, at the same clause count and the same
        // footprint.
        let wide = [elements, Value::List(vec![Value::U64(0); MAX_VALUE_ITEMS])];
        assert_eq!(
            evaluate_effects(&clauses, &inputs(&wide, &[]), &TestHasher),
            Err(EvalError::TooMuchWork)
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
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(1)),
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
                reach: None,
                guard: None,
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: SlotRef::Fixed(SlotId(4)),
                    material: vec![],
                    lo: Expr::Arg(0),
                    hi: Expr::Arg(1),
                    cap: Expr::Arg(2),
                },
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            },
            Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(9)),
                    material: vec![],
                }),
                mode: ModeExpr::Read,
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
                cap: 8,
            },
            mode: Mode::Write { moves: Moves::Both },
        }));
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(child_key(&TestHasher, ins.self_addr, SlotId(9), &[])),
            mode: Mode::Read,
        }));

        let inverted = [Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: SlotRef::Fixed(SlotId(4)),
                material: vec![],
                lo: Expr::Arg(1),
                hi: Expr::Arg(0),
                cap: Expr::Literal(Value::U64(16)),
            },
            mode: ModeExpr::Write { moves: Moves::Both },
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
            reach: None,
            guard: None,
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: SlotRef::Fixed(SlotId(4)),
                material: vec![Expr::Arg(slot)],
                order: Expr::Literal(Value::U128(9)),
            },
            mode: ModeExpr::Write { moves: Moves::Both },
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
                mode: Mode::Write { moves: Moves::Both },
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
            reach: None,
            guard: None,
            target: TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: SlotRef::Fixed(SlotId(2)),
                material: vec![],
                order: Expr::OrderKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotId(2),
                    material: vec![Expr::Arg(slot)],
                },
            },
            mode: ModeExpr::Write { moves: Moves::Both },
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
                mode: Mode::Write { moves: Moves::Both },
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
            resource: ResourceAddr::new([0xE1; 31]),
            content: EdgeContent::NonFungible { ids: vec![7, 9] },
        };
        let fungible = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]),
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
    fn only_names_the_sole_element_of_a_list() {
        let one = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]),
            content: EdgeContent::NonFungible { ids: vec![7] },
        };
        let two = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]),
            content: EdgeContent::NonFungible { ids: vec![7, 9] },
        };
        let empty = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]),
            content: EdgeContent::NonFungible { ids: vec![] },
        };
        let args = [one, two, empty];
        let ins = inputs(&args, &[]);
        let sole = |arg| Expr::Only(Box::new(Expr::IdsOf(Box::new(Expr::Arg(arg)))));
        assert_eq!(
            evaluate_expr(&sole(0), &ins, &TestHasher),
            Ok(Value::U64(7)),
        );
        // Any other count names no one instance, and the number it did
        // carry is what the refusal says.
        assert_eq!(
            evaluate_expr(&sole(1), &ins, &TestHasher),
            Err(EvalError::NotSingleton { len: 2 }),
        );
        assert_eq!(
            evaluate_expr(&sole(2), &ins, &TestHasher),
            Err(EvalError::NotSingleton { len: 0 }),
        );
    }

    #[test]
    fn len_counts_a_list_and_refuses_anything_else() {
        let list = Value::List(vec![Value::U64(7), Value::U64(9), Value::U64(11)]);
        let bucket = Value::Bucket {
            resource: ResourceAddr::new([0xE1; 31]),
            content: EdgeContent::NonFungible { ids: vec![7, 9] },
        };
        let args = [list, bucket];
        let ins = inputs(&args, &[]);
        assert_eq!(
            evaluate_expr(&Expr::Len(Box::new(Expr::Arg(0))), &ins, &TestHasher),
            Ok(Value::U64(3)),
        );
        // The count of an edge's instances is the length of its id
        // projection — the composition a move's cap is derived through.
        assert_eq!(
            evaluate_expr(
                &Expr::Len(Box::new(Expr::IdsOf(Box::new(Expr::Arg(1))))),
                &ins,
                &TestHasher,
            ),
            Ok(Value::U64(2)),
        );
        // A bucket itself is not a list: the projection is spelled, not
        // implied.
        assert!(evaluate_expr(&Expr::Len(Box::new(Expr::Arg(1))), &ins, &TestHasher).is_err());
    }

    #[test]
    fn addition_sums_one_width_and_refuses_mixing_and_overflow() {
        let args = [Value::U64(7), Value::U128(9), Value::U64(u64::MAX)];
        let ins = inputs(&args, &[]);
        let sum = |left: Expr, right: Expr| {
            evaluate_expr(
                &Expr::Add(Box::new(left), Box::new(right)),
                &ins,
                &TestHasher,
            )
        };
        assert_eq!(sum(Expr::Arg(0), Expr::Arg(0)), Ok(Value::U64(14)));
        assert_eq!(sum(Expr::Arg(1), Expr::Arg(1)), Ok(Value::U128(18)));
        // The widening that would let a u64 meet a u128 is an addition
        // nobody wrote, exactly as `Lt` refuses to order them.
        assert!(sum(Expr::Arg(0), Expr::Arg(1)).is_err());
        // Overflow refuses rather than wraps: a wrapped count would be a
        // different declaration made silently.
        assert_eq!(sum(Expr::Arg(2), Expr::Arg(0)), Err(EvalError::AddOverflow));
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
                resource: ResourceAddr::try_from(resource).expect("resource class"),
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
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(1)),
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
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(1)),
                material: vec![Expr::Arg(0)],
            }),
            mode: ModeExpr::Delta { moves: Moves::Both },
            denomination: Some(Box::new(Expr::Arg(0))),
        }];
        assert_eq!(
            evaluate_declaration(&clauses, &ins, &TestHasher),
            Err(EvalError::NotAResource(WrongClass {
                expected: AddressClass::Resource,
                found: AddressClass::Component,
            })),
        );
    }

    /// The proven set is capped where it is built, so one `Proves` clause
    /// in a `for-each` — which publish counts once — cannot yield more
    /// claims than the cap the count stands for.
    #[test]
    fn a_loop_cannot_prove_past_the_signature_cap() {
        let badges = |n: usize| {
            Expr::Literal(Value::List(
                (0..n)
                    .map(|i| {
                        let mut body = [0xB0u8; 31];
                        body[0] = u8::try_from(i).expect("a small loop");
                        Value::Address(Address::new(body, AddressClass::Resource))
                    })
                    .collect(),
            ))
        };
        let proving = |n: usize| {
            [Clause::ForEach {
                guard: None,
                list: badges(n),
                body: vec![Clause::Proves {
                    guard: None,
                    claim: Expr::Binding(0),
                }],
            }]
        };
        let ins = inputs(&[], &[]);
        assert!(
            evaluate_declaration(&proving(MAX_PROVEN_PER_SIGNATURE), &ins, &TestHasher).is_ok()
        );
        assert_eq!(
            evaluate_declaration(&proving(MAX_PROVEN_PER_SIGNATURE + 1), &ins, &TestHasher),
            Err(EvalError::ProvesPastCap),
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
                resource: ResourceAddr::try_from(resource).expect("resource class"),
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
