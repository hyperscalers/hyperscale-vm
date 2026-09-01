//! The authority rule vocabulary.
//!
//! A rule names which claims may act as the object that stores it: a
//! single claim, or a count over sub-rules. `CountOf(1, …)` is
//! disjunction and a count requiring every branch is conjunction, so
//! one constructor covers "this key", "any of these three", and "two of
//! these five" without a second form.
//!
//! One tree serves both sides of the vocabulary, differing in its leaf
//! alone: [`StoredRule`] holds the claims themselves and [`RuleExpr`]
//! the expressions a signature evaluates into them.
//!
//! The caps bound a rule before anything evaluates it. Depth, branch
//! width, and a count past the branches it is over are refused at decode
//! — where a rule is written, never at evaluation — so
//! [`Rule::satisfied_by`] walks a structure whose size is a constant of
//! the vocabulary, not of the input.
//!
//! The threshold over *no* branches is the exception, and it is how this
//! algebra spells its two constants: a count of zero over nothing admits
//! everyone, a count of one over nothing admits nobody. Both are
//! storable, both have exactly one spelling ([`always()`] and [`never()`]),
//! and a constant standing beside real branches is refused for the same
//! reason a degenerate count would be — everyone-may beside anything is
//! everyone-may, and no-one-may beside it is the rest of the threshold.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};
use hyperscale_vm_types::{Presence, ResourceAddr};

use crate::claim::Claim;
use crate::dsl::{Expr, TargetExpr};
use crate::resource::{GrantsExpr, ResourceKind};

/// The bound on a rule's nesting depth: a lone identity is one, a
/// threshold one more than its deepest branch.
///
/// Two levels cover every flat shape — "this key", "k of these keys" —
/// and four admit a threshold whose branches are themselves small
/// key sets, which is the widest shape a guardian arrangement plausibly
/// takes. A bound on pre-payment work — a gate judges a rule before any
/// fee is assured — sized against evaluation cost rather than
/// measurement, and worth revisiting when a real rule shape exists.
pub const MAX_RULE_DEPTH: usize = 4;

/// The bound on one threshold's branch count, on the same pre-payment
/// terms as [`MAX_RULE_DEPTH`].
///
/// A shape bound rather than a size one: what a tree of this depth and
/// this width may hold in total is [`MAX_RULE_LEAVES`], which is the
/// figure that binds.
pub const MAX_RULE_BRANCHES: usize = 16;

/// The leaves one rule may hold, however it arranges them.
///
/// The size bound the shape bounds do not give: depth and branch width
/// together admit `MAX_RULE_BRANCHES^(MAX_RULE_DEPTH - 1)` leaves, and a
/// tree that wide is neither a shape a guardian arrangement takes nor
/// one anybody could hand to a package. A stored rule travels as
/// [`Value::Bytes`](crate::Value::Bytes) — an argument under
/// [`MAX_VALUE_BYTES`](crate::types::MAX_VALUE_BYTES), a role table's entry under
/// the same — so past
/// what those bytes hold, a rule the caps admit is a rule no call can
/// carry. Sized so the widest tree inside the shape bounds encodes well
/// under that cap, pinned by test.
pub const MAX_RULE_LEAVES: usize = 64;

/// The decoder nesting cap that admits exactly the [`StoredRule`]s
/// within [`MAX_RULE_DEPTH`].
///
/// One threshold level costs two decoder levels — the branch list field
/// and its hoisted element body — and a terminal costs two, its own
/// field and the claim inside it, so the deepest admissible rule sits
/// one level under this cap and any deeper one costs at least one past
/// it. The relation is pinned by test at both boundaries;
/// [`StoredRule::from_slice`] decodes under this cap and gets the depth
/// gate as a decode-time consequence rather than a pass afterwards.
///
/// The stored instantiation alone, because the terminal's cost is its
/// leaf's: a [`RuleExpr`] carries an expression there and is never
/// decoded on its own, arriving inside metadata under that cap instead.
pub const MAX_RULE_WIRE_DEPTH: usize = 2 * MAX_RULE_DEPTH + 1;

/// An authority rule: a threshold over leaves.
///
/// The leaf is the only thing the two sides of the vocabulary disagree
/// about. A stored rule's leaves are the claims themselves; a declared
/// rule's are expressions over a method's own inputs, which evaluate
/// into claims. Everything above the leaf — the algebra, the caps, the
/// walk — is one implementation, which is what lets a gate fixed at
/// publish say "two of these three" in the same words a stored one does.
///
/// Amounts are deliberately absent — a rule asks which claims are
/// present, and nothing else. Which claims those are is [`Claim`]'s:
/// an identity acting as itself, a badge resource, or one instance of
/// one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
#[hbor(validate = well_formed)]
pub enum Rule<L> {
    /// Satisfied when this leaf is among those presented.
    Require(L),
    /// Satisfied when enough branches are.
    ///
    /// Over an empty branch list this is the algebra's top and bottom:
    /// [`always`] is a count of zero, [`never()`] a count of one, and both
    /// fall out of the same `met >= count` the judge already computes.
    CountOf {
        /// How many of `rules` must be satisfied. Over branches, at
        /// least one and at most the branch count; over none, zero or
        /// one — the decode gate refuses the rest.
        count: u8,
        /// The branches, each judged independently over the same
        /// presented set.
        #[hbor(max = MAX_RULE_BRANCHES)]
        rules: Vec<Self>,
    },
}

/// The stage that answers: for a leaf, the earliest stage whose
/// knowledge holds its answer; for a rule, the earliest stage that can
/// answer every leaf it holds.
///
/// One ladder for both questions, because a rule's placement is read off
/// its leaves — nothing declares one, and no reviewer has to check that
/// a declaration stated one honestly.
///
/// Three stages know three things: admission holds what a caller
/// presents, which is signed content and needs no state; materialization
/// holds committed state, before any body runs; the leg's session is the
/// only stage holding evidence and state together. So the fold over a
/// rule is a join rather than a max — a rule mixing an admission-answered
/// leaf with a materialization-answered one lands in the leg, though each
/// leaf alone is answered earlier, because no single earlier stage holds
/// both.
///
/// The order matters for one property beyond cost. **Admission and
/// materialization both land before any leg commits**, so a verdict
/// reached there aborts the whole transaction and no caller has
/// committed on the strength of it. A verdict reached in the walk lands
/// inside the declaring node's own leg, which a caller may already have
/// committed without waiting for — which is what a
/// [`Total`](crate::signature::Totality::Total) frame may not carry.
///
/// That reading holds for admission and it is where the star classifier
/// parts company on materialization. A node the classifier peels off the
/// core as an outbound leg materializes on its own shard *after* the
/// core committed, so a verdict reached there does land on a caller that
/// already committed — the halt fence and any movement entry resolving
/// to a [`Presence`](crate::manifest::JudgedLeaf::Presence) leaf both
/// can. So the classifier asks for [`Judged::AtAdmission`] alone rather
/// than for this, and the two questions stay apart: this one is about
/// what may abort a transaction, and that one is about what may be
/// waited on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judged {
    /// From presented evidence, which is signed content and needs no
    /// state at all.
    AtAdmission,
    /// From committed state, by the shard holding the leaf, before any
    /// leg runs.
    AtMaterialization,
    /// In the walk of the declaring node's own leg — the only stage
    /// holding the evidence and the session together, and so the only
    /// one a stored rule can be read in.
    InTheLeg,
}

impl Judged {
    /// Whether the verdict lands before any leg commits.
    ///
    /// What separates a feasibility fact from a verdict a caller could
    /// already have committed past.
    #[must_use]
    pub const fn before_any_leg(self) -> bool {
        !matches!(self, Self::InTheLeg)
    }
}

/// A rule's leaf, at whichever point of its life the rule is: authored,
/// sealed, or evaluated.
///
/// One question — where is this leaf's answer — and every walk over a
/// rule's placement is a fold over it, written once. That is also what
/// holds the vocabulary's instantiations to one reading: a sealed leaf
/// predicts what its evaluated twin will say because both answer here,
/// per leaf, rather than in parallel folds kept agreeing by hand.
pub trait Leaf {
    /// The stage that answers this leaf.
    fn judged(&self) -> Judged;

    /// Whether this leaf's answer is in the store rather than in what a
    /// caller presents — what separates a feasibility fact from a gate:
    /// a rule of these alone turns no caller away, so it is not part of
    /// who may call a method.
    fn reads_state_only(&self) -> bool {
        matches!(self.judged(), Judged::AtMaterialization)
    }
}

/// A rule as it is sealed and judged, its leaves resolved.
///
/// Two sources and no more, because a sealed rule has no call to read and
/// no expression left to evaluate: a claim somebody presents, and a badge
/// the rule's own subject holds. Who that subject is, is the rule's
/// position — the cell's owner for a rule stored in one, the access's
/// owner for a movement entry — which is what lets one sealed rule govern
/// a holder nobody had named when it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum SealedLeaf {
    /// A claim the presented set must contain.
    Claim(Claim),
    /// The subject holds this badge, in the shape the holding names.
    Held {
        /// The badge held.
        badge: ResourceAddr,
        /// Which of the subject's holdings of it the presence is about.
        holding: Holding,
    },
}

impl Leaf for SealedLeaf {
    /// A holding is a standing fact in the store about the moving party;
    /// a claim stays a claim. No sealed leaf is judged in the leg —
    /// settled at the seal, before any holder has been named and before
    /// any transaction exists, because each sealed leaf maps one-to-one
    /// onto the evaluated leaf answered at the same stage.
    fn judged(&self) -> Judged {
        match self {
            Self::Claim(_) => Judged::AtAdmission,
            Self::Held { .. } => Judged::AtMaterialization,
        }
    }
}

/// Where a subject's holding of one badge lives, and how much of it the
/// question is about.
///
/// A badge's address folds its kind, so a rule naming a badge it derives
/// knows which shape to ask about; a rule naming one through
/// configuration does not, and asks both — which costs it the second
/// read rather than an answer that is silently always false.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Holding {
    /// A balance: the one point cell keyed by what it holds.
    ///
    /// A balance reaching zero deletes its leaf, so presence and a
    /// nonzero holding are the same fact, asked once.
    Balance,
    /// Any instance of it: the subject's collection for the badge holds
    /// an entry, whichever one.
    AnyInstance,
    /// One named instance: the entry at its id.
    Instance(u64),
}

/// A rule as it is stored and judged, its leaves resolved.
pub type StoredRule = Rule<SealedLeaf>;

impl Rule<SealedLeaf> {
    /// The one-leaf rule a presented claim satisfies.
    #[must_use]
    pub const fn claim(presented: Claim) -> Self {
        Self::Require(SealedLeaf::Claim(presented))
    }

    /// The one-leaf rule the subject's own holding satisfies.
    #[must_use]
    pub const fn held(badge: ResourceAddr, holding: Holding) -> Self {
        Self::Require(SealedLeaf::Held { badge, holding })
    }
}

/// A declared rule's leaf: a claim the declaration names, or the rule
/// stored at a cell under a role.
///
/// The second is what lets a declared rule reach mutable authority — and
/// the type is what bounds the reach: a stored rule is
/// [`Rule<Claim>`], which cannot hold a `Stored` leaf, so a declared
/// rule reads stored rules exactly one level deep and no chain of cell
/// reads is expressible. Mixing follows for free — "the configured
/// owner, or two of the stored admins" is one rule with leaves of both
/// kinds — and the cost is legible in the same clause: a claim over
/// configuration reads no state, a stored leaf is a provisioned read of
/// a mutable cell.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum RuleLeaf {
    /// A claim the declaration names, evaluated over the method's own
    /// inputs into the claim a caller must present.
    Claim(Expr),
    /// The rule stored at this cell, judged where the cell lives — the
    /// one leaf that reaches mutable authority.
    Stored {
        /// The cell expression the rule lives at. Declared as an access
        /// by the same signature, which is what provisions it to every
        /// participant.
        cell: Expr,
    },
    /// The leaf this target names is there, or is not.
    ///
    /// The one leaf answered from the store rather than from what a
    /// caller presented, which is what decides where a rule holding it is
    /// judged. A rule of these alone states a feasibility fact and is
    /// answered before any body runs; one mixing them with a claim is
    /// judged at the call, like any rule that reads evidence.
    Presence {
        /// The cell the question is about, evaluated over the method's
        /// own inputs. Declared as an access by the same signature, which
        /// is what provisions it to every participant.
        target: Box<TargetExpr>,
        /// What must be true of it. Never [`Presence::Either`], which
        /// requires nothing and is refused at publish.
        expect: Presence,
    },
}

impl Leaf for RuleLeaf {
    /// The authored twin of [`JudgedLeaf`]'s answer: each leaf resolves
    /// into the evaluated leaf answered at the same stage, so what a
    /// declaration says about placement is what its evaluation does.
    ///
    /// [`JudgedLeaf`]: crate::manifest::JudgedLeaf
    fn judged(&self) -> Judged {
        match self {
            Self::Claim(_) => Judged::AtAdmission,
            Self::Stored { .. } => Judged::InTheLeg,
            Self::Presence { .. } => Judged::AtMaterialization,
        }
    }
}

impl RuleLeaf {
    /// Whether the leaf reads what the caller supplies — the claim's own
    /// expression, or the cell a stored rule is read from.
    pub(crate) fn reads_call_inputs(&self) -> bool {
        match self {
            Self::Claim(expr) => expr.reads_call_inputs(),
            Self::Stored { cell } => cell.reads_call_inputs(),
            Self::Presence { target, .. } => target.reads_call_inputs(),
        }
    }
}

/// A rule as a signature declares it, its leaves over a method's own
/// inputs.
///
/// Authored as its own tree rather than an expression evaluating to a
/// rule: a rule-valued expression would let a rule's *shape* depend on
/// evaluation, so the depth a signature declares could not be bounded at
/// publish. Here the shape is static and only the leaves evaluate, which
/// is what lets [`check_metadata`] hold an authored tree to the same caps
/// the decode gate holds a stored one to.
///
/// [`check_metadata`]: crate::check_metadata
pub type RuleExpr = Rule<RuleLeaf>;

/// A granted rule's leaf: the subject a resource's own derivation
/// commits to.
///
/// The behaviour owns the question — an actor question resolves it to a
/// claim, a holder question to a holding — so the leaf names only the
/// subject both ask about.
///
/// Its own closed vocabulary rather than [`RuleLeaf`], because a granted
/// rule is folded into an address rather than judged against a cell.
/// **The tree stays a tree**: reusing [`RuleLeaf`] would put a [`Rule`]
/// inside an [`Expr`] while [`RuleLeaf::Claim`] already holds one, making
/// the two mutually recursive and their depth caps a joint property.
///
/// What it can name is what a resource's own address already knows: the
/// instance that issues it, a badge that instance issues, or a field of
/// the configuration the instance's address folds. Nothing a caller
/// supplies, because a caller supplies nothing to a derivation.
///
/// A badge carries the rules **it** grants, because an address is the
/// hash of them: a leaf deriving through the granting-nothing form would
/// name an address nothing is minted at the moment the badge grants
/// anything — and a credential badge is soulbound by granting
/// `Withdraw: Never`, so that is the ordinary case rather than the exotic
/// one. What keeps the derivation well-founded is that **those rules name
/// no badge of their own**: the chain one address folds is one link long,
/// refused at publish and at resolution alike, so a resource's address
/// depth is a property of the resource rather than of how deeply its
/// author nested. A cycle is unreachable for the same reason.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum GrantSubject {
    /// The issuing instance, acting as itself.
    SelfAddr,
    /// A badge the issuing instance also issues, at the material
    /// separating it from the instance's others.
    ///
    /// Naming a non-fungible one here is naming **any instance of it**,
    /// which is the same reading `#[requires(..)]` gives the same words —
    /// one spelling, one meaning, wherever it is written.
    SelfBadge {
        /// The mark, canonically encoded into the badge's derivation.
        mark: Vec<u8>,
        /// What the badge is, folded into its derivation beside the mark.
        kind: ResourceKind,
        /// The rules the badge's own address grants, which name no badge.
        rules: GrantsExpr,
    },
    /// One named instance of a non-fungible badge the issuing instance
    /// also issues.
    SelfInstance {
        /// The mark, as [`GrantSubject::SelfBadge`] states it.
        mark: Vec<u8>,
        /// Which instance of it.
        id: u64,
        /// The rules the badge's own address grants, which name no badge.
        rules: GrantsExpr,
    },
    /// The n-th field of the issuing instance's configuration, whose
    /// address class says which claim it makes — the same reading
    /// [`Claim::of_address`] gives every other declared address.
    Config(u32),
}

impl<L: Leaf> Rule<L> {
    /// Where this rule is judged, read off its leaves: the earliest
    /// stage that can answer every one of them.
    ///
    /// A rule reaching a leg-judged leaf needs the leg; one mixing
    /// evidence with state needs both, and no single earlier stage holds
    /// them. Everything else is answerable at one stage alone.
    ///
    /// One fold for every instantiation, which is what pins the reading
    /// a record's holder is owed to the reading a transaction gets: a
    /// sealed rule's placement *is* its evaluated twin's, because both
    /// are this walk over leaves answered at the same stage. An entry
    /// asking a standing fact about the moving party is answered before
    /// any body runs and turns nobody away mid-transaction; one asking
    /// whether this transaction was approved is answered before it is a
    /// transaction at all; one asking both is the only shape that lands
    /// inside a leg.
    ///
    /// A rule with no leaves is the algebra's own constant — satisfied
    /// by anyone or by no one — and admission decides those as cheaply
    /// as anything else does.
    #[must_use]
    pub fn judged(&self) -> Judged {
        let mut state = false;
        let mut evidence = false;
        for leaf in self.leaves() {
            match leaf.judged() {
                Judged::InTheLeg => return Judged::InTheLeg,
                Judged::AtMaterialization => state = true,
                Judged::AtAdmission => evidence = true,
            }
        }
        match (state, evidence) {
            (true, true) => Judged::InTheLeg,
            (true, false) => Judged::AtMaterialization,
            (false, _) => Judged::AtAdmission,
        }
    }

    /// Whether every leaf reads the store alone, which is what keeps a
    /// feasibility fact out of the question of who may call a method.
    #[must_use]
    pub fn reads_state_only(&self) -> bool {
        self.leaves().all(Leaf::reads_state_only)
    }
}

/// A rule a resource's address grants, before the instance that issues it
/// is known.
///
/// The shape is static and only the leaves resolve, on the terms
/// [`RuleExpr`] states — so the caps a declaration is held to at publish
/// are the caps the granted set is held to wherever it is judged.
pub type GrantRuleExpr = Rule<GrantSubject>;

/// How many leaves a tree holds, over every branch of it.
fn leaves<L>(rule: &Rule<L>) -> usize {
    let mut total = 0;
    let mut stack = vec![rule];
    while let Some(rule) = stack.pop() {
        match rule {
            Rule::Require(_) => total += 1,
            Rule::CountOf { rules, .. } => stack.extend(rules),
        }
    }
    total
}

/// The threshold rule one node meets, wherever the rule came from.
///
/// A count within the branch count, over a branch list within the width
/// cap. The empty threshold is admitted at both ends and means what it
/// reads as: a count of zero over no branches admits everyone, and a
/// count of one over no branches admits nobody.
///
/// One node rather than a tree, which is what lets every side share it.
/// As a decode gate it runs per value, so branches judge themselves and
/// the check never recurses; inside [`Rule::within_caps`] it is what the
/// walk applies at each node; the tracer's `n_of` and the macro's
/// threshold lowering judge each node they build through it, so a
/// refusal cannot fork between the span-bearing copy and the one that
/// panics. Depth is absent because it is the one cap the sides do not
/// share a mechanism for — a stored rule takes it from the decoder's own
/// nesting bound, a declared one from the caps walk, a written one from
/// the lowering's counter.
///
/// # Errors
///
/// The refusal, phrased for whoever wrote the rule: each caller adds its
/// own span or panic site and passes the reason through.
pub fn well_formed<L>(rule: &Rule<L>) -> Result<(), &'static str> {
    match rule {
        Rule::Require(_) => Ok(()),
        // The threshold over nothing is how this algebra spells its top
        // and its bottom: none of nothing is met by anyone, one of
        // nothing by no one, and the judge computes both from `met >=
        // count` without an arm of its own. Two counts and no more, so
        // each constant has one spelling.
        Rule::CountOf { count, rules } if rules.is_empty() => {
            if *count > 1 {
                Err("everyone is a count of zero over no branches and no one is a count of one")
            } else {
                Ok(())
            }
        }
        Rule::CountOf { count, rules } => {
            // A constant branch is a rule that could be written shorter:
            // everyone-may beside anything is everyone-may, and no-one-may
            // beside it is the rest of the threshold. Refused on the same
            // grounds a degenerate count is, so each meaning has one
            // spelling however deep it sits.
            if rules
                .iter()
                .any(|branch| matches!(branch, Rule::CountOf { rules, .. } if rules.is_empty()))
            {
                Err("a threshold branching on everyone or on no one can be written shorter")
            } else if *count == 0 {
                Err("a threshold over branches requiring none of them is the empty threshold")
            } else if usize::from(*count) > rules.len() {
                Err("a threshold requiring more branches than it has would admit no one")
            } else if rules.len() > MAX_RULE_BRANCHES {
                Err("a threshold branches wider than the vocabulary admits")
            } else if leaves(rule) > MAX_RULE_LEAVES {
                Err("a rule holds more leaves than the vocabulary admits")
            } else {
                Ok(())
            }
        }
    }
}

/// The rule anyone satisfies: none of nothing.
#[must_use]
pub const fn always<L>() -> Rule<L> {
    Rule::CountOf {
        count: 0,
        rules: Vec::new(),
    }
}

/// The rule nobody satisfies: one of nothing.
#[must_use]
pub const fn never<L>() -> Rule<L> {
    Rule::CountOf {
        count: 1,
        rules: Vec::new(),
    }
}

/// [`never()`]'s canonical bytes, as a constant.
///
/// Spelled out rather than encoded, because the one writer that needs it
/// is a guest and a guest cannot carry a rule's codec: the vocabulary is
/// recursive, and the deterministic profile wants an acyclic call graph.
/// The bytes are pinned against the encoder by test, so the constant
/// cannot drift from what the vocabulary would produce.
pub const NOBODY_BYTES: &[u8] = &[1, 1, 0];

impl<L> Rule<L> {
    /// Whether the tree sits inside the caps a stored rule is decoded
    /// under, so a signature that passes bounds cannot evaluate into a
    /// rule the decode gate would refuse.
    #[must_use]
    pub fn within_caps(&self, depth: usize) -> bool {
        if depth >= MAX_RULE_DEPTH {
            return false;
        }
        match self {
            Self::Require(_) => true,
            Self::CountOf { rules, .. } => {
                well_formed(self).is_ok() && rules.iter().all(|rule| rule.within_caps(depth + 1))
            }
        }
    }

    /// Every leaf, in preorder.
    pub fn leaves(&self) -> impl Iterator<Item = &L> {
        let mut stack = vec![self];
        std::iter::from_fn(move || {
            loop {
                match stack.pop()? {
                    Self::Require(leaf) => return Some(leaf),
                    Self::CountOf { rules, .. } => stack.extend(rules.iter().rev()),
                }
            }
        })
    }

    /// The same tree with every leaf replaced by what `map` makes of it.
    ///
    /// What turns a declared rule into the concrete one a gate judges,
    /// and the only place the two instantiations meet.
    ///
    /// # Errors
    ///
    /// Whatever `map` refuses: a leaf that does not evaluate, or one
    /// whose value names no claim.
    pub fn map_leaves<T, E>(&self, map: &mut impl FnMut(&L) -> Result<T, E>) -> Result<Rule<T>, E> {
        Ok(match self {
            Self::Require(leaf) => Rule::Require(map(leaf)?),
            Self::CountOf { count, rules } => Rule::CountOf {
                count: *count,
                rules: rules
                    .iter()
                    .map(|rule| rule.map_leaves(map))
                    .collect::<Result<_, _>>()?,
            },
        })
    }
}

impl Rule<Claim> {
    /// Whether the presented claims satisfy this rule.
    ///
    /// Total over any presented set, including degenerate thresholds
    /// built in memory: one requiring nothing is satisfied by anyone,
    /// and one requiring more than its branch count by no one — though
    /// neither survives decode, so no stored rule holds either form.
    /// Recursion is bounded by the decode gate: a rule this crate
    /// decoded nests at most [`MAX_RULE_DEPTH`] deep.
    ///
    /// Claims and nothing else. A holding is not a claim and a declared
    /// leaf is an expression, and asking whether either is among those
    /// presented compares two spellings rather than two claims — a
    /// question with an answer and no meaning. What turns one into the
    /// other is [`Rule::map_leaves`], and there is no way round it: a
    /// rule holding a leaf this judge cannot read does not reach it.
    #[must_use]
    pub fn satisfied_by(&self, presented: &[Claim]) -> bool {
        match self {
            Self::Require(claim) => presented.contains(claim),
            Self::CountOf { count, rules } => {
                let met = rules
                    .iter()
                    .filter(|rule| rule.satisfied_by(presented))
                    .count();
                met >= usize::from(*count)
            }
        }
    }
}

impl StoredRule {
    /// The claims this rule asks about, or nothing where it asks about
    /// something else.
    ///
    /// A holding is resolved to the presence of a key before anything
    /// judges it, so a stored rule still holding one is a rule no
    /// claims-only judge can answer — and the answer to a question that
    /// cannot be asked is not "no", it is that there is no answer.
    #[must_use]
    pub fn claims_only(&self) -> Option<Rule<Claim>> {
        self.map_leaves(&mut |leaf| match leaf {
            SealedLeaf::Claim(claim) => Ok(*claim),
            SealedLeaf::Held { .. } => Err(()),
        })
        .ok()
    }

    /// The rule's canonical wire bytes.
    ///
    /// Encoded under the same caps the decoder enforces, so a writer
    /// cannot exceed a bound a reader refuses. Degenerate thresholds are
    /// construction's to avoid: they encode, and the bytes are refused
    /// where they land.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past [`MAX_RULE_DEPTH`]; a branch list
    /// past [`MAX_RULE_BRANCHES`] is refused by the encoding itself.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, MAX_RULE_WIRE_DEPTH)
    }

    /// One whole rule from its canonical wire bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on trailing bytes, a non-canonical form, a rule
    /// past either cap, or a degenerate threshold.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, MAX_RULE_WIRE_DEPTH)
    }
}

impl RuleExpr {
    /// A rule requiring one claim the declaration names.
    #[must_use]
    pub const fn claim(expr: Expr) -> Self {
        Self::Require(RuleLeaf::Claim(expr))
    }

    /// Whether any leaf reads what the caller supplies.
    ///
    /// A caller who names the claim they must present can always present
    /// it — and a caller who names the cell a rule is read from names
    /// one holding whatever admits them — so the method reads as guarded
    /// and admits everyone. Every leaf answers, because one caller-named
    /// branch of a threshold is one branch the caller satisfies for
    /// free.
    ///
    /// A presence leaf is not that, and is why this asks about the
    /// evidence-reading leaves rather than about the tree: what a
    /// presence reads is state, and what keeps a caller from naming
    /// somewhere else is the access the same declaration must declare
    /// beside it.
    #[must_use]
    pub(crate) fn names_caller_authority(&self) -> bool {
        self.leaves()
            .any(|leaf| !leaf.reads_state_only() && leaf.reads_call_inputs())
    }
}

/// Scaffolding the vocabulary's boundary tests share, here and in the
/// role-set tests beside them: the uncapped wire twin — the source of
/// bytes a compliant encoder refuses to produce — and the chain
/// builders that walk the depth caps.
#[cfg(test)]
pub(crate) mod testing {
    use hyperscale_hbor::Hbor;
    use hyperscale_vm_types::{Address, AddressClass, CallTarget};

    use super::{SealedLeaf, StoredRule};
    use crate::claim::Claim;

    /// The same wire form as [`StoredRule`], with no caps.
    ///
    /// One leaf rather than a generic, because the stored instantiation
    /// is the only one with a wire form to twin: a declared rule reaches
    /// the decoder inside metadata, under metadata's cap.
    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    pub enum WideRule {
        Require(SealedLeaf),
        CountOf { count: u8, rules: Vec<Self> },
    }

    /// A test principal from one byte.
    pub fn principal(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Principal)
    }

    /// The same principal, narrowed to the position an identity claim
    /// carries.
    pub fn target(byte: u8) -> CallTarget {
        CallTarget::try_from(principal(byte)).expect("a principal is callable")
    }

    /// The claim that principal makes acting as itself.
    pub fn identity(byte: u8) -> Claim {
        Claim::of_subject(target(byte))
    }

    /// `levels` thresholds over one identity: nests `levels + 1` deep.
    pub fn chain(levels: usize) -> StoredRule {
        let mut rule = StoredRule::claim(identity(1));
        for _ in 0..levels {
            rule = StoredRule::CountOf {
                count: 1,
                rules: vec![rule],
            };
        }
        rule
    }

    /// The same chain through the uncapped twin.
    pub fn wide_chain(levels: usize) -> WideRule {
        let mut rule = WideRule::Require(SealedLeaf::Claim(identity(1)));
        for _ in 0..levels {
            rule = WideRule::CountOf {
                count: 1,
                rules: vec![rule],
            };
        }
        rule
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, to_vec};
    use hyperscale_vm_types::ResourceAddr;

    use super::testing::{WideRule, chain, identity, wide_chain};
    use super::{
        Holding, MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_LEAVES, NOBODY_BYTES, Rule,
        SealedLeaf, StoredRule, always, never,
    };
    use crate::types::MAX_VALUE_BYTES;

    /// The widest tree holding `leaves` leaves: the most thresholds the
    /// depth cap allows above them, since every one costs bytes of its
    /// own.
    fn widest(leaves: usize) -> StoredRule {
        fn build(leaves: usize, depth: usize) -> StoredRule {
            if leaves <= 1 || depth <= 1 {
                return StoredRule::claim(identity(1));
            }
            // The fewest branches that still reach `leaves` within the
            // depth left, so the tree above them is as tall as it can be.
            let reach = |branches: usize| (1..depth).fold(1, |wide, _| wide * branches);
            let mut branches = 2;
            while branches < MAX_RULE_BRANCHES && reach(branches) < leaves {
                branches += 1;
            }
            let per = leaves.div_ceil(branches);
            let mut rules = Vec::new();
            let mut left = leaves;
            while left > 0 {
                let take = per.min(left);
                rules.push(build(take, depth - 1));
                left -= take;
            }
            Rule::CountOf { count: 1, rules }
        }
        build(leaves, MAX_RULE_DEPTH)
    }

    /// A rule the vocabulary admits is a rule a call can carry.
    ///
    /// The leaf cap and the value byte cap meet here: a stored rule
    /// reaches a package as bytes in a value, so a tree the caps admit
    /// and the bytes cannot hold would be a rule nobody could ever hand
    /// over. The widest admissible tree encodes well inside the cap, and
    /// one leaf past it is refused where the tree is written rather than
    /// where the bytes are counted.
    #[test]
    fn the_widest_admissible_rule_fits_the_bytes_a_value_carries() {
        let widest_admitted = widest(MAX_RULE_LEAVES);
        let bytes = widest_admitted.to_bytes().expect("encodes");
        assert!(bytes.len() <= MAX_VALUE_BYTES, "{} bytes", bytes.len());
        assert_eq!(
            StoredRule::from_slice(&bytes).as_ref(),
            Ok(&widest_admitted)
        );

        let over = widest(MAX_RULE_LEAVES + 1);
        assert!(!over.within_caps(0));
        let bytes = to_vec(&over).expect("encoding does not judge the leaf count");
        assert!(matches!(
            StoredRule::from_slice(&bytes),
            Err(DecodeError::FailedValidation(_))
        ));
    }

    /// A claims judge is handed claims, and a rule holding anything else
    /// does not reach it.
    ///
    /// The old shape answered `false` for a holding leaf and leaned on a
    /// comment saying nothing routes one there. `false` is an answer,
    /// and the wrong one: a threshold could reach its count around the
    /// leaf, and `GrantedBehaviour::demanded`'s self-subtraction reads
    /// the same verdict to decide an actor already discharges a rule.
    /// Nothing reaches the judge now — the leaf has no place in its
    /// argument type — and `claims_only` is where the refusal happens.
    #[test]
    fn a_rule_about_a_holding_never_reaches_a_claims_judge() {
        let holding = StoredRule::Require(SealedLeaf::Held {
            badge: ResourceAddr::new([0xBA; 31]),
            holding: Holding::Balance,
        });
        assert_eq!(holding.claims_only(), None);

        // And one branch of it is enough: the rule is not partly
        // answerable.
        let mixed = StoredRule::CountOf {
            count: 1,
            rules: vec![StoredRule::claim(identity(1)), holding],
        };
        assert_eq!(mixed.claims_only(), None);

        // What does reach it carries over leaf for leaf.
        let claims = StoredRule::CountOf {
            count: 1,
            rules: vec![StoredRule::claim(identity(1))],
        };
        assert!(
            claims
                .claims_only()
                .expect("claims alone")
                .satisfied_by(&[identity(1)])
        );
    }

    #[test]
    fn a_threshold_is_satisfied_at_its_count_and_not_below() {
        let two_of_three = Rule::CountOf {
            count: 2,
            rules: vec![
                Rule::Require(identity(1)),
                Rule::Require(identity(2)),
                Rule::Require(identity(3)),
            ],
        };
        assert!(two_of_three.satisfied_by(&[identity(1), identity(3)]));
        assert!(two_of_three.satisfied_by(&[identity(1), identity(2), identity(3)]));
        assert!(!two_of_three.satisfied_by(&[identity(2)]));
        assert!(!two_of_three.satisfied_by(&[identity(4), identity(5)]));
        assert!(!two_of_three.satisfied_by(&[]));

        // A nested branch counts as one branch however many identities
        // satisfy its inside.
        let key_or_guardians = Rule::CountOf {
            count: 1,
            rules: vec![
                Rule::Require(identity(1)),
                Rule::CountOf {
                    count: 2,
                    rules: vec![Rule::Require(identity(2)), Rule::Require(identity(3))],
                },
            ],
        };
        assert!(key_or_guardians.satisfied_by(&[identity(1)]));
        assert!(key_or_guardians.satisfied_by(&[identity(2), identity(3)]));
        assert!(!key_or_guardians.satisfied_by(&[identity(3)]));
    }

    #[test]
    fn evaluation_is_total_over_degenerate_forms() {
        // Requiring nothing is satisfied by anyone, including no one.
        let vacuous = Rule::CountOf {
            count: 0,
            rules: Vec::new(),
        };
        assert!(vacuous.satisfied_by(&[]));

        // Requiring more than the branches offer is satisfied by no one.
        let unsatisfiable = Rule::CountOf {
            count: 2,
            rules: vec![Rule::Require(identity(1))],
        };
        assert!(!unsatisfiable.satisfied_by(&[identity(1), identity(2)]));

        // A repeated branch counts once per appearance.
        let doubled = Rule::CountOf {
            count: 2,
            rules: vec![Rule::Require(identity(1)), Rule::Require(identity(1))],
        };
        assert!(doubled.satisfied_by(&[identity(1)]));
    }

    /// A threshold over branches must be one the branch count can meet,
    /// and must not restate what a shorter rule says. Construction and
    /// encoding stay total; the bytes are refused where they land.
    #[test]
    fn a_degenerate_threshold_is_refused_at_decode() {
        let refused = |rule: StoredRule, why: &'static str| {
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(
                StoredRule::from_slice(&bytes),
                Err(DecodeError::FailedValidation(why))
            );
        };

        refused(
            StoredRule::CountOf {
                count: 0,
                rules: vec![StoredRule::claim(identity(1))],
            },
            "a threshold over branches requiring none of them is the empty threshold",
        );
        refused(
            StoredRule::CountOf {
                count: 2,
                rules: vec![StoredRule::claim(identity(1))],
            },
            "a threshold requiring more branches than it has would admit no one",
        );

        // Each constant has one count, so a third spelling of no one is
        // refused rather than accepted as a synonym.
        refused(
            StoredRule::CountOf {
                count: 2,
                rules: vec![],
            },
            "everyone is a count of zero over no branches and no one is a count of one",
        );

        // A branch judges itself as it decodes, and a constant branch is
        // a rule the author could have written shorter.
        refused(
            StoredRule::CountOf {
                count: 1,
                rules: vec![StoredRule::claim(identity(1)), always()],
            },
            "a threshold branching on everyone or on no one can be written shorter",
        );

        // The gate's whole boundary: count one and count == branches
        // both decode.
        for count in [1, 2] {
            let rule = StoredRule::CountOf {
                count,
                rules: vec![
                    StoredRule::claim(identity(1)),
                    StoredRule::claim(identity(2)),
                ],
            };
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(StoredRule::from_slice(&bytes).unwrap(), rule);
        }
    }

    /// The bytes a guest writes to close a rule are the bytes the
    /// encoder produces, held against it here because the guest cannot
    /// run the encoder to check for itself.
    #[test]
    fn the_closed_rule_constant_is_what_the_encoder_writes() {
        let closed: StoredRule = never();
        assert_eq!(closed.to_bytes().unwrap(), NOBODY_BYTES);
        assert_eq!(StoredRule::from_slice(NOBODY_BYTES).unwrap(), closed);
    }

    /// The algebra's top and bottom are the threshold over nothing, and
    /// they survive the round trip the vocabulary holds every rule to.
    ///
    /// The judge needs no arm for either: `met >= count` is met by zero
    /// of zero and unmet by one of zero, which is why admitting them is a
    /// deletion in the gate rather than a variant everything downstream
    /// has to learn.
    #[test]
    fn the_empty_threshold_is_everyone_and_no_one() {
        let anyone: StoredRule = always();
        let nobody: StoredRule = never();

        // Leafless, so both carry over to a claims judge whole.
        let (anyone_claims, nobody_claims) = (
            anyone.claims_only().expect("no leaf to refuse"),
            nobody.claims_only().expect("no leaf to refuse"),
        );
        assert!(anyone_claims.satisfied_by(&[]));
        assert!(anyone_claims.satisfied_by(&[identity(1)]));
        assert!(!nobody_claims.satisfied_by(&[]));
        assert!(!nobody_claims.satisfied_by(&[identity(1)]));

        for rule in [&anyone, &nobody] {
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(&StoredRule::from_slice(&bytes).unwrap(), rule);
        }
        assert_ne!(anyone, nobody, "and they are different rules");
    }

    #[test]
    fn the_wire_form_is_canonical_and_round_trips() {
        let rule = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::claim(identity(1)),
                StoredRule::CountOf {
                    count: 1,
                    rules: vec![
                        StoredRule::claim(identity(2)),
                        StoredRule::claim(identity(3)),
                    ],
                },
                StoredRule::claim(identity(4)),
            ],
        };
        assert_canonical(&rule);
        let bytes = rule.to_bytes().unwrap();
        assert_eq!(StoredRule::from_slice(&bytes).unwrap(), rule);
    }

    /// The wire cap admits exactly the admissible depths, at both
    /// boundaries: one threshold level costs two decoder levels and a
    /// terminal one more, so the relation is a constant, not a
    /// heuristic. A chain of `levels` thresholds over one identity
    /// nests `levels + 1` deep.
    #[test]
    fn the_wire_depth_cap_matches_the_rule_depth_gate() {
        // Depth MAX encodes and decodes.
        let deepest = chain(MAX_RULE_DEPTH - 1);
        let bytes = deepest.to_bytes().unwrap();
        assert_eq!(StoredRule::from_slice(&bytes).unwrap(), deepest);

        // Depth MAX + 1 is refused at encode, and its bytes — produced
        // through the uncapped twin — at decode.
        assert!(chain(MAX_RULE_DEPTH).to_bytes().is_err());
        let bytes = to_vec(&wide_chain(MAX_RULE_DEPTH)).unwrap();
        assert!(StoredRule::from_slice(&bytes).is_err());
    }

    #[test]
    fn a_branch_list_past_the_cap_is_refused_at_decode() {
        let branches = |count: usize| WideRule::CountOf {
            count: 1,
            rules: (0..count)
                .map(|i| WideRule::Require(SealedLeaf::Claim(identity(u8::try_from(i).unwrap()))))
                .collect(),
        };

        let widest = to_vec(&branches(MAX_RULE_BRANCHES)).unwrap();
        assert!(StoredRule::from_slice(&widest).is_ok());

        let wider = to_vec(&branches(MAX_RULE_BRANCHES + 1)).unwrap();
        assert_eq!(
            StoredRule::from_slice(&wider),
            Err(DecodeError::BoundExceeded {
                max: MAX_RULE_BRANCHES,
                actual: MAX_RULE_BRANCHES + 1,
            })
        );
    }
}
