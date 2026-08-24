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
//! the expressions a signature evaluates into them. A compile-time gate
//! once had `contains` and nothing else while a stored one had the whole
//! algebra, and nothing justified the split.
//!
//! The caps bound a rule before anything evaluates it. Depth, branch
//! width, and degenerate thresholds — a count of zero, which anyone
//! satisfies, or one past the branch count, which no one does — are
//! refused at decode — where a rule is written, never at evaluation — so
//! [`Rule::satisfied_by`] walks a structure whose size is a constant of
//! the vocabulary, not of the input, and a stored rule always names
//! someone it admits and someone it refuses.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};
use hyperscale_vm_types::{Presence, ResourceAddr};

use crate::dsl::{Expr, TargetExpr};
use crate::presented::Presented;
use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};

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
/// [`MAX_VALUE_BYTES`](crate::MAX_VALUE_BYTES), a role table's entry under
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
/// present, and nothing else. Which claims those are is [`Presented`]'s:
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
    /// [`always`] is a count of zero, [`never`] a count of one, and both
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
    Claim(Presented),
    /// The subject holds this badge: the vault leaf keyed by it is there.
    ///
    /// A fungible holding is one point cell keyed by what it holds, and a
    /// balance reaching zero deletes its leaf — so presence and a nonzero
    /// holding are the same fact, asked once.
    Held(ResourceAddr),
}

/// A rule as it is stored and judged, its leaves resolved.
pub type StoredRule = Rule<SealedLeaf>;

impl Rule<SealedLeaf> {
    /// The one-leaf rule a presented claim satisfies.
    #[must_use]
    pub const fn claim(presented: Presented) -> Self {
        Self::Require(SealedLeaf::Claim(presented))
    }

    /// The one-leaf rule the subject's own holding satisfies.
    #[must_use]
    pub const fn held(badge: ResourceAddr) -> Self {
        Self::Require(SealedLeaf::Held(badge))
    }
}

/// A declared rule's leaf: a claim the declaration names, or the rule
/// stored at a cell under a role.
///
/// The second is what lets a declared rule reach mutable authority — and
/// the type is what bounds the reach: a stored rule is
/// [`Rule<Presented>`], which cannot hold a `Stored` leaf, so a declared
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
    /// The rule stored at this cell, judged where the cell lives.
    ///
    /// The one leaf that reaches mutable authority, and the type is what
    /// bounds the reach: a stored rule is [`StoredRule`], which holds no
    /// `Stored` leaf, so a declared rule reads a stored one exactly one
    /// level deep and no chain of cell reads is expressible.
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
    /// The rule a resource's own address grants for one behaviour,
    /// resolved at admission from the presented record whose derivation
    /// the address commits — no cell read anywhere in the path.
    ///
    /// An unpresented record refuses the call, and so does an absent
    /// behaviour: the granted set is the address's own claim, and a
    /// behaviour it never granted is one nobody holds.
    Granted {
        /// The resource whose granted rules govern, evaluated over the
        /// method's own inputs.
        resource: Expr,
        /// The behaviour selecting the granted rule.
        behaviour: GrantedBehaviour,
    },
}

impl RuleLeaf {
    /// Whether the leaf reads what the caller supplies — the claim's own
    /// expression, or the cell a stored rule is read from.
    /// Whether this leaf's answer is in the store rather than in what a
    /// caller presents.
    ///
    /// The authored twin of [`JudgedLeaf::reads_state_only`], and what
    /// separates a feasibility fact from a gate: a rule of these alone
    /// turns no caller away, so it is not part of who may call a method.
    ///
    /// [`JudgedLeaf::reads_state_only`]: crate::manifest::JudgedLeaf::reads_state_only
    #[must_use]
    pub const fn reads_state_only(&self) -> bool {
        matches!(self, Self::Presence { .. })
    }

    pub(crate) fn reads_call_inputs(&self) -> bool {
        match self {
            Self::Claim(expr) => expr.reads_call_inputs(),
            Self::Stored { cell } => cell.reads_call_inputs(),
            Self::Presence { target, .. } => target.reads_call_inputs(),
            // A caller may name the resource: the rule is the address's
            // own commitment, verified by re-derivation, so the namer
            // chooses which granted rule governs and never what it says
            // — unlike a named claim, which its namer can present, or a
            // named cell, which holds whatever admits them.
            Self::Granted { .. } => false,
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
/// [`check_metadata`]: crate::metadata::check_metadata
pub type RuleExpr = Rule<RuleLeaf>;

/// A granted rule's leaf: a claim a resource's own derivation commits to.
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
pub enum GrantClaim {
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
        /// The mark, as [`GrantClaim::SelfBadge`] states it.
        mark: Vec<u8>,
        /// Which instance of it.
        id: u64,
        /// The rules the badge's own address grants, which name no badge.
        rules: GrantsExpr,
    },
    /// The n-th field of the issuing instance's configuration, whose
    /// address class says which claim it makes — the same reading
    /// [`Presented::of_address`] gives every other declared address.
    Config(u32),
}

impl Rule<RuleLeaf> {
    /// Whether every leaf reads the store alone, which is what keeps a
    /// feasibility fact out of the question of who may call a method.
    #[must_use]
    pub fn reads_state_only(&self) -> bool {
        self.leaves().all(RuleLeaf::reads_state_only)
    }
}

/// A rule a resource's address grants, before the instance that issues it
/// is known.
///
/// The shape is static and only the leaves resolve, on the terms
/// [`RuleExpr`] states — so the caps a declaration is held to at publish
/// are the caps the granted set is held to wherever it is judged.
pub type GrantRuleExpr = Rule<GrantClaim>;

/// The threshold rule one node meets, wherever the rule came from.
///
/// A count of one through the branch count, so the vocabulary holds no
/// rule that admits everyone or no one, over a branch list within the
/// width cap.
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

/// [`never`]'s canonical bytes, as a constant.
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

    /// Replace every leaf with a whole rule, keeping the tree above it.
    ///
    /// What a leaf that *names* a rule resolves through: a grant leaf
    /// stands for the tree its resource commits to, and grafting is how
    /// that tree takes the leaf's place under whatever threshold held
    /// it. The caller re-checks the grafted tree against the caps — a
    /// graft can deepen what a map never could.
    ///
    /// # Errors
    ///
    /// Whatever `graft` refuses a leaf with, unchanged.
    pub fn try_graft<T, E>(
        &self,
        graft: &mut impl FnMut(&L) -> Result<Rule<T>, E>,
    ) -> Result<Rule<T>, E> {
        Ok(match self {
            Self::Require(leaf) => graft(leaf)?,
            Self::CountOf { count, rules } => Rule::CountOf {
                count: *count,
                rules: rules
                    .iter()
                    .map(|rule| rule.try_graft(graft))
                    .collect::<Result<_, _>>()?,
            },
        })
    }
}

impl StoredRule {
    /// Whether the presented claims satisfy this rule.
    ///
    /// Total over any presented set, including degenerate thresholds
    /// built in memory: one requiring nothing is satisfied by anyone,
    /// and one requiring more than its branch count by no one — though
    /// neither survives decode, so no stored rule holds either form.
    /// Recursion is bounded by the decode gate: a rule this crate
    /// decoded nests at most [`MAX_RULE_DEPTH`] deep.
    ///
    /// The stored instantiation alone. A declared rule's leaves are
    /// expressions, and asking whether an expression is among those
    /// presented compares two spellings rather than two claims — a
    /// question with an answer and no meaning. What turns one into the
    /// other is [`Rule::map_leaves`], and there is no way round it.
    #[must_use]
    pub fn satisfied_by(&self, presented: &[Presented]) -> bool {
        match self {
            // A holding is not a claim, so a claims-only judge cannot
            // meet one. Nothing routes such a rule here: an actor
            // question's rule holds claims alone, refused otherwise where
            // the rule is sealed, and a holder question's holdings are
            // resolved to presence leaves before anything is judged.
            Self::Require(SealedLeaf::Held(_)) => false,
            Self::Require(SealedLeaf::Claim(claim)) => presented.contains(claim),
            Self::CountOf { count, rules } => {
                let met = rules
                    .iter()
                    .filter(|rule| rule.satisfied_by(presented))
                    .count();
                met >= usize::from(*count)
            }
        }
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
    use crate::presented::Presented;

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
    pub fn identity(byte: u8) -> Presented {
        Presented::of_subject(target(byte))
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

    use super::testing::{WideRule, chain, identity, wide_chain};
    use super::{
        MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_LEAVES, NOBODY_BYTES, Rule, SealedLeaf,
        StoredRule, always, never,
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

    #[test]
    fn a_threshold_is_satisfied_at_its_count_and_not_below() {
        let two_of_three = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::claim(identity(1)),
                StoredRule::claim(identity(2)),
                StoredRule::claim(identity(3)),
            ],
        };
        assert!(two_of_three.satisfied_by(&[identity(1), identity(3)]));
        assert!(two_of_three.satisfied_by(&[identity(1), identity(2), identity(3)]));
        assert!(!two_of_three.satisfied_by(&[identity(2)]));
        assert!(!two_of_three.satisfied_by(&[identity(4), identity(5)]));
        assert!(!two_of_three.satisfied_by(&[]));

        // A nested branch counts as one branch however many identities
        // satisfy its inside.
        let key_or_guardians = StoredRule::CountOf {
            count: 1,
            rules: vec![
                StoredRule::claim(identity(1)),
                StoredRule::CountOf {
                    count: 2,
                    rules: vec![
                        StoredRule::claim(identity(2)),
                        StoredRule::claim(identity(3)),
                    ],
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
        let vacuous = StoredRule::CountOf {
            count: 0,
            rules: vec![],
        };
        assert!(vacuous.satisfied_by(&[]));

        // Requiring more than the branches offer is satisfied by no one.
        let unsatisfiable = StoredRule::CountOf {
            count: 2,
            rules: vec![StoredRule::claim(identity(1))],
        };
        assert!(!unsatisfiable.satisfied_by(&[identity(1), identity(2)]));

        // A repeated branch counts once per appearance.
        let doubled = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::claim(identity(1)),
                StoredRule::claim(identity(1)),
            ],
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

        assert!(anyone.satisfied_by(&[]));
        assert!(anyone.satisfied_by(&[identity(1)]));
        assert!(!nobody.satisfied_by(&[]));
        assert!(!nobody.satisfied_by(&[identity(1)]));

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
