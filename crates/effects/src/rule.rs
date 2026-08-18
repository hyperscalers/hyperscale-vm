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

use crate::dsl::Expr;
use crate::presented::Presented;

/// The bound on a rule's nesting depth: a lone identity is one, a
/// threshold one more than its deepest branch.
///
/// Two levels cover every flat shape — "this key", "k of these keys" —
/// and four admit a threshold whose branches are themselves small
/// key sets, which is the widest shape a guardian arrangement plausibly
/// takes. Sized against evaluation cost rather than measurement, and
/// worth revisiting when a real rule shape exists.
pub const MAX_RULE_DEPTH: usize = 4;

/// The bound on one threshold's branch count.
///
/// With [`MAX_RULE_DEPTH`], the worst admissible rule holds
/// `MAX_RULE_BRANCHES^(MAX_RULE_DEPTH - 1)` identity leaves — 4096 — so
/// evaluating one is a few thousand address comparisons before it starts.
pub const MAX_RULE_BRANCHES: usize = 16;

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
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(validate = well_formed)]
pub enum Rule<L> {
    /// Satisfied when this leaf is among those presented.
    Require(L),
    /// Satisfied when enough branches are.
    CountOf {
        /// How many of `rules` must be satisfied. At least one, at most
        /// the branch count — the decode gate refuses the rest.
        count: u8,
        /// The branches, each judged independently over the same
        /// presented set.
        #[hbor(max = MAX_RULE_BRANCHES)]
        rules: Vec<Self>,
    },
}

/// A rule as it is stored and judged, its leaves the claims themselves.
pub type StoredRule = Rule<Presented>;

/// A rule as a signature declares it, its leaves expressions over a
/// method's own inputs.
///
/// Authored as its own tree rather than an expression evaluating to a
/// rule: a rule-valued expression would let a rule's *shape* depend on
/// evaluation, so the depth a signature declares could not be bounded at
/// publish. Here the shape is static and only the leaves evaluate, which
/// is what lets [`check_metadata`] hold an authored tree to the same caps
/// the decode gate holds a stored one to.
///
/// [`check_metadata`]: crate::metadata::check_metadata
pub type RuleExpr = Rule<Expr>;

/// The threshold rule one node meets, wherever the rule came from: a
/// count of one through the branch count, so the vocabulary holds no
/// rule that admits everyone or no one, over a branch list within the
/// width cap.
///
/// One node rather than a tree, which is what lets both sides share it.
/// As a decode gate it runs per value, so branches judge themselves and
/// the check never recurses; inside [`Rule::within_caps`] it is what the
/// walk applies at each node. Depth is absent because it is the one cap
/// the two sides do not share a mechanism for — a stored rule takes it
/// from the decoder's own nesting bound, a declared one from that walk.
fn well_formed<L>(rule: &Rule<L>) -> Result<(), &'static str> {
    match rule {
        Rule::Require(_) => Ok(()),
        Rule::CountOf { count, rules } => {
            if *count == 0 {
                Err("a threshold requiring nothing would admit anyone")
            } else if usize::from(*count) > rules.len() {
                Err("a threshold requiring more branches than it has would admit no one")
            } else if rules.len() > MAX_RULE_BRANCHES {
                Err("a threshold branches wider than the vocabulary admits")
            } else {
                Ok(())
            }
        }
    }
}

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

impl<L: PartialEq> Rule<L> {
    /// Whether the presented claims satisfy this rule.
    ///
    /// Total over any presented set, including degenerate thresholds
    /// built in memory: one requiring nothing is satisfied by anyone,
    /// and one requiring more than its branch count by no one — though
    /// neither survives decode, so no stored rule holds either form.
    /// Recursion is bounded by the decode gate: a rule this crate
    /// decoded nests at most [`MAX_RULE_DEPTH`] deep.
    #[must_use]
    pub fn satisfied_by(&self, presented: &[L]) -> bool {
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
    /// Whether any leaf reads what the caller supplies.
    ///
    /// A caller who names the claim they must present can always present
    /// it, so the method reads as guarded and admits everyone. Every
    /// leaf answers, because one caller-named branch of a threshold is
    /// one branch the caller satisfies for free.
    #[must_use]
    pub fn reads_call_inputs(&self) -> bool {
        match self {
            Self::Require(claim) => claim.reads_call_inputs(),
            Self::CountOf { rules, .. } => rules.iter().any(Self::reads_call_inputs),
        }
    }
}

/// Scaffolding the vocabulary's boundary tests share, here and in the
/// role-set tests beside them: the uncapped wire twin — the source of
/// bytes a compliant encoder refuses to produce — and the chain
/// builders that walk the depth caps.
#[cfg(test)]
pub(crate) mod testing {
    use hyperscale_hbor::Hbor;

    use super::StoredRule;
    use crate::presented::Presented;
    use crate::types::{Address, AddressClass};

    /// The same wire form as [`StoredRule`], with no caps.
    ///
    /// One leaf rather than a generic, because the stored instantiation
    /// is the only one with a wire form to twin: a declared rule reaches
    /// the decoder inside metadata, under metadata's cap.
    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    pub enum WideRule {
        Require(Presented),
        CountOf { count: u8, rules: Vec<Self> },
    }

    /// A test principal from one byte.
    pub fn principal(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Principal)
    }

    /// The claim that principal makes acting as itself.
    pub fn identity(byte: u8) -> Presented {
        Presented::Identity(principal(byte))
    }

    /// `levels` thresholds over one identity: nests `levels + 1` deep.
    pub fn chain(levels: usize) -> StoredRule {
        let mut rule = StoredRule::Require(identity(1));
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
        let mut rule = WideRule::Require(identity(1));
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
    use super::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, StoredRule};

    #[test]
    fn a_threshold_is_satisfied_at_its_count_and_not_below() {
        let two_of_three = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::Require(identity(1)),
                StoredRule::Require(identity(2)),
                StoredRule::Require(identity(3)),
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
                StoredRule::Require(identity(1)),
                StoredRule::CountOf {
                    count: 2,
                    rules: vec![
                        StoredRule::Require(identity(2)),
                        StoredRule::Require(identity(3)),
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
            rules: vec![StoredRule::Require(identity(1))],
        };
        assert!(!unsatisfiable.satisfied_by(&[identity(1), identity(2)]));

        // A repeated branch counts once per appearance.
        let doubled = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::Require(identity(1)),
                StoredRule::Require(identity(1)),
            ],
        };
        assert!(doubled.satisfied_by(&[identity(1)]));
    }

    /// A stored rule must name someone it admits and someone it refuses:
    /// the vacuous threshold would hand the account to anyone, and the
    /// unsatisfiable one would lock every role for good — securify is
    /// one-way, so no rule could undo either. Construction and encoding
    /// stay total; the bytes are refused where they land.
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
                rules: vec![],
            },
            "a threshold requiring nothing would admit anyone",
        );
        refused(
            StoredRule::CountOf {
                count: 0,
                rules: vec![StoredRule::Require(identity(1))],
            },
            "a threshold requiring nothing would admit anyone",
        );
        refused(
            StoredRule::CountOf {
                count: 2,
                rules: vec![StoredRule::Require(identity(1))],
            },
            "a threshold requiring more branches than it has would admit no one",
        );

        // A branch judges itself as it decodes, so a well-formed
        // threshold cannot smuggle a degenerate one inside.
        refused(
            StoredRule::CountOf {
                count: 1,
                rules: vec![
                    StoredRule::Require(identity(1)),
                    StoredRule::CountOf {
                        count: 0,
                        rules: vec![],
                    },
                ],
            },
            "a threshold requiring nothing would admit anyone",
        );

        // The gate's whole boundary: count one and count == branches
        // both decode.
        for count in [1, 2] {
            let rule = StoredRule::CountOf {
                count,
                rules: vec![
                    StoredRule::Require(identity(1)),
                    StoredRule::Require(identity(2)),
                ],
            };
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(StoredRule::from_slice(&bytes).unwrap(), rule);
        }
    }

    #[test]
    fn the_wire_form_is_canonical_and_round_trips() {
        let rule = StoredRule::CountOf {
            count: 2,
            rules: vec![
                StoredRule::Require(identity(1)),
                StoredRule::CountOf {
                    count: 1,
                    rules: vec![
                        StoredRule::Require(identity(2)),
                        StoredRule::Require(identity(3)),
                    ],
                },
                StoredRule::Require(identity(4)),
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
                .map(|i| WideRule::Require(identity(u8::try_from(i).unwrap())))
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
