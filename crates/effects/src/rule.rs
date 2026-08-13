//! The authority rule vocabulary.
//!
//! A rule names which identities may act as the object that stores it: a
//! single identity, or a count over sub-rules. `CountOf(1, …)` is
//! disjunction and a count requiring every branch is conjunction, so
//! one constructor covers "this key", "any of these three", and "two of
//! these five" without a second form.
//!
//! The caps bound a rule before anything evaluates it. Depth, branch
//! width, and degenerate thresholds — a count of zero, which anyone
//! satisfies, or one past the branch count, which no one does — are
//! refused at decode — where a rule is written, never at evaluation — so
//! [`Rule::satisfied_by`] walks a structure whose size is a constant of
//! the vocabulary, not of the input, and a stored rule always names
//! someone it admits and someone it refuses.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};

use crate::types::Address;

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

/// The decoder nesting cap that admits exactly the rules within
/// [`MAX_RULE_DEPTH`].
///
/// One threshold level costs two decoder levels — the branch list field
/// and its hoisted element body — and a terminal costs one more, its own
/// field, so the deepest admissible rule sits one level under this cap
/// and any deeper one costs at least one past it. The relation is pinned
/// by test at both boundaries; [`Rule::from_slice`] decodes under this
/// cap and gets the depth gate as a decode-time consequence rather than
/// a pass afterwards.
pub const MAX_RULE_WIRE_DEPTH: usize = 2 * MAX_RULE_DEPTH;

/// An authority rule: a threshold over identities.
///
/// Proof resources, amounts, and holder-presented custody are
/// deliberately absent — a rule asks which identities are present, and
/// nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
#[hbor(validate = well_formed)]
pub enum Rule {
    /// Satisfied when this identity is among those presented.
    Require(Address),
    /// Satisfied when enough branches are.
    CountOf {
        /// How many of `rules` must be satisfied. At least one, at most
        /// the branch count — the decode gate refuses the rest.
        count: u8,
        /// The branches, each judged independently over the same
        /// identity set.
        #[hbor(max = MAX_RULE_BRANCHES)]
        rules: Vec<Self>,
    },
}

/// The decode gate on one threshold: a count of one through the branch
/// count, so the vocabulary holds no rule that admits everyone or no
/// one. Runs as each value decodes, so branches judge themselves and
/// the check never recurses.
fn well_formed(rule: &Rule) -> Result<(), &'static str> {
    match rule {
        Rule::Require(_) => Ok(()),
        Rule::CountOf { count, rules } => {
            if *count == 0 {
                Err("a threshold requiring nothing would admit anyone")
            } else if usize::from(*count) > rules.len() {
                Err("a threshold requiring more branches than it has would admit no one")
            } else {
                Ok(())
            }
        }
    }
}

impl Rule {
    /// Whether the presented identities satisfy this rule.
    ///
    /// Total over any identity set, including degenerate thresholds
    /// built in memory: one requiring nothing is satisfied by anyone,
    /// and one requiring more than its branch count by no one — though
    /// neither survives decode, so no stored rule holds either form.
    /// Recursion is bounded by the decode gate: a rule this crate
    /// decoded nests at most [`MAX_RULE_DEPTH`] deep.
    #[must_use]
    pub fn satisfied_by(&self, identities: &[Address]) -> bool {
        match self {
            Self::Require(identity) => identities.contains(identity),
            Self::CountOf { count, rules } => {
                let met = rules
                    .iter()
                    .filter(|rule| rule.satisfied_by(identities))
                    .count();
                met >= usize::from(*count)
            }
        }
    }

    /// The rule's nesting depth: an identity is one, a threshold one more
    /// than its deepest branch. Measured over an explicit stack, so
    /// measurement is total even where evaluation would not be.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut deepest = 0;
        let mut stack: Vec<(&Self, usize)> = vec![(self, 1)];
        while let Some((rule, depth)) = stack.pop() {
            deepest = deepest.max(depth);
            if let Self::CountOf { rules, .. } = rule {
                stack.extend(rules.iter().map(|branch| (branch, depth + 1)));
            }
        }
        deepest
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

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, Hbor, assert_canonical, to_vec};

    use super::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, Rule};
    use crate::types::{Address, AddressClass};

    fn identity(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Principal)
    }

    /// The same wire form as [`Rule`], with no caps: the source of bytes
    /// a compliant encoder refuses to produce.
    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    enum Wide {
        Require(Address),
        CountOf { count: u8, rules: Vec<Self> },
    }

    fn wide_chain(levels: usize) -> Wide {
        let mut rule = Wide::Require(identity(1));
        for _ in 0..levels {
            rule = Wide::CountOf {
                count: 1,
                rules: vec![rule],
            };
        }
        rule
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
            rules: vec![],
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

    /// A stored rule must name someone it admits and someone it refuses:
    /// the vacuous threshold would hand the account to anyone, and the
    /// unsatisfiable one would lock every role for good — securify is
    /// one-way, so no rule could undo either. Construction and encoding
    /// stay total; the bytes are refused where they land.
    #[test]
    fn a_degenerate_threshold_is_refused_at_decode() {
        let refused = |rule: Rule, why: &'static str| {
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(
                Rule::from_slice(&bytes),
                Err(DecodeError::FailedValidation(why))
            );
        };

        refused(
            Rule::CountOf {
                count: 0,
                rules: vec![],
            },
            "a threshold requiring nothing would admit anyone",
        );
        refused(
            Rule::CountOf {
                count: 0,
                rules: vec![Rule::Require(identity(1))],
            },
            "a threshold requiring nothing would admit anyone",
        );
        refused(
            Rule::CountOf {
                count: 2,
                rules: vec![Rule::Require(identity(1))],
            },
            "a threshold requiring more branches than it has would admit no one",
        );

        // A branch judges itself as it decodes, so a well-formed
        // threshold cannot smuggle a degenerate one inside.
        refused(
            Rule::CountOf {
                count: 1,
                rules: vec![
                    Rule::Require(identity(1)),
                    Rule::CountOf {
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
            let rule = Rule::CountOf {
                count,
                rules: vec![Rule::Require(identity(1)), Rule::Require(identity(2))],
            };
            let bytes = rule.to_bytes().unwrap();
            assert_eq!(Rule::from_slice(&bytes).unwrap(), rule);
        }
    }

    #[test]
    fn the_wire_form_is_canonical_and_round_trips() {
        let rule = Rule::CountOf {
            count: 2,
            rules: vec![
                Rule::Require(identity(1)),
                Rule::CountOf {
                    count: 1,
                    rules: vec![Rule::Require(identity(2)), Rule::Require(identity(3))],
                },
                Rule::Require(identity(4)),
            ],
        };
        assert_canonical(&rule);
        let bytes = rule.to_bytes().unwrap();
        assert_eq!(Rule::from_slice(&bytes).unwrap(), rule);
    }

    /// The wire cap admits exactly the admissible depths, at both
    /// boundaries: one threshold level costs two decoder levels and a
    /// terminal one more, so the relation is a constant, not a
    /// heuristic.
    #[test]
    fn the_wire_depth_cap_matches_the_rule_depth_gate() {
        let chain = |levels: usize| {
            let mut rule = Rule::Require(identity(1));
            for _ in 0..levels {
                rule = Rule::CountOf {
                    count: 1,
                    rules: vec![rule],
                };
            }
            rule
        };

        // Depth MAX encodes and decodes.
        let deepest = chain(MAX_RULE_DEPTH - 1);
        assert_eq!(deepest.depth(), MAX_RULE_DEPTH);
        let bytes = deepest.to_bytes().unwrap();
        assert_eq!(Rule::from_slice(&bytes).unwrap(), deepest);

        // Depth MAX + 1 is refused at encode, and its bytes — produced
        // through the uncapped twin — at decode.
        let deeper = chain(MAX_RULE_DEPTH);
        assert_eq!(deeper.depth(), MAX_RULE_DEPTH + 1);
        assert!(deeper.to_bytes().is_err());
        let bytes = to_vec(&wide_chain(MAX_RULE_DEPTH)).unwrap();
        assert!(Rule::from_slice(&bytes).is_err());
    }

    #[test]
    fn a_branch_list_past_the_cap_is_refused_at_decode() {
        let branches = |count: usize| Wide::CountOf {
            count: 1,
            rules: (0..count)
                .map(|i| Wide::Require(identity(u8::try_from(i).unwrap())))
                .collect(),
        };

        let widest = to_vec(&branches(MAX_RULE_BRANCHES)).unwrap();
        assert!(Rule::from_slice(&widest).is_ok());

        let wider = to_vec(&branches(MAX_RULE_BRANCHES + 1)).unwrap();
        assert_eq!(
            Rule::from_slice(&wider),
            Err(DecodeError::BoundExceeded {
                max: MAX_RULE_BRANCHES,
                actual: MAX_RULE_BRANCHES + 1,
            })
        );
    }
}
