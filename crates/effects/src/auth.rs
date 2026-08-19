//! The account's stored-authority cell: three rules, a recovery delay,
//! and at most one timed proposal.
//!
//! One encoded record, read and written through this module by everyone
//! who touches it — the account guest that stores it, the kernel's gate,
//! and the payer shard's binding verdict. There is no second
//! implementation to agree with.
//!
//! Nothing applies a matured proposal: every reader compares its
//! instant against the transaction clock through [`AuthCell::governing`]
//! and answers under whichever base that picks. The write-side fold —
//! promoting a matured proposal's base before rewriting the cell — is
//! compaction of what reads already answer, never a change of verdict.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};
use hyperscale_vm_types::Address;

use crate::presented::Presented;
use crate::rule::{MAX_RULE_WIRE_DEPTH, StoredRule};

/// The decoder cap that admits exactly the role sets within the rule
/// vocabulary's caps.
///
/// The struct's field body costs one decoder level over the deepest
/// rule. The relation is pinned by test at both boundaries.
pub const MAX_ROLESET_WIRE_DEPTH: usize = MAX_RULE_WIRE_DEPTH + 1;

/// Which stored rule a role-gated method is judged against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum AuthRole {
    /// Governs `authorize`, and so everything the account does.
    Primary,
    /// May propose a replacement for all three rules.
    Recovery,
    /// May enact a proposal before it matures.
    Confirmation,
}

/// The three stored rules of a securified account.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct RoleSet {
    /// Governs `authorize`, and so everything the account does —
    /// including paying, at the payer shard's binding verdict.
    pub primary: StoredRule,
    /// Governs `propose`.
    pub recovery: StoredRule,
    /// Governs `confirm`.
    pub confirmation: StoredRule,
}

impl RoleSet {
    /// One rule as all three roles.
    #[must_use]
    pub fn uniform(rule: StoredRule) -> Self {
        Self {
            primary: rule.clone(),
            recovery: rule.clone(),
            confirmation: rule,
        }
    }

    /// The rule `role` selects.
    #[must_use]
    pub const fn rule(&self, role: AuthRole) -> &StoredRule {
        match role {
            AuthRole::Primary => &self.primary,
            AuthRole::Recovery => &self.recovery,
            AuthRole::Confirmation => &self.confirmation,
        }
    }

    /// The role set's canonical wire bytes, under the same caps the
    /// decoder enforces.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past the vocabulary caps.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, MAX_ROLESET_WIRE_DEPTH)
    }

    /// One whole role set from its canonical wire bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on trailing bytes, a non-canonical form, a rule
    /// past either vocabulary cap, or a degenerate threshold.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, MAX_ROLESET_WIRE_DEPTH)
    }
}

/// A role set as it is stored and carried: the canonical bytes, not the
/// tree.
///
/// The one thing in the cell that stays opaque, and for a reason the
/// runtime fixes rather than a preference. A [`StoredRule`] is
/// recursive, so its decoder is; the deterministic profile requires an
/// acyclic call graph, because a static stack bound is what makes stack
/// exhaustion unreachable in both engines rather than reachable at
/// different depths in each ([crates/runtime/src/frames.rs]). A guest
/// therefore cannot carry a rule's codec, and a package that stores
/// authority moves these bytes without reading them. Whoever judges a
/// rule decodes them, under the vocabulary's own caps, where the judging
/// happens.
///
/// [crates/runtime/src/frames.rs]: https://docs.rs/
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
#[hbor(transparent)]
pub struct StoredRoles(pub Vec<u8>);

impl StoredRoles {
    /// The canonical bytes, which is all a body may do with one: what
    /// they mean was settled where they were decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The role set these bytes encode.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on bytes that are not a role set within the
    /// vocabulary's caps.
    pub fn decode(&self) -> Result<RoleSet, DecodeError> {
        RoleSet::from_slice(&self.0)
    }
}

impl TryFrom<&RoleSet> for StoredRoles {
    type Error = EncodeError;

    fn try_from(roles: &RoleSet) -> Result<Self, EncodeError> {
        roles.to_bytes().map(Self)
    }
}

/// The decoder nesting bound for a whole cell.
///
/// Five levels to the deepest field, and constant: the cell's own body,
/// the `Option` around a proposal, the proposal's body, the base's body
/// inside it, and the byte string holding the roles. What nests
/// unboundedly is a rule, and no rule is in here — the roles are one
/// opaque field, decoded at their own cap wherever one is judged. Pinned
/// by test at both boundaries.
pub const MAX_AUTH_CELL_WIRE_DEPTH: usize = 5;

/// The cell's persistent half: the delay a proposal must wait, and the
/// roles that govern while none has matured.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct AuthBase {
    /// How long a proposal waits before it governs, in weighted-time
    /// milliseconds.
    pub recovery_delay_ms: u64,
    /// The three stored rules, as the bytes they were decoded from.
    pub roles: StoredRoles,
}

impl AuthBase {
    /// The base holding `roles`, encoded.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past the vocabulary caps.
    pub fn new(recovery_delay_ms: u64, roles: &RoleSet) -> Result<Self, EncodeError> {
        Ok(Self {
            recovery_delay_ms,
            roles: StoredRoles::try_from(roles)?,
        })
    }
}

/// A pending replacement for the whole base, governing from its instant.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Proposal {
    /// The weighted-time instant the proposal's base starts governing,
    /// computed where the proposal is written: the transaction clock
    /// plus the recovery delay stored beside the roles it replaces.
    pub effective_at_ms: u64,
    /// The replacement base, whole: roles and delay together.
    pub base: AuthBase,
}

/// The decoded stored-authority cell.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct AuthCell {
    /// The persistent half.
    pub base: AuthBase,
    /// At most one pending replacement.
    pub proposal: Option<Proposal>,
}

impl AuthCell {
    /// A cell holding `base` and nothing pending.
    #[must_use]
    pub const fn new(base: AuthBase) -> Self {
        Self {
            base,
            proposal: None,
        }
    }

    /// Decode one whole cell from its stored bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on a truncated or non-canonical encoding, trailing
    /// bytes, or a role set past either vocabulary cap.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, MAX_AUTH_CELL_WIRE_DEPTH)
    }

    /// The cell's canonical wire bytes, under the same cap the decoder
    /// enforces.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past the vocabulary caps.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, MAX_AUTH_CELL_WIRE_DEPTH)
    }

    /// The base that governs at `clock_ms`: the proposal's once its
    /// instant has arrived, the stored one until then.
    #[must_use]
    pub const fn governing(&self, clock_ms: u64) -> &AuthBase {
        match &self.proposal {
            Some(proposal) if proposal.effective_at_ms <= clock_ms => &proposal.base,
            _ => &self.base,
        }
    }

    /// The stored-rule verdict, whole: whether the claims presented to
    /// `target`'s cell satisfy the rule `role` selects at `clock_ms`.
    ///
    /// This is the one judgment both readers share — the kernel's gate
    /// asks it with a call's evidence, the payer shard's binding verdict
    /// with the envelope signer alone and the primary, since paying is
    /// governed by whatever governs `authorize`. An empty `stored` is an
    /// account that never securified: the virtual rule, the identity the
    /// target's address derives, whichever role asks. Stored bytes that
    /// do not decode admit nobody — the write path refuses such bytes,
    /// so these are not a rule, and a cell that cannot be read fails
    /// closed.
    #[must_use]
    pub fn admits(
        stored: &[u8],
        target: Address,
        role: AuthRole,
        evidence: &[Presented],
        clock_ms: u64,
    ) -> bool {
        if stored.is_empty() {
            return evidence.contains(&Presented::Identity(target));
        }
        Self::from_slice(stored).is_ok_and(|cell| {
            cell.governing(clock_ms)
                .roles
                .decode()
                .is_ok_and(|roles| roles.rule(role).satisfied_by(evidence))
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Hbor, from_slice_with_depth, to_vec, to_vec_with_depth};

    use super::{
        AuthBase, AuthCell, AuthRole, MAX_AUTH_CELL_WIRE_DEPTH, Proposal, RoleSet, StoredRoles,
    };
    use crate::presented::Presented;
    use crate::rule::testing::{WideRule, chain, identity, principal, wide_chain};
    use crate::rule::{MAX_RULE_DEPTH, StoredRule};

    fn base(byte: u8, delay: u64) -> AuthBase {
        AuthBase::new(
            delay,
            &RoleSet::uniform(StoredRule::Require(identity(byte))),
        )
        .unwrap()
    }

    #[test]
    fn a_role_selects_its_rule() {
        let roles = RoleSet {
            primary: StoredRule::Require(identity(1)),
            recovery: StoredRule::Require(identity(2)),
            confirmation: StoredRule::Require(identity(3)),
        };
        assert_eq!(
            roles.rule(AuthRole::Primary),
            &StoredRule::Require(identity(1))
        );
        assert_eq!(
            roles.rule(AuthRole::Recovery),
            &StoredRule::Require(identity(2))
        );
        assert_eq!(
            roles.rule(AuthRole::Confirmation),
            &StoredRule::Require(identity(3))
        );
    }

    #[test]
    fn the_cell_round_trips_with_and_without_a_proposal() {
        let bare = AuthCell::new(base(1, 86_400_000));
        let bytes = bare.to_bytes().unwrap();
        assert_eq!(AuthCell::from_slice(&bytes).unwrap(), bare);

        let pending = AuthCell {
            base: base(1, 86_400_000),
            proposal: Some(Proposal {
                effective_at_ms: 1_700_000_000_000,
                base: base(2, 3_600_000),
            }),
        };
        let bytes = pending.to_bytes().unwrap();
        assert_eq!(AuthCell::from_slice(&bytes).unwrap(), pending);
    }

    /// The cell is the encoding of its own fields, in declaration order
    /// and with nothing between them — so what a reader decodes is what
    /// the writer's type says, and there is no second layout to agree
    /// with.
    #[test]
    fn the_cell_is_its_own_encoding() {
        let roles = RoleSet::uniform(StoredRule::Require(identity(7)));
        let pending = AuthCell {
            base: AuthBase::new(5000, &roles).unwrap(),
            proposal: Some(Proposal {
                effective_at_ms: 99_000,
                base: AuthBase::new(7000, &roles).unwrap(),
            }),
        };
        let bytes = pending.to_bytes().unwrap();
        assert_eq!(
            bytes,
            to_vec_with_depth(&pending, MAX_AUTH_CELL_WIRE_DEPTH).unwrap()
        );
        assert_eq!(AuthCell::from_slice(&bytes).unwrap(), pending);

        // The bound is exact: the deepest field sits at it, and one
        // level short does not reach.
        assert!(to_vec_with_depth(&pending, MAX_AUTH_CELL_WIRE_DEPTH - 1).is_err());
        assert!(from_slice_with_depth::<AuthCell>(&bytes, MAX_AUTH_CELL_WIRE_DEPTH - 1).is_err());
    }

    #[test]
    fn governing_flips_at_the_instant_and_not_before() {
        let cell = AuthCell {
            base: base(1, 1000),
            proposal: Some(Proposal {
                effective_at_ms: 500,
                base: base(2, 2000),
            }),
        };
        assert_eq!(cell.governing(0), &base(1, 1000));
        assert_eq!(cell.governing(499), &base(1, 1000));
        assert_eq!(cell.governing(500), &base(2, 2000));
        assert_eq!(cell.governing(u64::MAX), &base(2, 2000));
        assert_eq!(
            AuthCell::new(base(1, 1000)).governing(u64::MAX),
            &base(1, 1000)
        );
    }

    #[test]
    fn a_malformed_cell_is_refused() {
        assert!(AuthCell::from_slice(&[]).is_err());
        assert!(AuthCell::from_slice(&[1, 0, 0]).is_err());
        // Trailing bytes past a well-formed cell.
        let mut bytes = AuthCell::new(base(1, 0)).to_bytes().unwrap();
        bytes.extend_from_slice(&[0; 4]);
        assert!(AuthCell::from_slice(&bytes).is_err());
        // A cell truncated inside its own role set.
        let whole = AuthCell::new(base(1, 0)).to_bytes().unwrap();
        assert!(AuthCell::from_slice(&whole[..whole.len() - 1]).is_err());
        // Bare rule bytes are not a cell.
        let rule = StoredRule::Require(identity(1)).to_bytes().unwrap();
        assert!(AuthCell::from_slice(&rule).is_err());
    }

    /// The same wire form as [`RoleSet`], with no caps: the source of
    /// bytes a compliant encoder refuses to produce.
    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    struct WideSet {
        primary: WideRule,
        recovery: WideRule,
        confirmation: WideRule,
    }

    /// The role-set cap admits exactly the rules the rule vocabulary
    /// admits, at both boundaries — the struct costs one decoder level,
    /// no more.
    #[test]
    fn the_roleset_wire_depth_tracks_the_rule_caps() {
        let deepest = RoleSet::uniform(chain(MAX_RULE_DEPTH - 1));
        let bytes = deepest.to_bytes().unwrap();
        assert_eq!(RoleSet::from_slice(&bytes).unwrap(), deepest);

        // One level past the rule cap is refused at encode, and its
        // bytes — produced through the uncapped twin — at decode.
        assert!(RoleSet::uniform(chain(MAX_RULE_DEPTH)).to_bytes().is_err());
        let wide = WideSet {
            primary: wide_chain(MAX_RULE_DEPTH),
            recovery: WideRule::Require(identity(1)),
            confirmation: WideRule::Require(identity(1)),
        };
        assert!(RoleSet::from_slice(&to_vec(&wide).unwrap()).is_err());
    }

    /// A stored role set is judged at the rule vocabulary's own cap
    /// wherever it sits, because it sits in the cell as bytes: what
    /// decodes them is [`StoredRoles::decode`], at one cap, and the cell
    /// around them nests nothing.
    ///
    /// So an over-deep rule is refused in either position for the same
    /// reason rather than by an arithmetic relation between two caps —
    /// and a cell carrying one admits nobody rather than trapping.
    #[test]
    fn a_stored_rule_past_the_caps_is_refused_wherever_it_sits() {
        let deepest = RoleSet::uniform(chain(MAX_RULE_DEPTH - 1));
        let cell = AuthCell {
            base: AuthBase::new(1, &deepest).unwrap(),
            proposal: Some(Proposal {
                effective_at_ms: 7,
                base: AuthBase::new(1, &deepest).unwrap(),
            }),
        };
        let bytes = cell.to_bytes().unwrap();
        assert_eq!(AuthCell::from_slice(&bytes).unwrap(), cell);
        assert_eq!(cell.base.roles.decode().unwrap(), deepest);

        // One level past the cap is refused at encode, and the bytes the
        // uncapped twin produces are refused at decode.
        assert!(AuthBase::new(1, &RoleSet::uniform(chain(MAX_RULE_DEPTH))).is_err());
        let over = StoredRoles(
            to_vec(&WideSet {
                primary: wide_chain(MAX_RULE_DEPTH),
                recovery: WideRule::Require(identity(1)),
                confirmation: WideRule::Require(identity(1)),
            })
            .unwrap(),
        );
        assert!(over.decode().is_err());

        // In either position, the cell still decodes — the bytes are a
        // byte string here — and the verdict it answers is nobody.
        let target = principal(1);
        for cell in [
            AuthCell::new(AuthBase {
                recovery_delay_ms: 1,
                roles: over.clone(),
            }),
            AuthCell {
                base: AuthBase::new(1, &deepest).unwrap(),
                proposal: Some(Proposal {
                    effective_at_ms: 0,
                    base: AuthBase {
                        recovery_delay_ms: 1,
                        roles: over,
                    },
                }),
            },
        ] {
            let stored = cell.to_bytes().unwrap();
            assert!(AuthCell::from_slice(&stored).is_ok());
            assert!(!AuthCell::admits(
                &stored,
                target,
                AuthRole::Primary,
                &[identity(1)],
                u64::MAX,
            ));
        }
    }

    /// The verdict both readers share, whole: absent is the virtual
    /// rule for every role, stored is the named role's rule from the
    /// base the clock picks, and bytes that are not a cell admit
    /// nobody.
    #[test]
    fn the_shared_verdict_dispatches_on_presence_role_and_clock() {
        let target = principal(1);

        // Absent: the identity the target's address derives, whichever
        // role asks, whatever the clock says.
        assert!(AuthCell::admits(
            &[],
            target,
            AuthRole::Primary,
            &[Presented::Identity(target)],
            0
        ));
        assert!(AuthCell::admits(
            &[],
            target,
            AuthRole::Recovery,
            &[Presented::Identity(target)],
            u64::MAX
        ));
        assert!(!AuthCell::admits(
            &[],
            target,
            AuthRole::Primary,
            &[identity(2)],
            0
        ));

        // Stored, with a proposal pending: each role selects its own
        // rule, the target's own identity is no longer one of them, and
        // the verdict flips at the instant with nothing applying it.
        let cell = AuthCell {
            base: AuthBase {
                recovery_delay_ms: 1_000,
                roles: StoredRoles::try_from(&RoleSet {
                    primary: StoredRule::Require(identity(2)),
                    recovery: StoredRule::Require(identity(3)),
                    confirmation: StoredRule::Require(identity(4)),
                })
                .unwrap(),
            },
            proposal: Some(Proposal {
                effective_at_ms: 500,
                base: base(5, 1_000),
            }),
        }
        .to_bytes()
        .unwrap();
        let admits =
            |role, who: u8, clock| AuthCell::admits(&cell, target, role, &[identity(who)], clock);
        assert!(admits(AuthRole::Primary, 2, 499));
        assert!(!admits(AuthRole::Primary, 1, 499));
        assert!(admits(AuthRole::Recovery, 3, 499));
        assert!(!admits(AuthRole::Recovery, 2, 499));
        assert!(admits(AuthRole::Confirmation, 4, 499));
        assert!(admits(AuthRole::Primary, 5, 500));
        assert!(!admits(AuthRole::Primary, 2, 500));

        // Bytes no cell decodes from admit nobody.
        assert!(!AuthCell::admits(
            &[0xFF, 0xFF],
            target,
            AuthRole::Primary,
            &[Presented::Identity(target)],
            0
        ));
    }
}
