//! The account's stored-authority cell: three rules, a recovery delay,
//! and at most one timed proposal.
//!
//! The layout is a frame rather than one encoded record, because the
//! account guest splices it with integer reads at fixed offsets and
//! carries no codec: a u32 length, u64 instants, and HBOR blobs the
//! guest never reads. This module owns the read side — the kernel's
//! gate and the payer shard's binding verdict decode through it — and
//! the guest owns the write-side splices; the corpus pins their
//! agreement on exact bytes.
//!
//! Frame: `[u32 LE base_len][base]`, optionally followed by
//! `[u64 LE effective_at_ms][base']` running to the cell's end, where
//! `base = [u64 LE recovery_delay_ms][RoleSet]`. The length is u32
//! because a cap-maximal role set exceeds u16.
//!
//! Nothing applies a matured proposal: every reader compares its
//! instant against the transaction clock through [`AuthCell::governing`]
//! and answers under whichever base that picks. The write-side fold —
//! promoting a matured proposal's base before rewriting the cell — is
//! compaction of what reads already answer, never a change of verdict.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, from_slice_with_depth, to_vec_with_depth};

use crate::rule::{MAX_RULE_WIRE_DEPTH, Rule};

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
    pub primary: Rule,
    /// Governs `propose`.
    pub recovery: Rule,
    /// Governs `confirm`.
    pub confirmation: Rule,
}

impl RoleSet {
    /// One rule as all three roles.
    #[must_use]
    pub fn uniform(rule: Rule) -> Self {
        Self {
            primary: rule.clone(),
            recovery: rule.clone(),
            confirmation: rule,
        }
    }

    /// The rule `role` selects.
    #[must_use]
    pub const fn rule(&self, role: AuthRole) -> &Rule {
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

/// The cell's persistent half: the delay a proposal must wait, and the
/// roles that govern while none has matured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthBase {
    /// How long a proposal waits before it governs, in weighted-time
    /// milliseconds. Read by the guest as the base's first eight bytes,
    /// which is why it sits outside the role set's encoding.
    pub recovery_delay_ms: u64,
    /// The three stored rules.
    pub roles: RoleSet,
}

impl AuthBase {
    fn parse(bytes: &[u8]) -> Result<Self, AuthCellError> {
        let (delay, roles) = bytes
            .split_first_chunk::<8>()
            .ok_or(AuthCellError::Truncated)?;
        Ok(Self {
            recovery_delay_ms: u64::from_le_bytes(*delay),
            roles: RoleSet::from_slice(roles)?,
        })
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(&self.recovery_delay_ms.to_le_bytes());
        out.extend_from_slice(&self.roles.to_bytes()?);
        Ok(())
    }
}

/// A pending replacement for the whole base, governing from its instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The weighted-time instant the proposal's base starts governing,
    /// computed where the proposal is written: the transaction clock
    /// plus the recovery delay stored beside the roles it replaces.
    pub effective_at_ms: u64,
    /// The replacement base, whole: roles and delay together.
    pub base: AuthBase,
}

/// The decoded stored-authority cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCell {
    /// The persistent half.
    pub base: AuthBase,
    /// At most one pending replacement.
    pub proposal: Option<Proposal>,
}

/// Why bytes are not a stored-authority cell. Every reader fails closed
/// on one: a cell that cannot be read admits nobody.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthCellError {
    /// The frame ends before a length or instant it promises.
    #[error("the frame ends before a field it promises")]
    Truncated,
    /// A role set that does not decode as the vocabulary: past a cap,
    /// non-canonical, or holding a degenerate threshold.
    #[error(transparent)]
    Roles(#[from] DecodeError),
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
    /// [`AuthCellError`] on a truncated frame, trailing bytes, or a
    /// role set that does not decode as the vocabulary.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AuthCellError> {
        let (len, rest) = bytes
            .split_first_chunk::<4>()
            .ok_or(AuthCellError::Truncated)?;
        let base_len =
            usize::try_from(u32::from_le_bytes(*len)).map_err(|_| AuthCellError::Truncated)?;
        if rest.len() < base_len {
            return Err(AuthCellError::Truncated);
        }
        let (base, tail) = rest.split_at(base_len);
        let base = AuthBase::parse(base)?;
        let proposal = if tail.is_empty() {
            None
        } else {
            let (instant, proposed) = tail
                .split_first_chunk::<8>()
                .ok_or(AuthCellError::Truncated)?;
            Some(Proposal {
                effective_at_ms: u64::from_le_bytes(*instant),
                base: AuthBase::parse(proposed)?,
            })
        };
        Ok(Self { base, proposal })
    }

    /// The cell's frame bytes — what the guest's splices produce, byte
    /// for byte, which the corpus pins.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past the vocabulary caps.
    ///
    /// # Panics
    ///
    /// On a base past `u32::MAX` bytes — unreachable for any role set
    /// the caps admit.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut base = Vec::new();
        self.base.encode_into(&mut base)?;
        let mut out = Vec::with_capacity(base.len() + 4);
        out.extend_from_slice(
            &u32::try_from(base.len())
                .expect("a role set within the caps encodes under u32::MAX bytes")
                .to_le_bytes(),
        );
        out.append(&mut base);
        if let Some(proposal) = &self.proposal {
            out.extend_from_slice(&proposal.effective_at_ms.to_le_bytes());
            proposal.base.encode_into(&mut out)?;
        }
        Ok(out)
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
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Hbor, to_vec};

    use super::{AuthBase, AuthCell, AuthCellError, AuthRole, Proposal, RoleSet};
    use crate::rule::{MAX_RULE_DEPTH, Rule};
    use crate::types::{Address, AddressClass};

    fn identity(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Principal)
    }

    fn base(byte: u8, delay: u64) -> AuthBase {
        AuthBase {
            recovery_delay_ms: delay,
            roles: RoleSet::uniform(Rule::Require(identity(byte))),
        }
    }

    #[test]
    fn a_role_selects_its_rule() {
        let roles = RoleSet {
            primary: Rule::Require(identity(1)),
            recovery: Rule::Require(identity(2)),
            confirmation: Rule::Require(identity(3)),
        };
        assert_eq!(roles.rule(AuthRole::Primary), &Rule::Require(identity(1)));
        assert_eq!(roles.rule(AuthRole::Recovery), &Rule::Require(identity(2)));
        assert_eq!(
            roles.rule(AuthRole::Confirmation),
            &Rule::Require(identity(3))
        );
    }

    #[test]
    fn the_frame_round_trips_with_and_without_a_proposal() {
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

    /// The guest writes the frame by concatenation — a u32 length, two
    /// u64 instants, opaque role-set bytes — so the codec here must
    /// agree with exactly that layout, byte for byte.
    #[test]
    fn the_frame_is_the_guests_concatenation() {
        let roles = RoleSet::uniform(Rule::Require(identity(7)))
            .to_bytes()
            .unwrap();
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&u32::try_from(8 + roles.len()).unwrap().to_le_bytes());
        spliced.extend_from_slice(&5000u64.to_le_bytes());
        spliced.extend_from_slice(&roles);
        assert_eq!(
            AuthCell::from_slice(&spliced).unwrap(),
            AuthCell::new(AuthBase {
                recovery_delay_ms: 5000,
                roles: RoleSet::uniform(Rule::Require(identity(7))),
            })
        );

        let mut with_proposal = spliced.clone();
        with_proposal.extend_from_slice(&99_000u64.to_le_bytes());
        with_proposal.extend_from_slice(&7000u64.to_le_bytes());
        with_proposal.extend_from_slice(&roles);
        let decoded = AuthCell::from_slice(&with_proposal).unwrap();
        assert_eq!(
            decoded.proposal,
            Some(Proposal {
                effective_at_ms: 99_000,
                base: AuthBase {
                    recovery_delay_ms: 7000,
                    roles: RoleSet::uniform(Rule::Require(identity(7))),
                },
            })
        );
        assert_eq!(with_proposal, decoded.to_bytes().unwrap());
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
    fn a_malformed_frame_is_refused() {
        assert!(AuthCell::from_slice(&[]).is_err());
        assert!(AuthCell::from_slice(&[1, 0, 0]).is_err());
        // A length past the bytes on hand.
        assert!(matches!(
            AuthCell::from_slice(&[0xFF, 0, 0, 0, 1, 2, 3]),
            Err(AuthCellError::Truncated)
        ));
        // A base too short for its own delay.
        assert!(AuthCell::from_slice(&[4, 0, 0, 0, 1, 2, 3, 4]).is_err());
        // A well-formed base with a truncated proposal instant.
        let mut bytes = AuthCell::new(base(1, 0)).to_bytes().unwrap();
        bytes.extend_from_slice(&[0; 4]);
        assert!(matches!(
            AuthCell::from_slice(&bytes),
            Err(AuthCellError::Truncated)
        ));
        // Bare rule bytes are not a frame.
        let rule = Rule::Require(identity(1)).to_bytes().unwrap();
        assert!(AuthCell::from_slice(&rule).is_err());
    }

    /// The same wire form as [`RoleSet`], with no caps: the source of
    /// bytes a compliant encoder refuses to produce.
    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    enum WideRule {
        Require(Address),
        CountOf { count: u8, rules: Vec<Self> },
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hbor)]
    struct WideSet {
        primary: WideRule,
        recovery: WideRule,
        confirmation: WideRule,
    }

    fn wide_chain(levels: usize) -> WideRule {
        let mut rule = WideRule::Require(identity(1));
        for _ in 0..levels {
            rule = WideRule::CountOf {
                count: 1,
                rules: vec![rule],
            };
        }
        rule
    }

    /// The role-set cap admits exactly the rules the rule vocabulary
    /// admits, at both boundaries — the struct costs one decoder level,
    /// no more.
    #[test]
    fn the_roleset_wire_depth_tracks_the_rule_caps() {
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
}
