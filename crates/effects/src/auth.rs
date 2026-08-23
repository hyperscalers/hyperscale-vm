//! The stored-authority cell: a table of rules by role, a recovery
//! delay, and at most one timed proposal.
//!
//! One encoded record, read and written through this module by everyone
//! who touches it — the guest that stores it, the kernel's gate, and the
//! payer shard's binding verdict. There is no second implementation to
//! agree with.
//!
//! Nothing applies a matured proposal: every reader compares its
//! instant against the transaction clock through [`AuthCell::governing`]
//! and answers under whichever base that picks. The write-side fold —
//! promoting a matured proposal's base before rewriting the cell — is
//! compaction of what reads already answer, never a change of verdict.

use hyperscale_hbor::{
    DecodeError, EncodeError, Hbor, HborShape, from_slice_with_depth, to_vec_with_depth,
};
use hyperscale_vm_types::{Address, CallTarget};

use crate::presented::Presented;
use crate::rule::StoredRule;

/// Which stored rule a role-gated method is judged against: a banded
/// number, like [`SlotId`](crate::SlotId).
///
/// The account's three roles hold the reserved numbers; a package's own
/// roles count up from [`PACKAGE_ROLE_BASE`]. The kernel bounds a number
/// without resolving it — a wallet renders a package role's name from
/// the metadata table beside the ones for events and errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor, HborShape)]
#[hbor(transparent)]
pub struct RoleId(pub u16);

/// Governs `authorize`, and so everything a principal does — including
/// paying, at the payer shard's binding verdict.
pub const PRIMARY: RoleId = RoleId(0);
/// May propose a replacement for the whole base, and withdraw it.
pub const RECOVERY: RoleId = RoleId(1);
/// May enact a proposal before it matures.
pub const CONFIRMATION: RoleId = RoleId(2);

/// Where a package's own role numbers start.
///
/// Above the reserved roles with room left over, so a role added to the
/// reserved set later is not a renumbering of every package that ever
/// stored a table.
pub const PACKAGE_ROLE_BASE: u16 = 16;

const _: () = assert!(PACKAGE_ROLE_BASE > CONFIRMATION.0);

/// The roles one package may declare.
///
/// The same kind of bound `MAX_EVENT_TYPES` and `MAX_ERROR_CODES` are:
/// a gate carries the band offset and a metadata table renders it, so
/// what publish holds a record to is the ceiling rather than the table
/// behind it. Well below what the band can address, because an entry
/// past a ceiling is one no gate reaches.
pub const MAX_PACKAGE_ROLES: usize = 1024;

const _: () = assert!(MAX_PACKAGE_ROLES < (u16::MAX - PACKAGE_ROLE_BASE) as usize);

/// The `n`th role of a package's own band.
#[must_use]
pub const fn package_role(n: u16) -> RoleId {
    RoleId(PACKAGE_ROLE_BASE + n)
}

/// One stored rule as it is stored and carried: the canonical bytes, not
/// the tree.
///
/// The one thing in the table that stays opaque, and for a reason the
/// runtime fixes rather than a preference. A [`StoredRule`] is
/// recursive, so its decoder is; the deterministic profile requires an
/// acyclic call graph — the runtime's frame-bound check — because a
/// static stack bound is what makes stack exhaustion unreachable in both
/// engines rather than reachable at different depths in each. A guest
/// therefore cannot carry a rule's codec, and a package that stores
/// authority moves these bytes without reading them. Whoever judges a
/// rule decodes them, under the vocabulary's own caps, where the judging
/// happens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent)]
pub struct RoleBytes(pub Vec<u8>);

impl RoleBytes {
    /// The canonical bytes, which is all a body may do with one: what
    /// they mean was settled where they were decoded.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The rule these bytes encode.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on bytes that are not a rule within the
    /// vocabulary's caps.
    pub fn decode(&self) -> Result<StoredRule, DecodeError> {
        StoredRule::from_slice(&self.0)
    }
}

impl TryFrom<&StoredRule> for RoleBytes {
    type Error = EncodeError;

    fn try_from(rule: &StoredRule) -> Result<Self, EncodeError> {
        rule.to_bytes().map(Self)
    }
}

/// The decoder cap that admits exactly the tables this module writes:
/// the table's entries, one entry's pair, and the byte string holding
/// one rule. Pinned by test at both boundaries.
///
/// A rule's own depth is not in here — an entry is a byte string at this
/// layer, decoded at the rule vocabulary's cap wherever one is judged.
/// Nor is an entry count: an entry costs bytes, so the count is bounded
/// by what the input paid for, and the roles that mean anything are the
/// ones some method names.
pub const MAX_ROLE_TABLE_WIRE_DEPTH: usize = 3;

/// The stored role table: rules by role number, each as the bytes it
/// was handed.
///
/// The skeleton is legible — a guest decodes the entries, moves or
/// removes one, and re-encodes them — while each rule's bytes stay
/// opaque for the reason [`RoleBytes`] states. **An absent entry
/// denies**: a miss is the one expressible "deny", since the rule
/// vocabulary refuses a degenerate threshold, and it is what makes
/// stripping a role a removal rather than a rule nobody can write.
///
/// A sorted list rather than a `BTreeMap`, because this type crosses
/// into guests and the deterministic profile requires an acyclic call
/// graph: a tree's clone is recursive where a list's is a loop. The map
/// semantics stand — ascending, duplicate-free role numbers — held by
/// the decode-time validation, so an unsorted payload is refused as a
/// second byte string for a value that already has one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent, validate = ascending)]
pub struct RoleTable(Vec<(RoleId, RoleBytes)>);

/// The table's canonical-order rule: role numbers strictly ascending.
fn ascending(table: &RoleTable) -> Result<(), &'static str> {
    table
        .0
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
        .then_some(())
        .ok_or("role numbers must be ascending and distinct")
}

impl RoleTable {
    /// An empty table, which admits nobody under any role.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// One rule as all three reserved roles.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] on a rule past the vocabulary caps.
    pub fn uniform(rule: &StoredRule) -> Result<Self, EncodeError> {
        let bytes = RoleBytes::try_from(rule)?;
        Ok(Self(vec![
            (PRIMARY, bytes.clone()),
            (RECOVERY, bytes.clone()),
            (CONFIRMATION, bytes),
        ]))
    }

    fn position(&self, role: RoleId) -> Result<usize, usize> {
        self.0.binary_search_by_key(&role, |entry| entry.0)
    }

    /// The stored bytes of the rule `role` selects, if the table holds
    /// one.
    #[must_use]
    pub fn rule(&self, role: RoleId) -> Option<&RoleBytes> {
        self.position(role).ok().map(|at| &self.0[at].1)
    }

    /// Store `bytes` under `role`, replacing what was there.
    pub fn set(&mut self, role: RoleId, bytes: RoleBytes) {
        match self.position(role) {
            Ok(at) => self.0[at].1 = bytes,
            Err(at) => self.0.insert(at, (role, bytes)),
        }
    }

    /// Remove `role`'s entry, leaving every other entry's bytes exactly
    /// as they were. An absent entry denies, so this is how a role's
    /// power is stripped.
    pub fn remove(&mut self, role: RoleId) -> Option<RoleBytes> {
        self.position(role).ok().map(|at| self.0.remove(at).1)
    }

    /// Whether every entry decodes as a rule within the vocabulary's
    /// caps — the write path's refusal, so bytes behind a stored table
    /// are a rule or the table was never admitted.
    #[must_use]
    pub fn decodes(&self) -> bool {
        self.0.iter().all(|(_, bytes)| bytes.decode().is_ok())
    }

    /// The table's canonical wire bytes, under the same cap the decoder
    /// enforces.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] is unreachable at this cap; the signature is the
    /// codec's.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, MAX_ROLE_TABLE_WIRE_DEPTH)
    }

    /// One whole table from its canonical wire bytes.
    ///
    /// The skeleton alone: whether every entry decodes as a rule is
    /// [`decodes`](Self::decodes), asked where a table is admitted
    /// rather than wherever one is moved.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on trailing bytes, unsorted or duplicate roles,
    /// or a non-canonical form.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, MAX_ROLE_TABLE_WIRE_DEPTH)
    }
}

impl FromIterator<(RoleId, RoleBytes)> for RoleTable {
    fn from_iter<I: IntoIterator<Item = (RoleId, RoleBytes)>>(entries: I) -> Self {
        let mut table = Self::new();
        for (role, bytes) in entries {
            table.set(role, bytes);
        }
        table
    }
}

/// The decoder nesting bound for a whole cell.
///
/// Seven levels to the deepest field, and constant: the cell's own
/// body, the `Option` around a proposal, the proposal's body, the
/// base's body inside it, the table's entries, one entry's pair, and
/// the byte string holding one rule. What nests unboundedly is a rule, and no rule is in here — an
/// entry is opaque bytes, decoded at their own cap wherever one is
/// judged. Pinned by test at both boundaries.
pub const MAX_AUTH_CELL_WIRE_DEPTH: usize = 7;

/// The cell's persistent half: the delay a proposal must wait, and the
/// roles that govern while none has matured.
#[derive(Clone, Debug, PartialEq, Eq, Hbor, HborShape)]
pub struct AuthBase {
    /// How long a proposal waits before it governs, in weighted-time
    /// milliseconds.
    pub recovery_delay_ms: u64,
    /// The stored rules, each as the bytes it was handed.
    pub roles: RoleTable,
}

impl AuthBase {
    /// The base holding `roles`.
    #[must_use]
    pub const fn new(recovery_delay_ms: u64, roles: RoleTable) -> Self {
        Self {
            recovery_delay_ms,
            roles,
        }
    }
}

/// A pending replacement for the whole base, governing from its instant.
#[derive(Clone, Debug, PartialEq, Eq, Hbor, HborShape)]
pub struct Proposal {
    /// The weighted-time instant the proposal's base starts governing,
    /// computed where the proposal is written: the transaction clock
    /// plus the recovery delay stored beside the roles it replaces.
    pub effective_at_ms: u64,
    /// The replacement base, whole: roles and delay together.
    pub base: AuthBase,
}

/// The decoded stored-authority cell.
#[derive(Clone, Debug, PartialEq, Eq, Hbor, HborShape)]
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
    /// bytes, or a malformed table.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, MAX_AUTH_CELL_WIRE_DEPTH)
    }

    /// The cell's canonical wire bytes, under the same cap the decoder
    /// enforces.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] is unreachable at this cap; the signature is the
    /// codec's.
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
    /// governed by whatever governs `authorize`. An empty `stored` is a
    /// cell nobody wrote: the virtual rule, the identity the target's
    /// address derives, whichever role asks — satisfiable only where a
    /// key derives the address, so an unwritten package table denies. A
    /// stored table whose entry for `role` is absent denies: a map miss
    /// is the one expressible "deny". Stored bytes that do not decode
    /// admit nobody — the write path refuses such bytes, so these are
    /// not a rule, and a cell that cannot be read fails closed.
    #[must_use]
    pub fn admits(
        stored: &[u8],
        target: Address,
        role: RoleId,
        evidence: &[Presented],
        clock_ms: u64,
    ) -> bool {
        if stored.is_empty() {
            // A target is callable by construction; anything else has no
            // virtual rule to satisfy and fails closed.
            return CallTarget::try_from(target)
                .is_ok_and(|target| evidence.contains(&Presented::Identity(target)));
        }
        Self::from_slice(stored).is_ok_and(|cell| {
            cell.governing(clock_ms)
                .roles
                .rule(role)
                .is_some_and(|bytes| bytes.decode().is_ok_and(|rule| rule.satisfied_by(evidence)))
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice_with_depth, to_vec, to_vec_with_depth};

    use super::{
        AuthBase, AuthCell, CONFIRMATION, MAX_AUTH_CELL_WIRE_DEPTH, MAX_ROLE_TABLE_WIRE_DEPTH,
        PRIMARY, Proposal, RECOVERY, RoleBytes, RoleId, RoleTable, package_role,
    };
    use crate::rule::testing::{chain, identity, principal, wide_chain};
    use crate::rule::{MAX_RULE_DEPTH, StoredRule};

    fn table(byte: u8) -> RoleTable {
        RoleTable::uniform(&StoredRule::Require(identity(byte))).unwrap()
    }

    fn base(byte: u8, delay: u64) -> AuthBase {
        AuthBase::new(delay, table(byte))
    }

    #[test]
    fn a_role_selects_its_rule_and_an_absent_entry_holds_none() {
        let rule = |byte| RoleBytes::try_from(&StoredRule::Require(identity(byte))).unwrap();
        let roles = RoleTable::from_iter([
            (PRIMARY, rule(1)),
            (RECOVERY, rule(2)),
            (CONFIRMATION, rule(3)),
        ]);
        assert_eq!(roles.rule(PRIMARY), Some(&rule(1)));
        assert_eq!(roles.rule(RECOVERY), Some(&rule(2)));
        assert_eq!(roles.rule(CONFIRMATION), Some(&rule(3)));
        assert_eq!(roles.rule(package_role(0)), None);
    }

    /// Removing one entry is a map operation: no rule is decoded, and
    /// every other entry's bytes are exactly what they were — which is
    /// what lets a guest strip a role while the rules stay opaque to it.
    #[test]
    fn removal_touches_no_other_entry_and_decodes_no_rule() {
        // Bytes that are not a rule at all: a decode anywhere would
        // refuse, so the operations below provably never look.
        let opaque = |byte| RoleBytes(vec![byte; 3]);
        let mut roles = RoleTable::from_iter([
            (PRIMARY, opaque(1)),
            (RECOVERY, opaque(2)),
            (package_role(4), opaque(3)),
        ]);
        assert!(!roles.decodes());
        assert_eq!(roles.remove(PRIMARY), Some(opaque(1)));
        assert_eq!(roles.rule(PRIMARY), None);
        let bytes = roles.to_bytes().unwrap();
        let reread = RoleTable::from_slice(&bytes).unwrap();
        assert_eq!(reread.rule(RECOVERY), Some(&opaque(2)));
        assert_eq!(reread.rule(package_role(4)), Some(&opaque(3)));
    }

    /// A table with package-band roles round-trips under the caps, with
    /// every rule held to the rule vocabulary's own bounds where it is
    /// judged.
    #[test]
    fn a_package_band_table_round_trips_under_the_caps() {
        let deepest = RoleBytes::try_from(&chain(MAX_RULE_DEPTH - 1)).unwrap();
        let mut roles = table(1);
        roles.set(package_role(0), deepest.clone());
        roles.set(package_role(7), deepest);
        let bytes = roles.to_bytes().unwrap();
        let reread = RoleTable::from_slice(&bytes).unwrap();
        assert_eq!(reread, roles);
        assert!(reread.decodes());

        // One level past the rule cap is refused where the rule encodes,
        // and bytes produced through the uncapped twin are not a rule.
        assert!(RoleBytes::try_from(&chain(MAX_RULE_DEPTH)).is_err());
        let over = RoleBytes(to_vec(&wide_chain(MAX_RULE_DEPTH)).unwrap());
        assert!(over.decode().is_err());
        let mut wide = table(1);
        wide.set(package_role(0), over);
        assert!(!wide.decodes());
        // The skeleton still round-trips: what refuses such an entry is
        // the write path's `decodes`, not the map codec.
        let bytes = wide.to_bytes().unwrap();
        assert_eq!(RoleTable::from_slice(&bytes).unwrap(), wide);
    }

    /// The table's own bound is exact: the deepest field sits at it, and
    /// one level short does not reach.
    #[test]
    fn the_table_wire_depth_is_exact() {
        let roles = table(1);
        let bytes = roles.to_bytes().unwrap();
        assert_eq!(RoleTable::from_slice(&bytes).unwrap(), roles);
        assert!(to_vec_with_depth(&roles, MAX_ROLE_TABLE_WIRE_DEPTH - 1).is_err());
        assert!(from_slice_with_depth::<RoleTable>(&bytes, MAX_ROLE_TABLE_WIRE_DEPTH - 1).is_err());
    }

    #[test]
    fn unsorted_or_duplicate_roles_are_refused() {
        let entry = |role: u16, byte: u8| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&to_vec(&RoleId(role)).unwrap());
            bytes.extend_from_slice(&to_vec(&RoleBytes(vec![byte])).unwrap());
            bytes
        };
        let framed = |entries: &[Vec<u8>]| {
            let mut bytes = vec![u8::try_from(entries.len()).unwrap()];
            bytes.extend(entries.concat());
            bytes
        };
        let sorted = framed(&[entry(0, 1), entry(1, 2)]);
        assert!(RoleTable::from_slice(&sorted).is_ok());
        let unsorted = framed(&[entry(1, 2), entry(0, 1)]);
        assert!(RoleTable::from_slice(&unsorted).is_err());
        let duplicate = framed(&[entry(0, 1), entry(0, 2)]);
        assert!(RoleTable::from_slice(&duplicate).is_err());
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
        let pending = AuthCell {
            base: base(7, 5000),
            proposal: Some(Proposal {
                effective_at_ms: 99_000,
                base: base(7, 7000),
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
        // A cell truncated inside its own table.
        let whole = AuthCell::new(base(1, 0)).to_bytes().unwrap();
        assert!(AuthCell::from_slice(&whole[..whole.len() - 1]).is_err());
        // Bare rule bytes are not a cell.
        let rule = StoredRule::Require(identity(1)).to_bytes().unwrap();
        assert!(AuthCell::from_slice(&rule).is_err());
    }

    /// A stored rule is judged at the rule vocabulary's own cap wherever
    /// it sits, because it sits in the table as bytes: what decodes them
    /// is [`RoleBytes::decode`], at one cap, and the cell around them
    /// nests nothing.
    ///
    /// So an over-deep rule is refused in either position for the same
    /// reason rather than by an arithmetic relation between two caps —
    /// and a cell carrying one admits nobody rather than trapping.
    #[test]
    fn a_stored_rule_past_the_caps_is_refused_wherever_it_sits() {
        let deepest = RoleTable::uniform(&chain(MAX_RULE_DEPTH - 1)).unwrap();
        let cell = AuthCell {
            base: AuthBase::new(1, deepest.clone()),
            proposal: Some(Proposal {
                effective_at_ms: 7,
                base: AuthBase::new(1, deepest.clone()),
            }),
        };
        let bytes = cell.to_bytes().unwrap();
        assert_eq!(AuthCell::from_slice(&bytes).unwrap(), cell);
        assert!(cell.base.roles.decodes());

        // One level past the cap is refused at encode, and the bytes the
        // uncapped twin produces are refused where a rule is decoded.
        assert!(RoleTable::uniform(&chain(MAX_RULE_DEPTH)).is_err());
        let over = RoleBytes(to_vec(&wide_chain(MAX_RULE_DEPTH)).unwrap());
        let mut wide = deepest.clone();
        wide.set(PRIMARY, over);

        // In either position, the cell still decodes — the bytes are a
        // byte string here — and the verdict it answers is nobody.
        let target = principal(1);
        for cell in [
            AuthCell::new(AuthBase::new(1, wide.clone())),
            AuthCell {
                base: AuthBase::new(1, deepest),
                proposal: Some(Proposal {
                    effective_at_ms: 0,
                    base: AuthBase::new(1, wide.clone()),
                }),
            },
        ] {
            let stored = cell.to_bytes().unwrap();
            assert!(AuthCell::from_slice(&stored).is_ok());
            assert!(!AuthCell::admits(
                &stored,
                target,
                PRIMARY,
                &[identity(1)],
                u64::MAX,
            ));
        }
    }

    /// The verdict both readers share, whole: absent is the virtual
    /// rule for every role, stored is the named role's rule from the
    /// base the clock picks, an absent entry denies, and bytes that are
    /// not a cell admit nobody.
    #[test]
    fn the_shared_verdict_dispatches_on_presence_role_and_clock() {
        let target = principal(1);

        // Absent: the identity the target's address derives, whichever
        // role asks, whatever the clock says.
        assert!(AuthCell::admits(&[], target, PRIMARY, &[identity(1)], 0));
        assert!(AuthCell::admits(
            &[],
            target,
            RECOVERY,
            &[identity(1)],
            u64::MAX
        ));
        assert!(!AuthCell::admits(&[], target, PRIMARY, &[identity(2)], 0));

        // Stored, with a proposal pending: each role selects its own
        // rule, the target's own identity is no longer one of them, and
        // the verdict flips at the instant with nothing applying it.
        let rule = |byte| RoleBytes::try_from(&StoredRule::Require(identity(byte))).unwrap();
        let cell = AuthCell {
            base: AuthBase {
                recovery_delay_ms: 1_000,
                roles: RoleTable::from_iter([
                    (PRIMARY, rule(2)),
                    (RECOVERY, rule(3)),
                    (CONFIRMATION, rule(4)),
                ]),
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
        assert!(admits(PRIMARY, 2, 499));
        assert!(!admits(PRIMARY, 1, 499));
        assert!(admits(RECOVERY, 3, 499));
        assert!(!admits(RECOVERY, 2, 499));
        assert!(admits(CONFIRMATION, 4, 499));
        assert!(admits(PRIMARY, 5, 500));
        assert!(!admits(PRIMARY, 2, 500));

        // A role the stored table has no entry for denies, whoever asks
        // — a map miss is the one expressible "deny".
        let stripped = AuthCell::new(AuthBase {
            recovery_delay_ms: 1_000,
            roles: RoleTable::from_iter([(RECOVERY, rule(3))]),
        })
        .to_bytes()
        .unwrap();
        assert!(!AuthCell::admits(
            &stripped,
            target,
            PRIMARY,
            &[identity(1), identity(2), identity(3)],
            0
        ));
        assert!(AuthCell::admits(
            &stripped,
            target,
            RECOVERY,
            &[identity(3)],
            0
        ));

        // Bytes no cell decodes from admit nobody.
        assert!(!AuthCell::admits(
            &[0xFF, 0xFF],
            target,
            PRIMARY,
            &[identity(1)],
            0
        ));
    }
}
