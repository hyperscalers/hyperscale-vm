//! The bytes a stored rule travels as, and the record an account's
//! governing cell holds.
//!
//! A rule is one thing, opaque to whoever carries it and decoded only
//! where the rule is judged. What a package does with a rule it stores —
//! how many it keeps, under what names, and what it takes to replace one
//! — is that package's own business, held in that package's own cells.
//! The one cell the kernel itself reads is the governing cell, and what
//! it holds is stated here so the package that writes it and the two
//! judges that read it agree.

use hyperscale_hbor::{
    Bytes, DecodeError, EncodeError, Hbor, HborBound, HborShape, from_slice, from_slice_with_depth,
    to_vec, to_vec_with_depth,
};
use hyperscale_vm_types::Address;

use crate::claim::Claim;
use crate::rule::{ANYBODY_BYTES, StoredRule};
use crate::types::MAX_VALUE_BYTES;

/// A stored rule as the bytes it travels as.
///
/// Opaque for a reason the runtime fixes rather than a preference. A
/// [`StoredRule`] is recursive, so its decoder is; the deterministic
/// profile requires an acyclic call graph — the runtime's frame-bound
/// check — because a static stack bound is what makes stack exhaustion
/// unreachable in both engines rather than reachable at different depths
/// in each. A guest therefore cannot carry a rule's codec, and a package
/// that stores authority moves these bytes without reading them. Whoever
/// judges a rule decodes them, under the vocabulary's own caps, where
/// the judging happens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent)]
pub struct RuleBytes(pub Bytes<MAX_VALUE_BYTES>);

impl RuleBytes {
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

    /// These bytes as the cell holding them reads.
    ///
    /// The other half of [`rule_in_cell`](Self::rule_in_cell), so a
    /// consumer seeding a cell writes exactly what a package would.
    ///
    /// # Panics
    ///
    /// Only on an encoder failure no byte string can reach.
    #[must_use]
    pub fn in_cell(&self) -> Vec<u8> {
        to_vec(self).expect("a byte string encodes")
    }

    /// The rule a cell holding these bytes stores.
    ///
    /// A cell holds the record, and the record holds the rule — two
    /// framings, read here in one place so the package that writes a
    /// cell and the kernel that judges it cannot disagree about which
    /// one they are looking at. An unwritten cell reads as no bytes at
    /// all, which is no record and so no rule.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on bytes that are not a stored rule's record, or
    /// whose rule is past the vocabulary's caps.
    pub fn rule_in_cell(cell: &[u8]) -> Result<StoredRule, DecodeError> {
        from_slice::<Self>(cell)?.decode()
    }
}

/// A rule every leaf of which is a claim on a principal address.
///
/// The one shape an `auth` cell can usefully hold, and a parameter
/// declaring it is where that is settled: the cell is judged against the
/// keys attesting an intent, so a leaf naming a component or a resource
/// is one no attesting set can meet and a holding is one the judge
/// cannot read — either leaves an account nobody opens. Admission
/// decodes the bytes and refuses them, on the terms every other
/// parameter kind is held to, before the composition is signed.
///
/// Carried as the same bytes [`RuleBytes`] is, so a body that stores
/// what it was handed converts nothing here either.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent)]
pub struct PrincipalRule(pub Bytes<MAX_VALUE_BYTES>);

impl PrincipalRule {
    /// The bytes a cell holds, which is what a body does with one.
    #[must_use]
    pub fn into_bytes(self) -> RuleBytes {
        RuleBytes(self.0)
    }

    /// The canonical bytes, for a caller that only reads them.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&StoredRule> for PrincipalRule {
    type Error = EncodeError;

    fn try_from(rule: &StoredRule) -> Result<Self, EncodeError> {
        RuleBytes::try_from(rule).map(|bytes| Self(bytes.0))
    }
}

/// What an account's governing cell holds: the everyday rule, and the
/// second factor beside it.
///
/// Both are rules over principal claims, judged against the keys
/// attesting an intent, and an intent acts as the account only when
/// both admit its attesting set. One record rather than two cells
/// because the sign-in asks one question, so the policy is one value:
/// the fields say what the account requires without the judge having
/// to, a third factor would be a field rather than a slot and another
/// provisioned read, and every intent on every account provisions one
/// leaf to carry the three bytes `always()` encodes to.
///
/// The two are separate rather than folded into one conjunction because
/// their lifecycles differ: a recovery replaces the primary and may
/// leave the confirmation standing, so what colluding guardians get is
/// a new primary and not the account.
#[derive(Clone, Debug, PartialEq, Eq, Hbor, HborShape)]
pub struct Authority {
    /// The everyday rule: one key, or a threshold over several.
    pub primary: RuleBytes,
    /// The second factor, required beside the primary at every sign-in.
    /// The rule anyone satisfies where the account keeps none.
    pub confirmation: RuleBytes,
}

/// The decoder cap for the governing cell: the levels the record's own
/// shape nests.
///
/// A cap that admits exactly this record's values, so one that grows a
/// nested field moves it rather than failing against a figure written
/// beside it. The record crosses one boundary — the account writes the
/// cell its shard and the fee reservation later decode — and the three
/// agree by reading the shape.
const CELL_DEPTH: usize = <Authority as HborBound>::MAX_DEPTH;

impl Authority {
    /// The policy an account has before it names a second factor: the
    /// primary alone, and a confirmation anyone satisfies.
    #[must_use]
    pub fn primary_only(primary: RuleBytes) -> Self {
        Self {
            primary,
            confirmation: RuleBytes(Bytes::from_array(ANYBODY_BYTES)),
        }
    }

    /// This record as the cell holding it reads.
    ///
    /// The other half of [`from_cell`](Self::from_cell), so a consumer
    /// seeding a governing cell writes exactly what the account would.
    ///
    /// # Panics
    ///
    /// Only on an encoder failure no pair of byte strings can reach.
    #[must_use]
    pub fn in_cell(&self) -> Vec<u8> {
        to_vec_with_depth(self, CELL_DEPTH).expect("a pair of byte strings encodes")
    }

    /// The record a governing cell holds.
    ///
    /// Read in one place so the package that writes the cell and the
    /// kernel that judges it cannot disagree about its shape. An
    /// unwritten cell reads as no bytes at all, which is no record.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on bytes that are not this record.
    pub fn from_cell(cell: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(cell, CELL_DEPTH)
    }
}

/// Whether the rule stored in `owner`'s `auth` cell admits `keys`.
///
/// The one judgment made against keys rather than against the claims a
/// call presented, and two judges ask it: the fee reservation, before
/// the transaction is included at all, and the sign-in condition its
/// account's shard answers at materialization. They ask different
/// questions of the same cell, so they must not be able to read it
/// differently — which is why this is the whole of both rather than a
/// rule each states for itself.
///
/// An unwritten cell is governed by the key its address derives — the
/// rule naming that one principal, judged as a stored one would be, so
/// an attesting set answers it by holding the principal, whoever else
/// signed beside it. A written cell holds an [`Authority`], and the set
/// must answer both of its rules. Bytes that are not the record are not
/// a record admitting everybody, bytes in a rule's place that are not a
/// rule are not one either, and neither is a rule asking about anything
/// but claims: all fail closed.
#[must_use]
pub fn auth_cell_admits(owner: Address, cell: Option<&[u8]>, keys: &[Claim]) -> bool {
    match cell {
        None | Some([]) => admitted_by(&StoredRule::claim(Claim::of_subject(owner)), keys),
        Some(bytes) => Authority::from_cell(bytes).is_ok_and(|authority| {
            rule_admits(&authority.primary, keys) && rule_admits(&authority.confirmation, keys)
        }),
    }
}

/// Whether one stored rule's bytes admit `keys`, failing closed on
/// bytes that are not a rule.
fn rule_admits(rule: &RuleBytes, keys: &[Claim]) -> bool {
    rule.decode().is_ok_and(|rule| admitted_by(&rule, keys))
}

/// Whether one stored rule admits `keys`, failing closed on a rule
/// asking about anything but claims.
fn admitted_by(rule: &StoredRule, keys: &[Claim]) -> bool {
    rule.claims_only()
        .is_some_and(|claims| claims.satisfied_by(keys))
}

/// A rule as the bytes a cell holds, where the encoding fits the value
/// cap: the widest rule inside the vocabulary's caps does, and one past
/// them is refused as a value too wide to store.
impl TryFrom<&StoredRule> for RuleBytes {
    type Error = EncodeError;

    fn try_from(rule: &StoredRule) -> Result<Self, EncodeError> {
        let bytes = rule.to_bytes()?;
        Bytes::new(bytes)
            .map(Self)
            .map_err(|overflow| EncodeError::BoundExceeded {
                field: "rule",
                actual: overflow.actual,
                max: overflow.max,
            })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass};

    use super::{Authority, RuleBytes, auth_cell_admits};
    use crate::claim::Claim;
    use crate::rule::StoredRule;

    fn principal(tag: u8) -> Address {
        Address::new([tag; 31], AddressClass::Principal)
    }

    fn naming(who: Address) -> RuleBytes {
        RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(who)))
            .expect("a rule within the caps")
    }

    fn one_rule() -> StoredRule {
        StoredRule::claim(Claim::of_subject(Address::new(
            [7; 31],
            AddressClass::Component,
        )))
    }

    /// A rule crosses as an argument as its own bytes and sits in a cell
    /// inside a record, and the two are not the same bytes.
    ///
    /// Stated here because this is the file that owns both halves: a
    /// writer reaching for the wrong one stores a rule no gate can read,
    /// and the only signal would be an account nobody can open.
    #[test]
    fn the_cell_form_frames_what_the_argument_form_carries() {
        let rule = one_rule();
        let carried = RuleBytes::try_from(&rule).expect("a rule within the caps");
        let stored = carried.in_cell();

        assert_ne!(
            stored,
            *carried.bytes(),
            "a cell holds the record, and the record holds the rule"
        );
        assert_eq!(RuleBytes::rule_in_cell(&stored), Ok(rule));
    }

    /// And the wrong half fails closed. A cell holding what an argument
    /// carries decodes as no rule at all, which admits nobody — never as
    /// some other rule, which would admit somebody.
    #[test]
    fn a_cell_holding_the_argument_form_reads_as_no_rule() {
        let carried = RuleBytes::try_from(&one_rule()).expect("a rule within the caps");

        assert!(RuleBytes::rule_in_cell(carried.bytes()).is_err());
        assert!(RuleBytes::rule_in_cell(&[]).is_err());
    }

    /// The governing cell admits an attesting set only when both of its
    /// rules do: the primary alone is the phone without the card, the
    /// confirmation alone is the card without the phone, and an account
    /// naming no second factor is opened by its primary.
    #[test]
    fn a_governing_cell_admits_a_set_both_rules_admit() {
        let owner = principal(1);
        let phone = Claim::of_subject(principal(2));
        let card = Claim::of_subject(principal(3));
        let both = Authority {
            primary: naming(phone.subject),
            confirmation: naming(card.subject),
        }
        .in_cell();

        assert!(auth_cell_admits(owner, Some(&both), &[phone, card]));
        assert!(!auth_cell_admits(owner, Some(&both), &[phone]));
        assert!(!auth_cell_admits(owner, Some(&both), &[card]));

        let phone_only = Authority::primary_only(naming(phone.subject)).in_cell();
        assert!(auth_cell_admits(owner, Some(&phone_only), &[phone]));
        assert!(!auth_cell_admits(owner, Some(&phone_only), &[card]));
    }

    /// A cell holding one bare rule where the record belongs admits
    /// nobody, the key that rule names included: bytes that are not the
    /// record are not a record admitting somebody.
    #[test]
    fn a_governing_cell_holding_one_bare_rule_admits_nobody() {
        let owner = principal(1);
        let phone = Claim::of_subject(principal(2));
        let bare = naming(phone.subject).in_cell();

        assert!(!auth_cell_admits(owner, Some(&bare), &[phone]));
        assert!(auth_cell_admits(owner, None, &[Claim::of_subject(owner)]));
    }
}
