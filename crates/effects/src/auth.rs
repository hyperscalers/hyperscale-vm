//! The bytes a stored rule travels as.
//!
//! One thing, opaque to whoever carries it and decoded only where the
//! rule is judged. What a package does with a rule it stores — how many
//! it keeps, under what names, and what it takes to replace one — is that
//! package's own business, held in that package's own cells.

use hyperscale_hbor::{DecodeError, EncodeError, Hbor, HborShape, from_slice, to_vec};

use crate::rule::StoredRule;

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
pub struct RuleBytes(pub Vec<u8>);

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

impl TryFrom<&StoredRule> for RuleBytes {
    type Error = EncodeError;

    fn try_from(rule: &StoredRule) -> Result<Self, EncodeError> {
        rule.to_bytes().map(Self)
    }
}
