//! How a fungible amount is stored in a cell.
//!
//! One encoding, shared by everything that reads or writes a balance:
//! the kernel judging a movement, an embedder settling a receipt, a
//! guest reading its own vault. It lives here rather than in the kernel
//! because settlement folds movements onto cells outside any execution,
//! and a second copy of this rule is a second chance to disagree about
//! what a balance is.

/// The width of a fungible-amount cell.
pub const AMOUNT_CELL_BYTES: usize = 16;

/// Encode an amount into its cell representation: little-endian `u128`.
#[must_use]
pub const fn encode_amount(amount: u128) -> [u8; AMOUNT_CELL_BYTES] {
    amount.to_le_bytes()
}

/// The cell form of an amount: a zero balance is an absent cell, not
/// sixteen zero bytes.
///
/// Storage is a refundable per-byte bond, so the leaf has to go when the
/// balance does — draining is the commonest shrink in the system, and for
/// a commutative cell it is the only exit, since a delta capability has no
/// remove. The supply accumulator has always shed zero entries; this is
/// the cell half of the same rule.
///
/// The consequence at the guest boundary is that a drained cell reads as
/// empty rather than as sixteen zero bytes. Both decode to zero, and
/// every stdlib guest already treats them alike, but the obligation is
/// permanent: an amount decoder must accept an empty cell.
#[must_use]
pub fn amount_cell(amount: u128) -> Option<[u8; AMOUNT_CELL_BYTES]> {
    (amount != 0).then(|| encode_amount(amount))
}

/// Decode an amount cell, or `None` if it is not one.
///
/// An absent cell is zero; callers that distinguish absent from
/// malformed check for the cell before asking.
#[must_use]
pub fn read_amount(bytes: &[u8]) -> Option<u128> {
    let cell: [u8; AMOUNT_CELL_BYTES] = bytes.try_into().ok()?;
    Some(u128::from_le_bytes(cell))
}
