//! The mode lattice's execution semantics: the amount cell, the delta
//! fold, and reservation feasibility.
//!
//! Everything here is a pure function with a deterministic verdict — the
//! commutative modes are exactly the ones whose outcome cannot depend on
//! scheduling, and these functions are where that property is enforced:
//! delta folds are total sums within one transaction, applied per
//! transaction in canonical transaction-hash order under a floor of
//! outstanding reservations, and reservation feasibility is judged in the
//! same order against committed balance minus prior reservations, never
//! counting in-flight deltas.

pub use hyperscale_vm_effects::TxHash;

/// The width of a fungible-amount cell.
pub const AMOUNT_CELL_BYTES: usize = 16;

/// Why a mode-semantics computation rejected its inputs. Deterministic:
/// the same inputs fail identically on every replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModeError {
    /// An amount cell whose byte length is not [`AMOUNT_CELL_BYTES`].
    #[error("amount cell must be exactly {AMOUNT_CELL_BYTES} bytes, found {0}")]
    BadAmountCell(usize),
    /// Summing a fold's increments or decrements overflowed `u128`.
    #[error("delta totals overflow")]
    DeltaOverflow,
    /// A fold that would push a cell above `u128::MAX`.
    #[error("amount cell overflow")]
    CellOverflow,
    /// A fold whose decrements exceed the cell's credited total.
    #[error("amount cell underflow")]
    CellUnderflow,
    /// A supply accumulator update past its bounds.
    #[error("supply accumulator out of bounds")]
    SupplyOutOfBounds,
}

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

/// Decode an amount cell.
///
/// # Errors
///
/// [`ModeError::BadAmountCell`] unless the value is exactly
/// [`AMOUNT_CELL_BYTES`] long.
pub fn decode_amount(bytes: &[u8]) -> Result<u128, ModeError> {
    let cell: [u8; AMOUNT_CELL_BYTES] = bytes
        .try_into()
        .map_err(|_| ModeError::BadAmountCell(bytes.len()))?;
    Ok(u128::from_le_bytes(cell))
}

/// One unconditional commutative movement on an amount cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaOp {
    /// Credit the cell.
    Add(u128),
    /// Debit the cell unconditionally; feasibility, where needed, is the
    /// reserve mode's job.
    Sub(u128),
}

/// Fold a batch of deltas over a committed amount.
///
/// The fold computes increment and decrement totals with checked
/// arithmetic and applies them once, so no application order can influence
/// the outcome — the canonical-order discipline is satisfied by
/// construction, and the permutation-invariance property tests witness it.
///
/// # Errors
///
/// [`ModeError::DeltaOverflow`] if either total overflows,
/// [`ModeError::CellOverflow`] / [`ModeError::CellUnderflow`] if the folded
/// cell leaves `u128`.
pub fn fold_deltas(committed: u128, ops: &[DeltaOp]) -> Result<u128, ModeError> {
    let mut credit: u128 = 0;
    let mut debit: u128 = 0;
    for op in ops {
        match op {
            DeltaOp::Add(amount) => {
                credit = credit
                    .checked_add(*amount)
                    .ok_or(ModeError::DeltaOverflow)?;
            }
            DeltaOp::Sub(amount) => {
                debit = debit.checked_add(*amount).ok_or(ModeError::DeltaOverflow)?;
            }
        }
    }
    committed
        .checked_add(credit)
        .ok_or(ModeError::CellOverflow)?
        .checked_sub(debit)
        .ok_or(ModeError::CellUnderflow)
}

/// A reservation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feasibility {
    /// The reservation holds; execution may take the amount.
    Feasible,
    /// Committed minus prior reservations does not cover the amount; the
    /// transaction aborts as infeasible.
    Infeasible,
}

impl Feasibility {
    /// Whether the verdict is [`Feasibility::Feasible`].
    #[must_use]
    pub const fn is_feasible(self) -> bool {
        matches!(self, Self::Feasible)
    }
}

/// Judge a batch of reservation requests against an available amount.
///
/// Requests are ordered canonically — ascending transaction hash — and
/// each is feasible iff the amount remaining after every prior feasible
/// reservation covers it. The verdict list is returned in that canonical
/// order and is invariant under any permutation of the input.
#[must_use]
pub fn judge(available: u128, requests: &[(TxHash, u128)]) -> Vec<(TxHash, Feasibility)> {
    let mut ordered = requests.to_vec();
    ordered.sort_unstable();
    let mut remaining = available;
    ordered
        .into_iter()
        .map(|(tx, amount)| {
            let verdict = if remaining >= amount {
                remaining -= amount;
                Feasibility::Feasible
            } else {
                Feasibility::Infeasible
            };
            (tx, verdict)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::Hash32;

    use super::{
        AMOUNT_CELL_BYTES, DeltaOp, Feasibility, ModeError, TxHash, decode_amount, encode_amount,
        fold_deltas, judge,
    };

    fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    #[test]
    fn amount_cell_round_trips_and_rejects_bad_lengths() {
        let cell = encode_amount(7_000_000_000_000_000_000_000);
        assert_eq!(cell.len(), AMOUNT_CELL_BYTES);
        assert_eq!(decode_amount(&cell), Ok(7_000_000_000_000_000_000_000));
        assert_eq!(
            decode_amount(&cell[..15]),
            Err(ModeError::BadAmountCell(15))
        );
        assert_eq!(decode_amount(&[0; 17]), Err(ModeError::BadAmountCell(17)));
    }

    #[test]
    fn delta_fold_nets_credits_and_debits() {
        let ops = [DeltaOp::Add(50), DeltaOp::Sub(30), DeltaOp::Add(10)];
        assert_eq!(fold_deltas(100, &ops), Ok(130));
        assert_eq!(fold_deltas(0, &[]), Ok(0));
        // A debit past the credited total is a deterministic underflow, not
        // a saturation.
        assert_eq!(
            fold_deltas(10, &[DeltaOp::Sub(11)]),
            Err(ModeError::CellUnderflow)
        );
        // Net-fine but total-overflowing folds reject rather than depend on
        // evaluation shape.
        assert_eq!(
            fold_deltas(1, &[DeltaOp::Add(u128::MAX), DeltaOp::Sub(2)]),
            Err(ModeError::CellOverflow)
        );
    }

    #[test]
    fn feasibility_is_judged_in_hash_order() {
        // Contested balance: the lower hash wins regardless of input order.
        let requests = [(tx(9), 60), (tx(1), 60)];
        let verdicts = judge(100, &requests);
        assert_eq!(
            verdicts,
            vec![
                (tx(1), Feasibility::Feasible),
                (tx(9), Feasibility::Infeasible),
            ]
        );

        // Exact balance is feasible; zero is always feasible.
        assert_eq!(
            judge(60, &[(tx(2), 60)]),
            vec![(tx(2), Feasibility::Feasible)]
        );
        assert_eq!(
            judge(0, &[(tx(3), 0)]),
            vec![(tx(3), Feasibility::Feasible)]
        );
    }
}
