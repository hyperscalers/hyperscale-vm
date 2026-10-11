//! The amount ledger: reservations, movements, and the delta fold, over
//! whatever view a store presents.
//!
//! Two stores carry amount cells — the plain [`MemoryStore`](crate::MemoryStore)
//! and the layered [`OverlayStore`](crate::OverlayStore) — and they differ
//! in exactly two things: what a cell currently holds, and what is
//! currently held against it. Both questions already have answers on
//! [`Baseline`]: `cell` resolves the plain store's map or the overlay's
//! active-over-committed-over-base fall-through, and `holds`,
//! `fee_holds` and `withheld_credits` resolve the stored maps or the
//! three layers merged.
//!
//! So the arithmetic standing on those answers is written once, here,
//! and a store supplies only the seven operations that cannot be derived
//! — how it records an amount, a hold, a fee hold, a withheld credit, and
//! an access, and how it holds its queued deltas. What each store then owes is that its view
//! is right, which is what the overlay's differential corpus tests;
//! nothing owes a second copy of the floor.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_types::{EffectTarget, ModeKind, SubstateKey, TxHash, amount_cell};

use crate::modes::{DeltaOp, Feasibility, ModeError, decode_amount, fold_deltas, judge};
use crate::store::{AppliedDelta, Baseline, StoreError};

/// The amount-cell semantics, over a store's own view of committed
/// content and outstanding holds.
pub trait AmountLedger: Baseline {
    /// Record an amount, dropping the leaf when it reaches zero.
    fn set_amount(&mut self, key: SubstateKey, amount: u128);

    /// Record a hold, or drop the one `tx` has when `amount` is `None`.
    fn set_hold(&mut self, key: SubstateKey, tx: TxHash, amount: Option<u128>);

    /// Reduce `tx`'s hold on `key` to `amount`, leaving a smaller one
    /// alone.
    ///
    /// What a hold is worth to everyone else is the floor it keeps under
    /// the cell, and what it is worth to its own transaction is the
    /// ceiling on what settling it may take. [`Self::set_hold`] states an
    /// amount, so a caller settling a figure it derived elsewhere could
    /// raise the ceiling it is about to spend against and debit past a
    /// floor another transaction is standing on. Settling part of a hold
    /// goes through here so that cannot be what a disagreement produces.
    fn reduce_hold(&mut self, key: SubstateKey, tx: TxHash, amount: u128) {
        let standing = self.held_reservation(key, tx).unwrap_or_default();
        self.set_hold(key, tx, Some(amount.min(standing)));
    }

    /// Record `tx`'s fee hold on `key`, or end it when `amount` is `None`.
    ///
    /// Ending is the only thing a batch does to a fee hold, and only a
    /// member's own burn does it: nothing settles one, releases one, or
    /// reduces one.
    fn set_fee_hold(&mut self, key: SubstateKey, tx: TxHash, amount: Option<u128>);

    /// Record that `amount` of what `key` holds is `tx`'s credit, withheld
    /// from every other member.
    ///
    /// The amount is what the member's movement raised the cell by, its
    /// credit less its own debit: a cell a member moved value through
    /// holds what it held, whether the member stands or is discarded,
    /// and one it drew down holds less only while it stands. So every
    /// other member is judged over the lower of the two.
    ///
    /// Recorded where the credit is, so whatever rolls the credit back
    /// takes the record with it. Nothing ends one within a batch: it
    /// stands for as long as a debit judged over the credit could settle
    /// without it.
    fn withhold_credit(&mut self, key: SubstateKey, tx: TxHash, amount: u128);

    /// Note one access against the trace the oracle checks.
    fn note(&mut self, target: EffectTarget, kind: ModeKind);

    /// Deltas queued but not yet folded, per cell.
    fn queued(&self) -> BTreeMap<SubstateKey, Vec<DeltaOp>>;

    /// Drop every queued delta.
    fn clear_queued(&mut self);

    /// A cell's committed content as an amount; an absent cell is zero.
    ///
    /// # Errors
    ///
    /// A decode failure on a cell holding something that is not an amount.
    fn amount(&self, key: SubstateKey) -> Result<u128, StoreError> {
        match self.cell(key) {
            Some(cell) => Ok(decode_amount(&cell)?),
            None => Ok(0),
        }
    }

    /// `committed` with this transaction's own queued deltas folded in.
    ///
    /// A body that credits a cell and then reads it sees the credit: the
    /// queue is its own work and nothing else can observe it, so the
    /// alternative is a balance that disagrees with what the body just
    /// did.
    ///
    /// # Errors
    ///
    /// A fold that leaves `u128`.
    fn with_queued(&self, key: SubstateKey, committed: u128) -> Result<u128, StoreError> {
        match self.queued().get(&key) {
            Some(ops) => Ok(fold_deltas(committed, ops)?),
            None => Ok(committed),
        }
    }

    /// Every outstanding reservation on `key`, summed.
    ///
    /// # Errors
    ///
    /// [`StoreError::HeldExceedsCommitted`] if the total leaves `u128`,
    /// which is a violated ledger invariant rather than a cell's state.
    fn held_total(&self, key: SubstateKey) -> Result<u128, StoreError> {
        self.holds(key)
            .values()
            .try_fold(0u128, |total, amount| total.checked_add(*amount))
            .ok_or(StoreError::HeldExceedsCommitted(key))
    }

    /// Whether `key` can carry a reservation at all: either absent or a
    /// well-formed amount cell. A refusal here is a declaration defect —
    /// the sender's fault, judged before the feasibility race.
    ///
    /// # Errors
    ///
    /// An amount-cell decode failure.
    fn check_reserve_target(&self, key: SubstateKey) -> Result<(), StoreError> {
        self.amount(key)?;
        Ok(())
    }

    /// What of `standing` on `key` nothing has been promised: less every
    /// outstanding reservation, then less every fee hold and `withheld`,
    /// the credits in it the judged transaction may not spend.
    ///
    /// The floors fail differently because they are different promises.
    /// A reservation is a debit already granted against the cell, so
    /// reservations the cell cannot cover are a ledger that no longer
    /// adds up. A fee hold is a ceiling stood under whatever else the
    /// cell is asked for, and a withheld credit is value the cell may
    /// yet give back, so either past what is left leaves nothing to
    /// spend and nothing wrong.
    ///
    /// # Errors
    ///
    /// [`StoreError::HeldExceedsCommitted`] where the reservations exceed
    /// `standing`.
    fn unpromised(
        &self,
        key: SubstateKey,
        standing: u128,
        withheld: u128,
    ) -> Result<u128, StoreError> {
        Ok(standing
            .checked_sub(self.held_total(key)?)
            .ok_or(StoreError::HeldExceedsCommitted(key))?
            .saturating_sub(self.fee_holds(key).total())
            .saturating_sub(withheld))
    }

    /// What a debit of `tx`'s on `key` may take: the cell and `credit`,
    /// less everything [`Self::unpromised`] leaves out, every credit
    /// withheld from `tx` included.
    ///
    /// # Errors
    ///
    /// [`ModeError::CellOverflow`] on credit overflow, [`Self::unpromised`]'s
    /// ledger failure, or a decode failure.
    fn spendable(&self, key: SubstateKey, tx: TxHash, credit: u128) -> Result<u128, StoreError> {
        let credited = self
            .amount(key)?
            .checked_add(credit)
            .ok_or(ModeError::CellOverflow)?;
        self.unpromised(key, credited, self.withheld_credits(key).kept_from(tx))
    }

    /// Judge `tx`'s net movement on an amount cell, returning the value
    /// the cell would take. The floor is [`Self::spendable`]'s: an
    /// unconditional debit can never consume value a held reservation
    /// still covers, value a fee hold stands on, nor a credit another
    /// member made that is withheld.
    ///
    /// # Errors
    ///
    /// [`ModeError::CellUnderflow`] for a debit past the floor,
    /// [`ModeError::CellOverflow`] on credit overflow — both the judged
    /// transaction's deterministic loss — or a decode/ledger failure.
    fn judge_movement(
        &self,
        key: SubstateKey,
        tx: TxHash,
        credit: u128,
        debit: u128,
    ) -> Result<u128, StoreError> {
        let credited = self
            .amount(key)?
            .checked_add(credit)
            .ok_or(ModeError::CellOverflow)?;
        if debit > self.unpromised(key, credited, self.withheld_credits(key).kept_from(tx))? {
            return Err(ModeError::CellUnderflow.into());
        }
        Ok(credited - debit)
    }

    /// Apply `tx`'s net movement under [`Self::judge_movement`]'s floor.
    ///
    /// # Errors
    ///
    /// Exactly [`Self::judge_movement`]'s; a refusal leaves the cell
    /// untouched.
    fn apply_movement(
        &mut self,
        key: SubstateKey,
        tx: TxHash,
        credit: u128,
        debit: u128,
    ) -> Result<u128, StoreError> {
        let after = self.judge_movement(key, tx, credit, debit)?;
        self.set_amount(key, after);
        Ok(after)
    }

    /// Judge a batch of reservation requests, holding the feasible ones.
    ///
    /// Per cell: available is what [`Self::unpromised`] leaves of the
    /// committed amount, so a request competes with the reservations
    /// already held and stays above every fee hold, its own member's
    /// included, and above every withheld credit: a requester is judged
    /// before its body runs, so none of them is its own. The batch is
    /// judged in canonical transaction-hash order.
    /// Verdicts are invariant under any permutation of the batch. Each
    /// request records a reserve access.
    ///
    /// # Errors
    ///
    /// [`StoreError::DuplicateRequest`] for a repeated `(tx, key)` pair,
    /// [`StoreError::HeldExceedsCommitted`] on a violated ledger
    /// invariant, or an amount-cell decode failure.
    fn judge_and_hold(
        &mut self,
        requests: &[(TxHash, SubstateKey, u128)],
    ) -> Result<BTreeMap<(TxHash, SubstateKey), Feasibility>, StoreError> {
        let mut by_key: BTreeMap<SubstateKey, Vec<(TxHash, u128)>> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (tx, key, amount) in requests {
            if !seen.insert((*tx, *key)) {
                return Err(StoreError::DuplicateRequest { tx: *tx, key: *key });
            }
            self.note(EffectTarget::Point(*key), ModeKind::Reserve);
            by_key.entry(*key).or_default().push((*tx, *amount));
        }
        let mut verdicts = BTreeMap::new();
        for (key, batch) in by_key {
            let available =
                self.unpromised(key, self.amount(key)?, self.withheld_credits(key).total())?;
            for (tx, verdict) in judge(available, &batch) {
                if verdict.is_feasible() {
                    let amount = batch
                        .iter()
                        .find(|(candidate, _)| *candidate == tx)
                        .map_or(0, |(_, amount)| *amount);
                    self.set_hold(key, tx, Some(amount));
                }
                verdicts.insert((tx, key), verdict);
            }
        }
        Ok(verdicts)
    }

    /// Settle a held reservation: decrement the cell and drop the hold.
    /// Returns the settled amount.
    ///
    /// Everything fallible happens before anything mutable, so a refusal
    /// leaves the hold standing, the caller can still release it, and the
    /// ledger stays accountable.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReservation`] if `tx` holds nothing on `key`;
    /// a cell decode or underflow failure otherwise.
    fn settle(&mut self, key: SubstateKey, tx: TxHash) -> Result<u128, StoreError> {
        let amount = self
            .held_reservation(key, tx)
            .ok_or(StoreError::MissingReservation { tx, key })?;
        let after = self
            .amount(key)?
            .checked_sub(amount)
            .ok_or(StoreError::HeldExceedsCommitted(key))?;
        self.set_hold(key, tx, None);
        self.set_amount(key, after);
        Ok(amount)
    }

    /// Release a held reservation without touching the cell. Returns the
    /// released amount.
    ///
    /// Releasing records no access, and neither does [`Self::settle`],
    /// while [`Self::judge_and_hold`] does. The trace exists to catch a
    /// guest touching state its transaction never declared, and taking the
    /// hold is the declaration being exercised; disposing of it afterwards
    /// is the batch's own bookkeeping, running when no guest is left to
    /// attribute it to.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReservation`] if `tx` holds nothing on `key`.
    fn release(&mut self, key: SubstateKey, tx: TxHash) -> Result<u128, StoreError> {
        let amount = self
            .held_reservation(key, tx)
            .ok_or(StoreError::MissingReservation { tx, key })?;
        self.set_hold(key, tx, None);
        Ok(amount)
    }

    /// Fold every queued delta into its cell, atomically: all folds are
    /// computed before any cell changes, so an error leaves both state and
    /// the queue untouched.
    ///
    /// # Errors
    ///
    /// Any fold or decode failure, verbatim from the offending cell.
    fn commit_deltas(&mut self) -> Result<Vec<AppliedDelta>, StoreError> {
        let queued = self.queued();
        let mut applied = Vec::with_capacity(queued.len());
        for (key, ops) in &queued {
            let before = self.amount(*key)?;
            let after = fold_deltas(before, ops)?;
            applied.push(AppliedDelta {
                key: *key,
                before,
                after,
            });
        }
        for outcome in &applied {
            self.set_amount(outcome.key, outcome.after);
        }
        self.clear_queued();
        Ok(applied)
    }
}

/// The cell bytes an amount is stored as, or `None` at zero — a drained
/// cell is an absent leaf, not sixteen zero bytes.
pub(crate) fn amount_bytes(amount: u128) -> Option<Vec<u8>> {
    amount_cell(amount).map(|cell| cell.to_vec())
}
