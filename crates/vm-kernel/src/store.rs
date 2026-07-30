//! The substate store: the kernel-facing state surface and its in-memory,
//! access-recording implementation.
//!
//! The trait is the surface capability handles drive: mode-specific
//! operations over point cells and ordered-collection entries. The
//! [`MemoryStore`] records every access as an [`Access`] — the substrate
//! the trace-subset oracle asserts against — and owns the commutative
//! modes' lifecycle: deltas queue during execution and fold at commit;
//! reservations are judged and held before execution and settle or release
//! afterward.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{Address, EffectTarget, ModeKind, RoleId, SubstateKey};

use crate::modes::{
    DeltaOp, Feasibility, ModeError, TxHash, decode_amount, encode_amount, fold_deltas, judge,
};

/// Why a store operation rejected. Deterministic: identical on every
/// replica.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A mutation of a permanently locked substate.
    #[error("substate {0:?} is locked")]
    Locked(SubstateKey),
    /// Locking a substate that does not exist.
    #[error("cannot lock absent substate {0:?}")]
    LockMissing(SubstateKey),
    /// Settling or releasing a reservation that is not held.
    #[error("no reservation held by {tx:?} on {key:?}")]
    MissingReservation {
        /// The transaction claimed to hold it.
        tx: TxHash,
        /// The cell it would cover.
        key: SubstateKey,
    },
    /// Held reservations exceeding the committed cell — a ledger invariant
    /// violation surfaced as an error rather than silently misjudged.
    #[error("held reservations exceed committed balance on {0:?}")]
    HeldExceedsCommitted(SubstateKey),
    /// An amount-cell or fold failure.
    #[error(transparent)]
    Mode(#[from] ModeError),
}

/// One recorded access: what was touched and in which mode. The trace the
/// oracle compares against the declared effect set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Access {
    /// The touched target.
    pub target: EffectTarget,
    /// The mode the operation belongs to.
    pub kind: ModeKind,
}

/// The kernel-facing state surface.
///
/// Operations are mode-specific because that is what capability handles
/// invoke: a delta handle can queue deltas and nothing else. Reservations
/// have no trait operation — they are judged before execution and settled
/// after it, outside any guest's reach.
pub trait SubstateStore {
    /// Fresh coherent read of a point cell.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn read(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError>;

    /// Pinned read of a point cell; locked substates are read this way.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn snapshot(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError>;

    /// Exclusive write of a point cell.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] on a locked substate.
    fn write(&mut self, key: SubstateKey, value: Vec<u8>) -> Result<(), StoreError>;

    /// Remove a point cell, returning its value.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] on a locked substate.
    fn remove(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError>;

    /// Permanently lock a substate: creation-fixed configuration. Locked
    /// substates read as unbounded snapshots and reject every mutation.
    /// A kernel operation, not an access — nothing is recorded.
    ///
    /// # Errors
    ///
    /// [`StoreError::LockMissing`] if the substate does not exist.
    fn lock(&mut self, key: SubstateKey) -> Result<(), StoreError>;

    /// Queue a delta against an amount cell; folded at commit. An absent
    /// cell folds from zero, which is what lets deposits create balances
    /// without a prior write.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] on a locked substate.
    fn queue_delta(&mut self, key: SubstateKey, op: DeltaOp) -> Result<(), StoreError>;

    /// Read one ordered-collection entry.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn entry_read(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, StoreError>;

    /// Write one ordered-collection entry.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn entry_write(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), StoreError>;

    /// Remove one ordered-collection entry, returning its value.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn entry_remove(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, StoreError>;

    /// Scan a collection interval in ascending order, truncated at `cap`
    /// entries — the cap is the range effect's declared bound, so touching
    /// beyond it is not expressible through this surface. An inverted
    /// interval is empty.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn scan(
        &mut self,
        owner: Address,
        collection: RoleId,
        lo: u128,
        hi: u128,
        cap: u32,
    ) -> Result<Vec<(u128, Vec<u8>)>, StoreError>;
}

/// One applied delta fold, for conservation accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedDelta {
    /// The folded cell.
    pub key: SubstateKey,
    /// The committed amount before the fold.
    pub before: u128,
    /// The committed amount after the fold.
    pub after: u128,
}

/// The in-memory, access-recording store.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    pub(crate) cells: BTreeMap<SubstateKey, Vec<u8>>,
    pub(crate) entries: BTreeMap<(Address, RoleId), BTreeMap<u128, Vec<u8>>>,
    pub(crate) locked: BTreeSet<SubstateKey>,
    pub(crate) pending_deltas: BTreeMap<SubstateKey, Vec<DeltaOp>>,
    pub(crate) held: BTreeMap<SubstateKey, BTreeMap<TxHash, u128>>,
    log: Vec<Access>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            entries: BTreeMap::new(),
            locked: BTreeSet::new(),
            pending_deltas: BTreeMap::new(),
            held: BTreeMap::new(),
            log: Vec::new(),
        }
    }

    /// Every access recorded since the last [`Self::clear_log`].
    #[must_use]
    pub fn access_log(&self) -> &[Access] {
        &self.log
    }

    /// Reset the access log; state is untouched.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Whether a substate is permanently locked.
    #[must_use]
    pub fn is_locked(&self, key: SubstateKey) -> bool {
        self.locked.contains(&key)
    }

    /// The reservation amount `tx` holds on `key`, if any.
    #[must_use]
    pub fn held_reservation(&self, key: SubstateKey, tx: TxHash) -> Option<u128> {
        self.held
            .get(&key)
            .and_then(|holds| holds.get(&tx))
            .copied()
    }

    /// Deltas queued but not yet committed, per cell.
    pub fn pending_deltas(&self) -> impl Iterator<Item = (SubstateKey, &[DeltaOp])> + '_ {
        self.pending_deltas
            .iter()
            .map(|(key, ops)| (*key, ops.as_slice()))
    }

    /// Every point cell, in canonical key order.
    pub fn cells(&self) -> impl Iterator<Item = (SubstateKey, &[u8])> + '_ {
        self.cells
            .iter()
            .map(|(key, value)| (*key, value.as_slice()))
    }

    /// Every ordered-collection entry, in canonical order.
    pub fn collection_entries(
        &self,
    ) -> impl Iterator<Item = ((Address, RoleId, u128), &[u8])> + '_ {
        self.entries
            .iter()
            .flat_map(|((owner, collection), entries)| {
                entries
                    .iter()
                    .map(|(order, value)| ((*owner, *collection, *order), value.as_slice()))
            })
    }

    fn record(&mut self, target: EffectTarget, kind: ModeKind) {
        self.log.push(Access { target, kind });
    }

    fn reject_locked(&self, key: SubstateKey) -> Result<(), StoreError> {
        if self.locked.contains(&key) {
            return Err(StoreError::Locked(key));
        }
        Ok(())
    }

    fn committed_amount(&self, key: SubstateKey) -> Result<u128, StoreError> {
        match self.cells.get(&key) {
            Some(cell) => Ok(decode_amount(cell)?),
            None => Ok(0),
        }
    }

    fn held_total(&self, key: SubstateKey) -> Result<u128, StoreError> {
        self.held
            .get(&key)
            .map_or(Some(0), |holds| {
                holds
                    .values()
                    .try_fold(0u128, |acc, amount| acc.checked_add(*amount))
            })
            .ok_or(StoreError::HeldExceedsCommitted(key))
    }

    /// Whether `key` can carry a reservation at all: unlocked and either
    /// absent or a well-formed amount cell. A refusal here is a
    /// declaration defect — the sender's fault, judged before the
    /// feasibility race.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] or an amount-cell decode failure.
    pub fn check_reserve_target(&self, key: SubstateKey) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.committed_amount(key)?;
        Ok(())
    }

    /// Judge one transaction's net movement on an amount cell, returning
    /// the value the cell would take. The floor is committed plus the
    /// credit minus every outstanding reservation: an unconditional debit
    /// can never consume value a held reservation still covers.
    ///
    /// # Errors
    ///
    /// [`ModeError::CellUnderflow`] for a debit past the floor,
    /// [`ModeError::CellOverflow`] on credit overflow — both the judged
    /// transaction's deterministic loss — or a decode/ledger failure.
    pub fn judge_movement(
        &self,
        key: SubstateKey,
        credit: u128,
        debit: u128,
    ) -> Result<u128, StoreError> {
        let credited = self
            .committed_amount(key)?
            .checked_add(credit)
            .ok_or(ModeError::CellOverflow)?;
        let available = credited
            .checked_sub(self.held_total(key)?)
            .ok_or(StoreError::HeldExceedsCommitted(key))?;
        available
            .checked_sub(debit)
            .ok_or(ModeError::CellUnderflow)?;
        Ok(credited - debit)
    }

    /// Apply one transaction's net movement to an amount cell, under
    /// [`Self::judge_movement`]'s floor.
    ///
    /// # Errors
    ///
    /// Exactly [`Self::judge_movement`]'s; a refusal leaves the cell
    /// untouched.
    pub fn apply_movement(
        &mut self,
        key: SubstateKey,
        credit: u128,
        debit: u128,
    ) -> Result<u128, StoreError> {
        let after = self.judge_movement(key, credit, debit)?;
        self.cells.insert(key, encode_amount(after).to_vec());
        Ok(after)
    }

    /// Judge a batch of reservation requests, holding the feasible ones.
    ///
    /// Per cell: available is committed minus reservations already held,
    /// and the batch is judged in canonical transaction-hash order.
    /// Verdicts are invariant under any permutation of the batch. Each
    /// request records a reserve access.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] for a reservation on a locked substate,
    /// [`StoreError::HeldExceedsCommitted`] on a violated ledger
    /// invariant, or an amount-cell decode failure.
    pub fn judge_and_hold(
        &mut self,
        requests: &[(TxHash, SubstateKey, u128)],
    ) -> Result<BTreeMap<(TxHash, SubstateKey), Feasibility>, StoreError> {
        let mut by_key: BTreeMap<SubstateKey, Vec<(TxHash, u128)>> = BTreeMap::new();
        for (tx, key, amount) in requests {
            self.reject_locked(*key)?;
            self.record(EffectTarget::Point(*key), ModeKind::Reserve);
            by_key.entry(*key).or_default().push((*tx, *amount));
        }
        let mut verdicts = BTreeMap::new();
        for (key, batch) in by_key {
            let available = self
                .committed_amount(key)?
                .checked_sub(self.held_total(key)?)
                .ok_or(StoreError::HeldExceedsCommitted(key))?;
            for (tx, verdict) in judge(available, &batch) {
                if verdict.is_feasible() {
                    let amount = batch
                        .iter()
                        .find(|(candidate, _)| *candidate == tx)
                        .map_or(0, |(_, amount)| *amount);
                    self.held.entry(key).or_default().insert(tx, amount);
                }
                verdicts.insert((tx, key), verdict);
            }
        }
        Ok(verdicts)
    }

    /// Settle a held reservation: decrement the cell and drop the hold.
    /// Returns the settled amount.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReservation`] if `tx` holds nothing on `key`;
    /// a cell decode or underflow failure otherwise.
    pub fn settle(&mut self, key: SubstateKey, tx: TxHash) -> Result<u128, StoreError> {
        let amount = self
            .held
            .get_mut(&key)
            .and_then(|holds| holds.remove(&tx))
            .ok_or(StoreError::MissingReservation { tx, key })?;
        let committed = self.committed_amount(key)?;
        let after = committed
            .checked_sub(amount)
            .ok_or(StoreError::HeldExceedsCommitted(key))?;
        self.cells.insert(key, encode_amount(after).to_vec());
        Ok(amount)
    }

    /// Release a held reservation without touching the cell. Returns the
    /// released amount.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReservation`] if `tx` holds nothing on `key`.
    pub fn release(&mut self, key: SubstateKey, tx: TxHash) -> Result<u128, StoreError> {
        self.held
            .get_mut(&key)
            .and_then(|holds| holds.remove(&tx))
            .ok_or(StoreError::MissingReservation { tx, key })
    }

    /// Fold every queued delta into its cell, atomically: all folds are
    /// computed before any cell changes, so an error leaves both state and
    /// the queue untouched.
    ///
    /// # Errors
    ///
    /// Any fold or decode failure, verbatim from the offending cell.
    pub fn commit_deltas(&mut self) -> Result<Vec<AppliedDelta>, StoreError> {
        let mut applied = Vec::with_capacity(self.pending_deltas.len());
        for (key, ops) in &self.pending_deltas {
            let before = self.committed_amount(*key)?;
            let after = fold_deltas(before, ops)?;
            applied.push(AppliedDelta {
                key: *key,
                before,
                after,
            });
        }
        for outcome in &applied {
            self.cells
                .insert(outcome.key, encode_amount(outcome.after).to_vec());
        }
        self.pending_deltas.clear();
        Ok(applied)
    }
}

impl SubstateStore for MemoryStore {
    fn read(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Read);
        Ok(self.cells.get(&key).cloned())
    }

    fn snapshot(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Snapshot);
        Ok(self.cells.get(&key).cloned())
    }

    fn write(&mut self, key: SubstateKey, value: Vec<u8>) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Write);
        self.cells.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Write);
        Ok(self.cells.remove(&key))
    }

    fn lock(&mut self, key: SubstateKey) -> Result<(), StoreError> {
        if !self.cells.contains_key(&key) {
            return Err(StoreError::LockMissing(key));
        }
        self.locked.insert(key);
        Ok(())
    }

    fn queue_delta(&mut self, key: SubstateKey, op: DeltaOp) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Delta);
        self.pending_deltas.entry(key).or_default().push(op);
        Ok(())
    }

    fn entry_read(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            ModeKind::Read,
        );
        Ok(self
            .entries
            .get(&(owner, collection))
            .and_then(|entries| entries.get(&order))
            .cloned())
    }

    fn entry_write(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.record(
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            ModeKind::Write,
        );
        self.entries
            .entry((owner, collection))
            .or_default()
            .insert(order, value);
        Ok(())
    }

    fn entry_remove(
        &mut self,
        owner: Address,
        collection: RoleId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            ModeKind::Write,
        );
        Ok(self
            .entries
            .get_mut(&(owner, collection))
            .and_then(|entries| entries.remove(&order)))
    }

    fn scan(
        &mut self,
        owner: Address,
        collection: RoleId,
        lo: u128,
        hi: u128,
        cap: u32,
    ) -> Result<Vec<(u128, Vec<u8>)>, StoreError> {
        self.record(
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            },
            ModeKind::Read,
        );
        if lo > hi {
            return Ok(Vec::new());
        }
        let limit = usize::try_from(cap).unwrap_or(usize::MAX);
        Ok(self
            .entries
            .get(&(owner, collection))
            .map(|entries| {
                entries
                    .range(lo..=hi)
                    .take(limit)
                    .map(|(order, value)| (*order, value.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Address, EffectTarget, Hash32, ModeKind, RoleId, SubstateKey, TestHasher, child_key,
    };

    use super::{Access, MemoryStore, StoreError, SubstateStore};
    use crate::modes::{DeltaOp, Feasibility, ModeError, TxHash, decode_amount, encode_amount};

    fn key(byte: u8) -> SubstateKey {
        child_key(&TestHasher, Address([byte; 16]), RoleId(1), &[])
    }

    fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    #[test]
    fn movements_floor_at_outstanding_holds() {
        let mut store = MemoryStore::new();
        let vault = key(9);
        store.write(vault, encode_amount(60).to_vec()).unwrap();
        store.judge_and_hold(&[(tx(1), vault, 50)]).unwrap();

        // Ten of headroom above the hold; eleven is past the floor.
        assert_eq!(store.judge_movement(vault, 0, 10), Ok(50));
        assert_eq!(
            store.judge_movement(vault, 0, 11),
            Err(StoreError::Mode(ModeError::CellUnderflow))
        );
        // The transaction's own credit funds its debit above the floor.
        assert_eq!(store.judge_movement(vault, 5, 15), Ok(50));

        // A refused application leaves the cell untouched; an accepted one
        // lands, and the hold survives both.
        assert!(store.apply_movement(vault, 0, 11).is_err());
        assert_eq!(store.judge_movement(vault, 0, 0), Ok(60));
        assert_eq!(store.apply_movement(vault, 0, 10), Ok(50));
        assert_eq!(store.held_reservation(vault, tx(1)), Some(50));
        assert_eq!(store.settle(vault, tx(1)), Ok(50));
    }

    #[test]
    fn locked_substates_reject_every_mutation_and_read_as_snapshots() {
        let mut store = MemoryStore::new();
        let config = key(1);
        store.write(config, vec![7]).unwrap();
        store.lock(config).unwrap();

        assert_eq!(
            store.write(config, vec![8]),
            Err(StoreError::Locked(config))
        );
        assert_eq!(store.remove(config), Err(StoreError::Locked(config)));
        assert_eq!(
            store.queue_delta(config, DeltaOp::Add(1)),
            Err(StoreError::Locked(config))
        );
        assert_eq!(
            store.judge_and_hold(&[(tx(1), config, 1)]),
            Err(StoreError::Locked(config))
        );

        store.clear_log();
        assert_eq!(store.snapshot(config).unwrap(), Some(vec![7]));
        assert_eq!(
            store.access_log(),
            &[Access {
                target: EffectTarget::Point(config),
                kind: ModeKind::Snapshot,
            }]
        );

        assert_eq!(store.lock(key(2)), Err(StoreError::LockMissing(key(2))));
    }

    #[test]
    fn deltas_fold_from_virtual_zero_and_commit_atomically() {
        let mut store = MemoryStore::new();
        let fresh = key(3);
        store.queue_delta(fresh, DeltaOp::Add(30)).unwrap();
        store.queue_delta(fresh, DeltaOp::Sub(10)).unwrap();
        let applied = store.commit_deltas().unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!((applied[0].before, applied[0].after), (0, 20));
        assert_eq!(decode_amount(&store.read(fresh).unwrap().unwrap()), Ok(20));

        // An underflowing batch leaves state and queue untouched.
        let other = key(4);
        store.queue_delta(fresh, DeltaOp::Add(5)).unwrap();
        store.queue_delta(other, DeltaOp::Sub(1)).unwrap();
        assert!(store.commit_deltas().is_err());
        assert_eq!(decode_amount(&store.read(fresh).unwrap().unwrap()), Ok(20));
        // The queue survives the failure; fixing the offender lets the
        // batch commit.
        store.queue_delta(other, DeltaOp::Add(2)).unwrap();
        let applied = store.commit_deltas().unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(decode_amount(&store.read(fresh).unwrap().unwrap()), Ok(25));
        assert_eq!(decode_amount(&store.read(other).unwrap().unwrap()), Ok(1));
    }

    #[test]
    fn reservations_hold_settle_and_release() {
        let mut store = MemoryStore::new();
        let vault = key(5);
        store.write(vault, encode_amount(100).to_vec()).unwrap();

        let verdicts = store
            .judge_and_hold(&[(tx(1), vault, 60), (tx(2), vault, 60)])
            .unwrap();
        assert_eq!(verdicts[&(tx(1), vault)], Feasibility::Feasible);
        assert_eq!(verdicts[&(tx(2), vault)], Feasibility::Infeasible);
        assert_eq!(store.held_reservation(vault, tx(1)), Some(60));
        assert_eq!(store.held_reservation(vault, tx(2)), None);

        // A later batch judges against committed minus held.
        let verdicts = store.judge_and_hold(&[(tx(3), vault, 50)]).unwrap();
        assert_eq!(verdicts[&(tx(3), vault)], Feasibility::Infeasible);
        let verdicts = store.judge_and_hold(&[(tx(4), vault, 40)]).unwrap();
        assert_eq!(verdicts[&(tx(4), vault)], Feasibility::Feasible);

        // Settle decrements the cell; release does not.
        assert_eq!(store.settle(vault, tx(1)), Ok(60));
        assert_eq!(decode_amount(&store.read(vault).unwrap().unwrap()), Ok(40));
        assert_eq!(store.release(vault, tx(4)), Ok(40));
        assert_eq!(decode_amount(&store.read(vault).unwrap().unwrap()), Ok(40));
        assert_eq!(
            store.settle(vault, tx(1)),
            Err(StoreError::MissingReservation {
                tx: tx(1),
                key: vault,
            })
        );
    }

    #[test]
    fn scans_truncate_at_the_cap_and_record_the_interval() {
        let mut store = MemoryStore::new();
        let book = Address([9; 16]);
        let asks = RoleId(4);
        for order in [5u128, 10, 15, 20] {
            store
                .entry_write(book, asks, order, vec![u8::try_from(order).unwrap()])
                .unwrap();
        }
        store.clear_log();
        let hits = store.scan(book, asks, 5, 20, 3).unwrap();
        assert_eq!(
            hits.iter().map(|(order, _)| *order).collect::<Vec<_>>(),
            vec![5, 10, 15]
        );
        assert_eq!(
            store.access_log(),
            &[Access {
                target: EffectTarget::Range {
                    owner: book,
                    collection: asks,
                    lo: 5,
                    hi: 20,
                    cap: 3,
                },
                kind: ModeKind::Read,
            }]
        );
        // Inverted intervals are empty, not errors.
        assert_eq!(store.scan(book, asks, 20, 5, 3).unwrap(), Vec::new());
    }
}
