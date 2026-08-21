//! The kernel's state surfaces and their in-memory, access-recording
//! implementation.
//!
//! Three traits, split where durability ends. [`Substates`] is durable
//! content — point cells and ordered-collection entries, what a state
//! backend serves. [`Baseline`] is committed state as an overlay reads
//! it: substates plus the execution context standing over them —
//! permanent locks and outstanding reservations. [`WorkingStore`] is the
//! mutable surface capability handles drive: mode-specific operations
//! over cells and entries.
//!
//! The [`MemoryStore`] implements all three and records every access as
//! an [`Access`] — the substrate the trace-subset oracle asserts against.
//! What the commutative modes *mean* over any of these surfaces is
//! [`AmountLedger`](crate::AmountLedger)'s, written once and implemented
//! here in terms of this store's own view.

use std::collections::BTreeMap;

use hyperscale_vm_types::{
    AbortReason, Address, CollectionId, EffectTarget, EntryKey, ModeKind, SubstateKey, TxHash,
};

use crate::ledger::{AmountLedger, amount_bytes};
use crate::modes::{DeltaOp, ModeError};

/// Why a store operation rejected. Deterministic: identical on every
/// replica.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
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
    /// One judging batch carrying the same transaction and cell twice.
    /// The verdict map would keep the last and the held amount the first,
    /// so a pair with conflicting amounts would hold one and report the
    /// other; the request is refused instead.
    #[error("{tx:?} requests a reservation on {key:?} twice in one batch")]
    DuplicateRequest {
        /// The repeated transaction.
        tx: TxHash,
        /// The cell it repeats.
        key: SubstateKey,
    },
    /// An amount-cell or fold failure.
    #[error(transparent)]
    Mode(#[from] ModeError),
}

/// Whose fault a store refusal is.
///
/// Decided beside the error, so every consumer — settling a group's
/// reservations, judging movements at finish, replaying them at apply —
/// reads one classification instead of restating the match. What each
/// site *does* with a class stays the site's policy: a floor loss at
/// finish aborts the transaction, while the same class after the judge
/// has cleared every fold is the kernel disagreeing with itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The transaction's own deterministic loss: the floor its movement
    /// or reservation needed is not there. An uncovered debit, and a
    /// cell an exclusive write left below the reservations still
    /// outstanding on it, are the same loss.
    Floor,
    /// The declaring transaction's defect, priced as one: a commutative
    /// mode declared over bytes that are not an amount cell.
    Declaration(ModeError),
    /// The kernel's own defect; stops the batch.
    Defect,
}

impl StoreError {
    /// This refusal, classified.
    #[must_use]
    pub const fn fault(&self) -> Fault {
        match self {
            Self::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)
            | Self::HeldExceedsCommitted(_) => Fault::Floor,
            Self::Mode(error @ ModeError::BadAmountCell(_)) => Fault::Declaration(*error),
            _ => Fault::Defect,
        }
    }
}

impl From<StoreError> for AbortReason {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::MissingReservation { .. } => Self::ReservationMissing,
            StoreError::HeldExceedsCommitted(_) => Self::LedgerInvariant,
            StoreError::DuplicateRequest { .. } => Self::DuplicateReservationRequest,
            StoreError::Mode(mode) => mode.into(),
        }
    }
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

/// The mutable state surface a transaction executes against — working
/// state, not baseline.
///
/// Operations are mode-specific because that is what capability handles
/// invoke: a delta handle can queue deltas and nothing else. Reservations
/// have no trait operation — they are judged before execution and settled
/// after it, outside any guest's reach.
pub trait WorkingStore {
    /// Fresh coherent read of a point cell.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn read(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError>;

    /// Exclusive write of a point cell.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn write(&mut self, key: SubstateKey, value: Vec<u8>) -> Result<(), StoreError>;

    /// Remove a point cell, returning its value.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn remove(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError>;

    /// Queue a delta against an amount cell; folded at commit. An absent
    /// cell folds from zero, which is what lets deposits create balances
    /// without a prior write.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn queue_delta(&mut self, key: SubstateKey, op: DeltaOp) -> Result<(), StoreError>;

    /// Write one ordered-collection entry.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn entry_write(
        &mut self,
        owner: Address,
        collection: CollectionId,
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
        collection: CollectionId,
        order: u128,
    ) -> Result<Option<Vec<u8>>, StoreError>;

    /// The entries of a collection interval in ascending order, truncated
    /// at `cap` entries — the cap is the range effect's declared bound, so
    /// touching beyond it is not expressible through this surface. An
    /// inverted interval is empty.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`].
    fn entries_in_range(
        &mut self,
        owner: Address,
        collection: CollectionId,
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

/// Durable substate content: point cells and ordered-collection entries,
/// nothing execution-scoped.
///
/// The contract a state backend implements. Every read is of committed
/// content only.
pub trait Substates: Send + Sync {
    /// The committed value of a point cell.
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>>;

    /// Committed entries of an ordered collection within `[lo, hi]`,
    /// ascending by order key, at most `limit` of them.
    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)>;
}

impl<T: Substates + ?Sized> Substates for std::sync::Arc<T> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        T::cell(self, key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        T::entries_in_range(self, owner, collection, lo, hi, limit)
    }
}

impl<T: Substates + ?Sized> Substates for &T {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        T::cell(self, key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        T::entries_in_range(self, owner, collection, lo, hi, limit)
    }
}

/// Committed state as an overlay's baseline reads it: durable content
/// plus the execution context standing over it — the reservations
/// outstanding on each cell.
///
/// Holds are execution context, not backend state, which is why the
/// composite is a separate trait: [`MemoryStore`] implements it whole
/// for the kernel suite, while an embedder composes it from a
/// [`Substates`] backend and its own hold tracking. Pending deltas and
/// access logs are working state, not baseline.
pub trait Baseline: Substates + std::fmt::Debug {
    /// Every outstanding reservation on `key`.
    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128>;

    /// The reservation `tx` holds on `key`, if any.
    fn held_reservation(&self, key: SubstateKey, tx: TxHash) -> Option<u128> {
        self.holds(key).get(&tx).copied()
    }
}

impl Substates for MemoryStore {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if lo > hi {
            return Vec::new();
        }
        self.entries
            .get(&(owner, collection))
            .into_iter()
            .flat_map(|entries| entries.range(lo..=hi))
            .take(limit)
            .map(|(order, value)| (*order, value.clone()))
            .collect()
    }
}

impl Baseline for MemoryStore {
    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        self.held.get(&key).cloned().unwrap_or_default()
    }

    fn held_reservation(&self, key: SubstateKey, tx: TxHash) -> Option<u128> {
        Self::held_reservation(self, key, tx)
    }
}

/// The in-memory base store: seeded and committed state.
///
/// Records nothing. Execution runs over an [`crate::OverlayStore`], which
/// owns the access log the trace-subset oracle reads — so a base wrapped
/// in one starts clean by construction, and seeding a fixture leaves no
/// accesses to scrub.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    pub(crate) cells: BTreeMap<SubstateKey, Vec<u8>>,
    pub(crate) entries: BTreeMap<(Address, CollectionId), BTreeMap<u128, Vec<u8>>>,
    pub(crate) pending_deltas: BTreeMap<SubstateKey, Vec<DeltaOp>>,
    pub(crate) held: BTreeMap<SubstateKey, BTreeMap<TxHash, u128>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            entries: BTreeMap::new(),
            pending_deltas: BTreeMap::new(),
            held: BTreeMap::new(),
        }
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
    pub fn collection_entries(&self) -> impl Iterator<Item = (EntryKey, &[u8])> + '_ {
        self.entries
            .iter()
            .flat_map(|((owner, collection), entries)| {
                entries.iter().map(|(order, value)| {
                    let key = EntryKey {
                        owner: *owner,
                        collection: *collection,
                        order: *order,
                    };
                    (key, value.as_slice())
                })
            })
    }
}

impl AmountLedger for MemoryStore {
    fn set_amount(&mut self, key: SubstateKey, amount: u128) {
        match amount_bytes(amount) {
            Some(cell) => {
                self.cells.insert(key, cell);
            }
            None => {
                self.cells.remove(&key);
            }
        }
    }

    fn set_hold(&mut self, key: SubstateKey, tx: TxHash, amount: Option<u128>) {
        match amount {
            Some(amount) => {
                self.held.entry(key).or_default().insert(tx, amount);
            }
            None => {
                if let Some(holds) = self.held.get_mut(&key) {
                    holds.remove(&tx);
                }
            }
        }
    }

    fn note(&mut self, _target: EffectTarget, _kind: ModeKind) {}

    fn queued(&self) -> BTreeMap<SubstateKey, Vec<DeltaOp>> {
        self.pending_deltas.clone()
    }

    fn clear_queued(&mut self) {
        self.pending_deltas.clear();
    }
}

/// The seed surface: what a fixture or a composed genesis writes into a
/// base before anything executes. Unlogged, deliberately — these writes
/// are the world's, not a transaction's.
impl MemoryStore {
    /// Seed a point cell.
    pub fn write(&mut self, key: SubstateKey, value: Vec<u8>) {
        self.cells.insert(key, value);
    }

    /// Seed an ordered-collection entry.
    pub fn entry_write(
        &mut self,
        owner: Address,
        collection: CollectionId,
        order: u128,
        value: Vec<u8>,
    ) {
        self.entries
            .entry((owner, collection))
            .or_default()
            .insert(order, value);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, child_key};
    use hyperscale_vm_types::{
        Address, AddressClass, CollectionId, EffectTarget, ModeKind, SubstateKey, TxHash,
        encode_amount,
    };

    use super::{Access, Baseline, MemoryStore, StoreError, Substates, WorkingStore};
    use crate::ledger::AmountLedger;
    use crate::modes::{DeltaOp, Feasibility, ModeError, decode_amount};
    use crate::overlay::OverlayStore;

    /// The production shape: execution runs over an overlay of the base.
    fn over(base: MemoryStore) -> OverlayStore {
        OverlayStore::new(Arc::new(base) as Arc<dyn Baseline>)
    }

    fn key(byte: u8) -> SubstateKey {
        child_key(
            &TestHasher,
            Address::new([byte; 31], AddressClass::Component),
            SlotId(1),
            &[],
        )
    }

    fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    #[test]
    fn movements_floor_at_outstanding_holds() {
        let mut store = MemoryStore::new();
        let vault = key(9);
        store.write(vault, encode_amount(60).to_vec());
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
    fn deltas_fold_from_virtual_zero_and_commit_atomically() {
        let mut store = over(MemoryStore::new());
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
        store.write(vault, encode_amount(100).to_vec());

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
        assert_eq!(decode_amount(&store.cell(vault).unwrap()), Ok(40));
        assert_eq!(store.release(vault, tx(4)), Ok(40));
        assert_eq!(decode_amount(&store.cell(vault).unwrap()), Ok(40));
        assert_eq!(
            store.settle(vault, tx(1)),
            Err(StoreError::MissingReservation {
                tx: tx(1),
                key: vault,
            })
        );
    }

    #[test]
    fn a_refused_settle_leaves_the_hold_standing() {
        // The ledger invariant is violated — held exceeds committed — so
        // settling must refuse. What it must not do is drop the hold on
        // the way out: an accounted reservation would vanish, and the
        // caller could no longer release it.
        let mut store = MemoryStore::new();
        let vault = key(6);
        store.write(vault, encode_amount(100).to_vec());
        store.judge_and_hold(&[(tx(1), vault, 100)]).unwrap();
        // Drain the cell behind the hold's back.
        store.write(vault, encode_amount(10).to_vec());

        assert_eq!(
            store.settle(vault, tx(1)),
            Err(StoreError::HeldExceedsCommitted(vault))
        );
        assert_eq!(store.held_reservation(vault, tx(1)), Some(100));
        assert_eq!(decode_amount(&store.cell(vault).unwrap()), Ok(10));
        // And the hold is still releasable, which is the point.
        assert_eq!(store.release(vault, tx(1)), Ok(100));
    }

    #[test]
    fn scans_truncate_at_the_cap_and_record_the_interval() {
        let mut store = MemoryStore::new();
        let book = Address::new([9; 31], AddressClass::Component);
        let asks = CollectionId([4; 16]);
        for order in [5u128, 10, 15, 20] {
            store.entry_write(book, asks, order, vec![u8::try_from(order).unwrap()]);
        }
        let mut store = over(store);
        let hits = WorkingStore::entries_in_range(&mut store, book, asks, 5, 20, 3).unwrap();
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
        assert_eq!(
            WorkingStore::entries_in_range(&mut store, book, asks, 20, 5, 3).unwrap(),
            Vec::new()
        );
    }
}
