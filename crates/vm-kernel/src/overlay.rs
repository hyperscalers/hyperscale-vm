//! The overlay store: a transaction's state surface as layers over a
//! shared committed base.
//!
//! An [`OverlayStore`] holds an immutable base (`Arc<MemoryStore>`), a
//! `committed` layer carrying what earlier transactions in the same
//! conflict group threaded, and an `active` layer carrying the current
//! transaction's effects. Every mutation lands in `active`; reads fall
//! through `active`, then `committed`, then the base. Threading a group is
//! [`OverlayStore::merge_active`]; rolling a failed transaction back is
//! [`OverlayStore::discard_active`]; neither touches the base, so the cost
//! of every store operation is bounded by overlay size, never by state
//! size.
//!
//! Snapshot reads are the exception to layering: they resolve against the
//! base alone, which is the batch baseline — the attested version pinned
//! reads see regardless of what the group has threaded on top.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_vm_effects::{Address, EffectTarget, ModeKind, RoleId, SubstateKey};

use crate::modes::{
    DeltaOp, Feasibility, TxHash, decode_amount, encode_amount, fold_deltas, judge,
};
use crate::store::{Access, AppliedDelta, MemoryStore, StoreError, SubstateStore};

/// A collection's layered entry changes: `None` values are tombstones.
type EntryChanges = BTreeMap<u128, Option<Vec<u8>>>;

/// One overlay layer. `None` values are tombstones: a removal of the
/// corresponding base or lower-layer state.
#[derive(Clone, Debug, Default)]
struct Layer {
    cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    entries: BTreeMap<(Address, RoleId), EntryChanges>,
    locked: BTreeSet<SubstateKey>,
    pending_deltas: BTreeMap<SubstateKey, Vec<DeltaOp>>,
    held: BTreeMap<SubstateKey, BTreeMap<TxHash, Option<u128>>>,
}

/// Layered state over a shared committed base.
///
/// Cloning is cheap — the base and the committed layer are shared by
/// reference-count, and the active layer is empty at every clone point the
/// executor uses — which is what makes per-transaction rollback and the
/// group's threading O(overlay), not O(store).
#[derive(Clone, Debug)]
pub struct OverlayStore {
    base: Arc<MemoryStore>,
    committed: Arc<Layer>,
    active: Layer,
    log: Vec<Access>,
}

impl OverlayStore {
    /// An empty overlay over `base`.
    #[must_use]
    pub fn new(base: Arc<MemoryStore>) -> Self {
        Self {
            base,
            committed: Arc::new(Layer::default()),
            active: Layer::default(),
            log: Vec::new(),
        }
    }

    /// The shared base: the batch baseline snapshot reads resolve against.
    #[must_use]
    pub const fn base(&self) -> &Arc<MemoryStore> {
        &self.base
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

    fn record(&mut self, target: EffectTarget, kind: ModeKind) {
        self.log.push(Access { target, kind });
    }

    /// Whether a substate is permanently locked, in any layer.
    #[must_use]
    pub fn is_locked(&self, key: SubstateKey) -> bool {
        self.active.locked.contains(&key)
            || self.committed.locked.contains(&key)
            || self.base.is_locked(key)
    }

    fn reject_locked(&self, key: SubstateKey) -> Result<(), StoreError> {
        if self.is_locked(key) {
            return Err(StoreError::Locked(key));
        }
        Ok(())
    }

    /// The effective value of a point cell: active over committed over
    /// base.
    fn cell_value(&self, key: SubstateKey) -> Option<Vec<u8>> {
        if let Some(change) = self.active.cells.get(&key) {
            return change.clone();
        }
        if let Some(change) = self.committed.cells.get(&key) {
            return change.clone();
        }
        self.base.cells.get(&key).cloned()
    }

    /// The effective pre-active value of a point cell: what the cell held
    /// before this transaction touched it.
    #[must_use]
    pub fn pre_active_cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        if let Some(change) = self.committed.cells.get(&key) {
            return change.clone();
        }
        self.base.cells.get(&key).cloned()
    }

    /// The active layer's cell changes, in canonical key order; `None` is
    /// a removal.
    pub fn active_cells(&self) -> impl Iterator<Item = (SubstateKey, Option<&[u8]>)> + '_ {
        self.active
            .cells
            .iter()
            .map(|(key, change)| (*key, change.as_deref()))
    }

    /// The effective pre-active value of an ordered-collection entry.
    #[must_use]
    pub fn pre_active_entry(
        &self,
        owner: Address,
        collection: RoleId,
        order: u128,
    ) -> Option<Vec<u8>> {
        if let Some(change) = self
            .committed
            .entries
            .get(&(owner, collection))
            .and_then(|entries| entries.get(&order))
        {
            return change.clone();
        }
        self.base
            .entries
            .get(&(owner, collection))
            .and_then(|entries| entries.get(&order))
            .cloned()
    }

    /// The active layer's entry changes, in canonical order; `None` is a
    /// removal.
    pub fn active_entries(
        &self,
    ) -> impl Iterator<Item = ((Address, RoleId, u128), Option<&[u8]>)> + '_ {
        self.active
            .entries
            .iter()
            .flat_map(|((owner, collection), entries)| {
                entries
                    .iter()
                    .map(|(order, change)| ((*owner, *collection, *order), change.as_deref()))
            })
    }

    fn entry_value(&self, owner: Address, collection: RoleId, order: u128) -> Option<Vec<u8>> {
        if let Some(change) = self
            .active
            .entries
            .get(&(owner, collection))
            .and_then(|entries| entries.get(&order))
        {
            return change.clone();
        }
        self.pre_active_entry(owner, collection, order)
    }

    fn committed_amount(&self, key: SubstateKey) -> Result<u128, StoreError> {
        match self.cell_value(key) {
            Some(cell) => Ok(decode_amount(&cell)?),
            None => Ok(0),
        }
    }

    /// The effective holds on a cell: base holds with both layers' changes
    /// applied.
    fn effective_holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        let mut holds = self.base.held.get(&key).cloned().unwrap_or_default();
        for layer in [self.committed.as_ref(), &self.active] {
            if let Some(changes) = layer.held.get(&key) {
                for (tx, change) in changes {
                    match change {
                        Some(amount) => {
                            holds.insert(*tx, *amount);
                        }
                        None => {
                            holds.remove(tx);
                        }
                    }
                }
            }
        }
        holds
    }

    /// The reservation amount `tx` holds on `key`, if any.
    #[must_use]
    pub fn held_reservation(&self, key: SubstateKey, tx: TxHash) -> Option<u128> {
        for layer in [&self.active, self.committed.as_ref()] {
            if let Some(change) = layer.held.get(&key).and_then(|holds| holds.get(&tx)) {
                return *change;
            }
        }
        self.base.held_reservation(key, tx)
    }

    /// Deltas queued but not yet committed, per cell, across both layers.
    /// A threaded group commits before merging, so in the executor's use
    /// the committed layer's queue is always empty; the merged view keeps
    /// the overlay faithful regardless.
    fn pending_map(&self) -> BTreeMap<SubstateKey, Vec<DeltaOp>> {
        let mut merged = self.committed.pending_deltas.clone();
        for (key, ops) in &self.active.pending_deltas {
            merged.entry(*key).or_default().extend(ops.iter().copied());
        }
        merged
    }

    /// Deltas queued but not yet committed, per cell.
    pub fn pending_deltas(&self) -> impl Iterator<Item = (SubstateKey, Vec<DeltaOp>)> + '_ {
        self.pending_map().into_iter()
    }

    /// Judge a batch of reservation requests against effective state,
    /// holding the feasible ones in the active layer. Semantics mirror
    /// [`MemoryStore::judge_and_hold`] exactly.
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
            let committed = self.committed_amount(key)?;
            let held_total = self
                .effective_holds(key)
                .values()
                .try_fold(0u128, |acc, amount| acc.checked_add(*amount))
                .ok_or(StoreError::HeldExceedsCommitted(key))?;
            let available = committed
                .checked_sub(held_total)
                .ok_or(StoreError::HeldExceedsCommitted(key))?;
            for (tx, verdict) in judge(available, &batch) {
                if verdict.is_feasible() {
                    let amount = batch
                        .iter()
                        .find(|(candidate, _)| *candidate == tx)
                        .map_or(0, |(_, amount)| *amount);
                    self.active
                        .held
                        .entry(key)
                        .or_default()
                        .insert(tx, Some(amount));
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
            .held_reservation(key, tx)
            .ok_or(StoreError::MissingReservation { tx, key })?;
        // The hold drops before the decrement is checked, mirroring
        // MemoryStore::settle.
        self.active.held.entry(key).or_default().insert(tx, None);
        let committed = self.committed_amount(key)?;
        let after = committed
            .checked_sub(amount)
            .ok_or(StoreError::HeldExceedsCommitted(key))?;
        self.active
            .cells
            .insert(key, Some(encode_amount(after).to_vec()));
        Ok(amount)
    }

    /// Release a held reservation without touching the cell. Returns the
    /// released amount.
    ///
    /// # Errors
    ///
    /// [`StoreError::MissingReservation`] if `tx` holds nothing on `key`.
    pub fn release(&mut self, key: SubstateKey, tx: TxHash) -> Result<u128, StoreError> {
        let amount = self
            .held_reservation(key, tx)
            .ok_or(StoreError::MissingReservation { tx, key })?;
        self.active.held.entry(key).or_default().insert(tx, None);
        Ok(amount)
    }

    /// Fold every queued delta into its cell, atomically: all folds are
    /// computed before any cell changes, so an error leaves both state and
    /// the queue untouched.
    ///
    /// # Errors
    ///
    /// Any fold or decode failure, verbatim from the offending cell.
    pub fn commit_deltas(&mut self) -> Result<Vec<AppliedDelta>, StoreError> {
        let pending = self.pending_map();
        let mut applied = Vec::with_capacity(pending.len());
        for (key, ops) in &pending {
            let before = match self.cell_value(*key) {
                Some(cell) => decode_amount(&cell)?,
                None => 0,
            };
            let after = fold_deltas(before, ops)?;
            applied.push(AppliedDelta {
                key: *key,
                before,
                after,
            });
        }
        for outcome in &applied {
            self.active
                .cells
                .insert(outcome.key, Some(encode_amount(outcome.after).to_vec()));
        }
        self.active.pending_deltas.clear();
        if !self.committed.pending_deltas.is_empty() {
            Arc::make_mut(&mut self.committed).pending_deltas.clear();
        }
        Ok(applied)
    }

    /// Fold the active layer into the committed layer: the transaction's
    /// effects become part of what the group has threaded. In-place when
    /// the committed layer is unshared; a shared layer is copied first.
    pub fn merge_active(&mut self) {
        let committed = Arc::make_mut(&mut self.committed);
        let active = std::mem::take(&mut self.active);
        committed.cells.extend(active.cells);
        for (collection, entries) in active.entries {
            committed
                .entries
                .entry(collection)
                .or_default()
                .extend(entries);
        }
        committed.locked.extend(active.locked);
        for (key, ops) in active.pending_deltas {
            committed.pending_deltas.entry(key).or_default().extend(ops);
        }
        for (key, holds) in active.held {
            committed.held.entry(key).or_default().extend(holds);
        }
    }

    /// Drop the active layer: the transaction never happened. The
    /// committed layer and the base are untouched.
    pub fn discard_active(&mut self) {
        self.active = Layer::default();
    }

    /// Collapse the overlay into a plain store: the base with both layers
    /// applied and a clear access log. The base is taken over when
    /// unshared, copied otherwise.
    #[must_use]
    pub fn collapse(self) -> MemoryStore {
        let mut store = Arc::try_unwrap(self.base).unwrap_or_else(|shared| (*shared).clone());
        let committed = Arc::try_unwrap(self.committed).unwrap_or_else(|shared| (*shared).clone());
        for layer in [committed, self.active] {
            for (key, change) in layer.cells {
                match change {
                    Some(value) => {
                        store.cells.insert(key, value);
                    }
                    None => {
                        store.cells.remove(&key);
                    }
                }
            }
            for (collection, entries) in layer.entries {
                for (order, change) in entries {
                    match change {
                        Some(value) => {
                            store
                                .entries
                                .entry(collection)
                                .or_default()
                                .insert(order, value);
                        }
                        None => {
                            if let Some(existing) = store.entries.get_mut(&collection) {
                                existing.remove(&order);
                            }
                        }
                    }
                }
            }
            store.locked.extend(layer.locked);
            for (key, ops) in layer.pending_deltas {
                store.pending_deltas.entry(key).or_default().extend(ops);
            }
            for (key, holds) in layer.held {
                for (tx, change) in holds {
                    match change {
                        Some(amount) => {
                            store.held.entry(key).or_default().insert(tx, amount);
                        }
                        None => {
                            if let Some(existing) = store.held.get_mut(&key) {
                                existing.remove(&tx);
                            }
                        }
                    }
                }
            }
        }
        store.clear_log();
        store
    }
}

impl SubstateStore for OverlayStore {
    fn read(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Read);
        Ok(self.cell_value(key))
    }

    fn snapshot(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Snapshot);
        Ok(self.base.cells.get(&key).cloned())
    }

    fn write(&mut self, key: SubstateKey, value: Vec<u8>) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Write);
        self.active.cells.insert(key, Some(value));
        Ok(())
    }

    fn remove(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Write);
        let previous = self.cell_value(key);
        self.active.cells.insert(key, None);
        Ok(previous)
    }

    fn lock(&mut self, key: SubstateKey) -> Result<(), StoreError> {
        if self.cell_value(key).is_none() {
            return Err(StoreError::LockMissing(key));
        }
        self.active.locked.insert(key);
        Ok(())
    }

    fn queue_delta(&mut self, key: SubstateKey, op: DeltaOp) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Delta);
        self.active.pending_deltas.entry(key).or_default().push(op);
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
        Ok(self.entry_value(owner, collection, order))
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
        self.active
            .entries
            .entry((owner, collection))
            .or_default()
            .insert(order, Some(value));
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
        let previous = self.entry_value(owner, collection, order);
        self.active
            .entries
            .entry((owner, collection))
            .or_default()
            .insert(order, None);
        Ok(previous)
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
        let empty_base = BTreeMap::new();
        let empty_layer = BTreeMap::new();
        let mut base = self
            .base
            .entries
            .get(&(owner, collection))
            .unwrap_or(&empty_base)
            .range(lo..=hi)
            .peekable();
        let mut committed = self
            .committed
            .entries
            .get(&(owner, collection))
            .unwrap_or(&empty_layer)
            .range(lo..=hi)
            .peekable();
        let mut active = self
            .active
            .entries
            .get(&(owner, collection))
            .unwrap_or(&empty_layer)
            .range(lo..=hi)
            .peekable();
        // Three-way ordered merge: at each order key the topmost layer
        // that mentions it wins, and tombstones drop the entry without
        // consuming the cap — the result is exactly what a scan of the
        // collapsed store would return.
        let mut hits = Vec::new();
        while hits.len() < limit {
            let next = [
                active.peek().map(|(order, _)| **order),
                committed.peek().map(|(order, _)| **order),
                base.peek().map(|(order, _)| **order),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(order) = next else {
                break;
            };
            let active_hit = active
                .next_if(|(candidate, _)| **candidate == order)
                .map(|(_, change)| change.clone());
            let committed_hit = committed
                .next_if(|(candidate, _)| **candidate == order)
                .map(|(_, change)| change.clone());
            let base_hit = base
                .next_if(|(candidate, _)| **candidate == order)
                .map(|(_, value)| value.clone());
            if let Some(value) = active_hit.or(committed_hit).unwrap_or(base_hit) {
                hits.push((order, value));
            }
        }
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::{Address, Hash32, RoleId, SubstateKey, TestHasher, child_key};

    use super::OverlayStore;
    use crate::modes::{DeltaOp, TxHash, decode_amount, encode_amount};
    use crate::store::{MemoryStore, StoreError, SubstateStore};

    fn key(byte: u8) -> SubstateKey {
        child_key(&TestHasher, Address([byte; 16]), RoleId(1), &[])
    }

    fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    const BOOK: Address = Address([9; 16]);
    const ASKS: RoleId = RoleId(4);

    fn overlay_over(entries: &[(u128, u8)]) -> OverlayStore {
        let mut base = MemoryStore::new();
        for (order, value) in entries {
            base.entry_write(BOOK, ASKS, *order, vec![*value]).unwrap();
        }
        base.clear_log();
        OverlayStore::new(Arc::new(base))
    }

    #[test]
    fn scans_merge_all_three_layers_and_tombstones_free_the_cap() {
        let mut overlay = overlay_over(&[(5, 5), (10, 10), (15, 15), (20, 20)]);
        overlay.entry_remove(BOOK, ASKS, 5).unwrap();
        overlay.entry_write(BOOK, ASKS, 12, vec![12]).unwrap();
        overlay.merge_active();
        overlay.entry_write(BOOK, ASKS, 10, vec![99]).unwrap();
        overlay.entry_remove(BOOK, ASKS, 12).unwrap();

        // Effective entries: 10→99 (active over base), 15, 20; a removed
        // base entry and a removed committed-layer entry never surface,
        // and neither consumes the cap.
        let hits = overlay.scan(BOOK, ASKS, 0, 100, 3).unwrap();
        assert_eq!(hits, vec![(10, vec![99]), (15, vec![15]), (20, vec![20])]);
        // Inverted intervals are empty, not errors.
        assert_eq!(overlay.scan(BOOK, ASKS, 100, 0, 3).unwrap(), Vec::new());
    }

    #[test]
    fn reads_layer_and_snapshots_pin_to_the_base() {
        let mut base = MemoryStore::new();
        let cell = key(1);
        base.write(cell, vec![1]).unwrap();
        base.clear_log();
        let mut overlay = OverlayStore::new(Arc::new(base));

        overlay.write(cell, vec![2]).unwrap();
        overlay.merge_active();
        assert_eq!(overlay.read(cell).unwrap(), Some(vec![2]));
        overlay.write(cell, vec![3]).unwrap();
        assert_eq!(overlay.read(cell).unwrap(), Some(vec![3]));
        // The snapshot resolves against the base, not the layers.
        assert_eq!(overlay.snapshot(cell).unwrap(), Some(vec![1]));

        overlay.remove(cell).unwrap();
        assert_eq!(overlay.read(cell).unwrap(), None);
        assert_eq!(overlay.snapshot(cell).unwrap(), Some(vec![1]));
    }

    #[test]
    fn discard_drops_the_active_layer_only() {
        let mut overlay = overlay_over(&[(5, 5)]);
        let cell = key(2);
        overlay.write(cell, vec![1]).unwrap();
        overlay.merge_active();
        overlay.write(cell, vec![2]).unwrap();
        overlay.entry_remove(BOOK, ASKS, 5).unwrap();
        overlay.discard_active();
        assert_eq!(overlay.read(cell).unwrap(), Some(vec![1]));
        assert_eq!(overlay.scan(BOOK, ASKS, 0, 10, 10).unwrap().len(), 1);
    }

    #[test]
    fn deltas_fold_through_the_layers() {
        let mut overlay = overlay_over(&[]);
        let cell = key(3);
        overlay.write(cell, encode_amount(10).to_vec()).unwrap();
        overlay.merge_active();
        overlay.queue_delta(cell, DeltaOp::Add(5)).unwrap();
        let applied = overlay.commit_deltas().unwrap();
        assert_eq!((applied[0].before, applied[0].after), (10, 15));
        assert_eq!(decode_amount(&overlay.read(cell).unwrap().unwrap()), Ok(15));
        // An underflow leaves state and queue untouched.
        overlay.queue_delta(cell, DeltaOp::Sub(100)).unwrap();
        assert!(overlay.commit_deltas().is_err());
        assert_eq!(decode_amount(&overlay.read(cell).unwrap().unwrap()), Ok(15));
        overlay.queue_delta(cell, DeltaOp::Add(85)).unwrap();
        assert!(overlay.commit_deltas().is_ok());
        assert_eq!(decode_amount(&overlay.read(cell).unwrap().unwrap()), Ok(0));
    }

    #[test]
    fn reservations_layer_over_base_holds() {
        let mut base = MemoryStore::new();
        let vault = key(4);
        base.write(vault, encode_amount(100).to_vec()).unwrap();
        base.judge_and_hold(&[(tx(1), vault, 60)]).unwrap();
        base.clear_log();
        let mut overlay = OverlayStore::new(Arc::new(base));

        // The base hold is visible and constrains a layered judge.
        assert_eq!(overlay.held_reservation(vault, tx(1)), Some(60));
        let verdicts = overlay.judge_and_hold(&[(tx(2), vault, 50)]).unwrap();
        assert!(!verdicts[&(tx(2), vault)].is_feasible());
        let verdicts = overlay.judge_and_hold(&[(tx(3), vault, 40)]).unwrap();
        assert!(verdicts[&(tx(3), vault)].is_feasible());

        // Settling the base hold tombstones it in the layer and decrements
        // the effective cell; the base itself is untouched.
        assert_eq!(overlay.settle(vault, tx(1)), Ok(60));
        assert_eq!(overlay.held_reservation(vault, tx(1)), None);
        assert_eq!(
            decode_amount(&overlay.read(vault).unwrap().unwrap()),
            Ok(40)
        );
        assert_eq!(overlay.base().held_reservation(vault, tx(1)), Some(60));
        assert_eq!(
            overlay.settle(vault, tx(1)),
            Err(StoreError::MissingReservation {
                tx: tx(1),
                key: vault,
            })
        );
        assert_eq!(overlay.release(vault, tx(3)), Ok(40));
        assert_eq!(overlay.held_reservation(vault, tx(3)), None);
    }

    #[test]
    fn locks_layer_and_reject_mutations() {
        let mut overlay = overlay_over(&[]);
        let cell = key(5);
        assert_eq!(overlay.lock(cell), Err(StoreError::LockMissing(cell)));
        overlay.write(cell, vec![7]).unwrap();
        overlay.lock(cell).unwrap();
        overlay.merge_active();
        assert!(overlay.is_locked(cell));
        assert_eq!(overlay.write(cell, vec![8]), Err(StoreError::Locked(cell)));
        assert_eq!(
            overlay.queue_delta(cell, DeltaOp::Add(1)),
            Err(StoreError::Locked(cell))
        );
    }

    #[test]
    fn collapse_applies_both_layers_to_the_base() {
        let mut overlay = overlay_over(&[(5, 5), (10, 10)]);
        let cell = key(6);
        overlay.write(cell, vec![1]).unwrap();
        overlay.entry_remove(BOOK, ASKS, 5).unwrap();
        overlay.merge_active();
        overlay.entry_write(BOOK, ASKS, 7, vec![7]).unwrap();
        overlay.remove(cell).unwrap();

        let mut collapsed = overlay.collapse();
        assert_eq!(collapsed.read(cell).unwrap(), None);
        assert_eq!(
            collapsed.scan(BOOK, ASKS, 0, 100, 10).unwrap(),
            vec![(7, vec![7]), (10, vec![10])]
        );
    }
}
