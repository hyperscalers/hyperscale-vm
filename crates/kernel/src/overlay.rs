//! The overlay store: a transaction's state surface as layers over a
//! shared committed base.
//!
//! An [`OverlayStore`] holds an immutable base (`Arc<dyn Baseline>`), a
//! `committed` layer carrying what earlier transactions in the same
//! conflict group threaded, and an `active` layer carrying the current
//! transaction's effects. Every mutation lands in `active`; reads fall
//! through `active`, then `committed`, then the base. Threading a group is
//! [`OverlayStore::merge_active`]; rolling a failed transaction back is
//! [`OverlayStore::discard_active`]; neither touches the base, so the cost
//! of every store operation is bounded by overlay size, never by state
//! size.
//!
//! Locked reads are the exception to layering: they resolve against the
//! base alone, which is the batch baseline — the attested version pinned
//! reads see regardless of what the group has threaded on top.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::{Address, CollectionId, EffectTarget, EntryKey, ModeKind, SubstateKey};

use crate::ledger::{AmountLedger, amount_bytes};
use crate::modes::{DeltaOp, TxHash};
use crate::store::{Access, Baseline, MemoryStore, StoreError, Substates, WorkingStore};

/// A collection's layered entry changes: `None` values are tombstones.
type EntryChanges = BTreeMap<u128, Option<Vec<u8>>>;

/// One layer's entry changes within `[lo, hi]`, ascending.
fn layer_range<'a>(
    layer: &'a Layer,
    empty: &'a EntryChanges,
    owner: Address,
    collection: CollectionId,
    lo: u128,
    hi: u128,
) -> std::collections::btree_map::Range<'a, u128, Option<Vec<u8>>> {
    layer
        .entries
        .get(&(owner, collection))
        .unwrap_or(empty)
        .range(lo..=hi)
}

/// One overlay layer. `None` values are tombstones: a removal of the
/// corresponding base or lower-layer state.
#[derive(Clone, Debug, Default)]
struct Layer {
    cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    entries: BTreeMap<(Address, CollectionId), EntryChanges>,
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
    base: Arc<dyn Baseline>,
    committed: Arc<Layer>,
    active: Layer,
    log: Vec<Access>,
}

impl OverlayStore {
    /// An empty overlay over `base`.
    #[must_use]
    pub fn new(base: Arc<dyn Baseline>) -> Self {
        Self {
            base,
            committed: Arc::new(Layer::default()),
            active: Layer::default(),
            log: Vec::new(),
        }
    }

    /// The shared base: the batch baseline locked reads resolve against.
    #[must_use]
    pub const fn base(&self) -> &Arc<dyn Baseline> {
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

    /// Whether a substate is permanently locked. Locks are baseline
    /// state — creation-fixed configuration composed under the base — so
    /// the layers never carry one.
    #[must_use]
    pub fn is_locked(&self, key: SubstateKey) -> bool {
        self.base.is_locked(key)
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
        self.base.cell(key)
    }

    /// The effective pre-active value of a point cell: what the cell held
    /// before this transaction touched it.
    #[must_use]
    pub fn pre_active_cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        if let Some(change) = self.committed.cells.get(&key) {
            return change.clone();
        }
        self.base.cell(key)
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
        collection: CollectionId,
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
            .entries_in_range(owner, collection, order, order, 1)
            .into_iter()
            .next()
            .map(|(_, value)| value)
    }

    /// The active layer's entry changes, in canonical order; `None` is a
    /// removal.
    pub fn active_entries(&self) -> impl Iterator<Item = (EntryKey, Option<&[u8]>)> + '_ {
        self.active
            .entries
            .iter()
            .flat_map(|((owner, collection), entries)| {
                entries.iter().map(|(order, change)| {
                    let key = EntryKey {
                        owner: *owner,
                        collection: *collection,
                        order: *order,
                    };
                    (key, change.as_deref())
                })
            })
    }

    fn entry_value(
        &self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Option<Vec<u8>> {
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

    /// The effective holds on a cell: base holds with both layers' changes
    /// applied.
    fn effective_holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        let mut holds = self.base.holds(key);
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

    /// Record a hold without judging feasibility. The cross-shard form:
    /// a reservation on a key another shard owns is judged there, and
    /// held here only so capability adoption and settlement accounting
    /// see the declared amount.
    pub fn hold_unjudged(&mut self, key: SubstateKey, tx: TxHash, amount: u128) {
        self.record(EffectTarget::Point(key), ModeKind::Reserve);
        self.active
            .held
            .entry(key)
            .or_default()
            .insert(tx, Some(amount));
    }

    /// Drop every queued delta whose cell `keep` refuses, in both layers.
    ///
    /// The cross-shard form: a movement on a key this shard does not own
    /// is an outbound record the owning shard folds, and folding it here
    /// would put a balance in the overlay for a cell this shard holds
    /// none of — which every later member of the conflict group reads.
    pub fn retain_pending_deltas(&mut self, keep: &dyn Fn(SubstateKey) -> bool) {
        self.active.pending_deltas.retain(|key, _| keep(*key));
        if self.committed.pending_deltas.keys().any(|key| !keep(*key)) {
            Arc::make_mut(&mut self.committed)
                .pending_deltas
                .retain(|key, _| keep(*key));
        }
    }

    /// The merged view of an ordered collection over `[lo, hi]`: at each
    /// order key the topmost layer that mentions it wins, and tombstones
    /// drop the entry without consuming the limit — the result is exactly
    /// what a scan of the collapsed store would return.
    ///
    /// The base fetch is bounded: the merge consumes at most `limit` base
    /// entries that become or shadow hits, plus one per layer tombstone in
    /// the range — so that many smallest-order entries always suffice.
    fn merged_entries(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if lo > hi || limit == 0 {
            return Vec::new();
        }
        let empty_layer = EntryChanges::new();
        let tombstones = [self.committed.as_ref(), &self.active]
            .into_iter()
            .flat_map(|layer| layer_range(layer, &empty_layer, owner, collection, lo, hi))
            .filter(|(_, change)| change.is_none())
            .count();
        let mut base = self
            .base
            .entries_in_range(owner, collection, lo, hi, limit.saturating_add(tombstones))
            .into_iter()
            .peekable();
        let mut committed =
            layer_range(&self.committed, &empty_layer, owner, collection, lo, hi).peekable();
        let mut active =
            layer_range(&self.active, &empty_layer, owner, collection, lo, hi).peekable();
        let mut hits = Vec::new();
        while hits.len() < limit {
            let next = [
                active.peek().map(|(order, _)| **order),
                committed.peek().map(|(order, _)| **order),
                base.peek().map(|(order, _)| *order),
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
                .next_if(|(candidate, _)| *candidate == order)
                .map(|(_, value)| value);
            if let Some(value) = active_hit.or(committed_hit).unwrap_or(base_hit) {
                hits.push((order, value));
            }
        }
        hits
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

    /// Whether either layer carries a cell change.
    ///
    /// Locked reads resolve against the base alone, so the overlay a
    /// batch forks its groups from must not have written a cell: if it
    /// had, every group's pinned reads would silently resolve against
    /// post-judge state instead of the attested baseline.
    #[must_use]
    pub fn has_layered_cells(&self) -> bool {
        !self.active.cells.is_empty() || !self.committed.cells.is_empty()
    }

    /// Apply both layers onto `base`, returning the collapsed plain store
    /// with a clear access log — the kernel-suite convenience for
    /// asserting a batch's end state. `base` must be the store this
    /// overlay was built over; integration bases diff the layers instead.
    #[must_use]
    pub fn collapse_onto(&self, mut store: MemoryStore) -> MemoryStore {
        for layer in [self.committed.as_ref(), &self.active] {
            for (key, change) in &layer.cells {
                match change {
                    Some(value) => {
                        store.cells.insert(*key, value.clone());
                    }
                    None => {
                        store.cells.remove(key);
                    }
                }
            }
            for (collection, entries) in &layer.entries {
                for (order, change) in entries {
                    match change {
                        Some(value) => {
                            store
                                .entries
                                .entry(*collection)
                                .or_default()
                                .insert(*order, value.clone());
                        }
                        None => {
                            if let Some(existing) = store.entries.get_mut(collection) {
                                existing.remove(order);
                            }
                        }
                    }
                }
            }
            for (key, ops) in &layer.pending_deltas {
                store
                    .pending_deltas
                    .entry(*key)
                    .or_default()
                    .extend(ops.iter().copied());
            }
            for (key, holds) in &layer.held {
                for (tx, change) in holds {
                    match change {
                        Some(amount) => {
                            store.held.entry(*key).or_default().insert(*tx, *amount);
                        }
                        None => {
                            if let Some(existing) = store.held.get_mut(key) {
                                existing.remove(tx);
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

impl WorkingStore for OverlayStore {
    fn read(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Read);
        Ok(self.cell_value(key))
    }

    fn locked(&mut self, key: SubstateKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.record(EffectTarget::Point(key), ModeKind::Locked);
        // The baseline, deliberately: a locked read is pinned like every
        // snapshot, and a locked cell rejects every mutation, so the
        // layers can hold nothing this read should see.
        Ok(self.base.cell(key))
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

    fn queue_delta(&mut self, key: SubstateKey, op: DeltaOp) -> Result<(), StoreError> {
        self.reject_locked(key)?;
        self.record(EffectTarget::Point(key), ModeKind::Delta);
        self.active.pending_deltas.entry(key).or_default().push(op);
        Ok(())
    }

    fn entry_write(
        &mut self,
        owner: Address,
        collection: CollectionId,
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
        collection: CollectionId,
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

    fn entries_in_range(
        &mut self,
        owner: Address,
        collection: CollectionId,
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
        Ok(self.merged_entries(
            owner,
            collection,
            lo,
            hi,
            usize::try_from(cap).unwrap_or(usize::MAX),
        ))
    }
}

impl AmountLedger for OverlayStore {
    fn set_amount(&mut self, key: SubstateKey, amount: u128) {
        self.active.cells.insert(key, amount_bytes(amount));
    }

    fn set_hold(&mut self, key: SubstateKey, tx: TxHash, amount: Option<u128>) {
        // A dropped hold tombstones rather than erases: the base may
        // carry one this layer has to shadow.
        self.active.held.entry(key).or_default().insert(tx, amount);
    }

    fn note(&mut self, target: EffectTarget, kind: ModeKind) {
        self.record(target, kind);
    }

    fn queued(&self) -> BTreeMap<SubstateKey, Vec<DeltaOp>> {
        self.pending_map()
    }

    fn clear_queued(&mut self) {
        self.active.pending_deltas.clear();
        if !self.committed.pending_deltas.is_empty() {
            Arc::make_mut(&mut self.committed).pending_deltas.clear();
        }
    }
}

impl Substates for OverlayStore {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cell_value(key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        self.merged_entries(owner, collection, lo, hi, limit)
    }
}

impl Baseline for OverlayStore {
    fn is_locked(&self, key: SubstateKey) -> bool {
        Self::is_locked(self, key)
    }

    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        self.effective_holds(key)
    }

    fn held_reservation(&self, key: SubstateKey, tx: TxHash) -> Option<u128> {
        Self::held_reservation(self, key, tx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::{
        Address, AddressClass, CollectionId, Hash32, RoleId, SubstateKey, TestHasher, child_key,
    };

    use super::OverlayStore;
    use crate::ledger::AmountLedger;
    use crate::modes::{DeltaOp, ModeError, TxHash, decode_amount, encode_amount};
    use crate::store::{MemoryStore, StoreError, WorkingStore};

    fn key(byte: u8) -> SubstateKey {
        child_key(
            &TestHasher,
            Address::new([byte; 31], AddressClass::Component),
            RoleId(1),
            &[],
        )
    }

    fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    const BOOK: Address = Address::new([9; 31], AddressClass::Component);
    const ASKS: CollectionId = CollectionId([4; 16]);

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
        let hits = overlay.entries_in_range(BOOK, ASKS, 0, 100, 3).unwrap();
        assert_eq!(hits, vec![(10, vec![99]), (15, vec![15]), (20, vec![20])]);
        // Inverted intervals are empty, not errors.
        assert_eq!(
            overlay.entries_in_range(BOOK, ASKS, 100, 0, 3).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn tombstones_beyond_the_cap_do_not_starve_a_scan() {
        // The base fetch is sized at the cap plus the tombstones in range,
        // so a scan whose interval is mostly deletions still returns a
        // full page of survivors rather than a short one.
        let base: Vec<(u128, u8)> = (0..20u8).map(|order| (u128::from(order), order)).collect();
        let mut overlay = overlay_over(&base);
        for order in 0..16 {
            overlay.entry_remove(BOOK, ASKS, order).unwrap();
        }
        overlay.merge_active();
        // Sixteen tombstones stand between the interval's start and the
        // first survivor, and the cap is two.
        let hits = overlay.entries_in_range(BOOK, ASKS, 0, 100, 2).unwrap();
        assert_eq!(hits, vec![(16, vec![16]), (17, vec![17])]);

        // Deleting in the active layer over a merged one is the same.
        overlay.entry_remove(BOOK, ASKS, 16).unwrap();
        let hits = overlay.entries_in_range(BOOK, ASKS, 0, 100, 2).unwrap();
        assert_eq!(hits, vec![(17, vec![17]), (18, vec![18])]);
    }

    #[test]
    fn reads_layer_and_locked_reads_resolve_against_the_base() {
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
        // The locked read resolves against the base, not the layers.
        assert_eq!(overlay.locked(cell).unwrap(), Some(vec![1]));

        overlay.remove(cell).unwrap();
        assert_eq!(overlay.read(cell).unwrap(), None);
        assert_eq!(overlay.locked(cell).unwrap(), Some(vec![1]));
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
        assert_eq!(
            overlay
                .entries_in_range(BOOK, ASKS, 0, 10, 10)
                .unwrap()
                .len(),
            1
        );
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
        // Draining the cell drops the leaf: a zero balance is an absent
        // cell, not sixteen zero bytes.
        overlay.queue_delta(cell, DeltaOp::Add(85)).unwrap();
        assert!(overlay.commit_deltas().is_ok());
        assert_eq!(overlay.read(cell).unwrap(), None);
        // And crediting it again brings the leaf back.
        overlay.queue_delta(cell, DeltaOp::Add(3)).unwrap();
        assert!(overlay.commit_deltas().is_ok());
        assert_eq!(decode_amount(&overlay.read(cell).unwrap().unwrap()), Ok(3));
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
    fn a_layered_settle_lifts_the_hold_off_the_floor() {
        // The floor a movement is judged against is the effective one, so
        // a hold the layers have settled stops constraining even though
        // the base still carries it.
        let mut base = MemoryStore::new();
        let vault = key(4);
        base.write(vault, encode_amount(60).to_vec()).unwrap();
        base.judge_and_hold(&[(tx(1), vault, 50)]).unwrap();
        base.clear_log();

        let overlay = OverlayStore::new(Arc::new(base.clone()));
        assert_eq!(overlay.judge_movement(vault, 0, 10), Ok(50));
        assert_eq!(
            overlay.judge_movement(vault, 0, 11),
            Err(StoreError::Mode(ModeError::CellUnderflow)),
            "the base's hold still floors the cell"
        );

        let mut settled = OverlayStore::new(Arc::new(base));
        settled.settle(vault, tx(1)).unwrap();
        assert_eq!(settled.judge_movement(vault, 0, 10), Ok(0));
    }

    #[test]
    fn a_refused_settle_leaves_the_hold_standing() {
        // Everything fallible runs before anything mutable, so the hold
        // the settle could not honour is still there to release.
        let mut base = MemoryStore::new();
        let vault = key(7);
        base.write(vault, encode_amount(100).to_vec()).unwrap();
        base.judge_and_hold(&[(tx(1), vault, 100)]).unwrap();
        base.clear_log();
        let mut overlay = OverlayStore::new(Arc::new(base));
        overlay.write(vault, encode_amount(10).to_vec()).unwrap();

        assert_eq!(
            overlay.settle(vault, tx(1)),
            Err(StoreError::HeldExceedsCommitted(vault))
        );
        assert_eq!(overlay.held_reservation(vault, tx(1)), Some(100));
        assert_eq!(overlay.release(vault, tx(1)), Ok(100));
    }

    #[test]
    fn base_locks_reject_overlay_mutations() {
        let mut base = MemoryStore::new();
        let cell = key(5);
        base.write(cell, vec![7]).unwrap();
        base.lock(cell);
        base.clear_log();
        let mut overlay = OverlayStore::new(Arc::new(base));
        assert!(overlay.is_locked(cell));
        assert_eq!(overlay.write(cell, vec![8]), Err(StoreError::Locked(cell)));
        assert_eq!(overlay.remove(cell), Err(StoreError::Locked(cell)));
        assert_eq!(
            overlay.queue_delta(cell, DeltaOp::Add(1)),
            Err(StoreError::Locked(cell))
        );
    }

    #[test]
    fn collapse_applies_both_layers_to_the_base() {
        let mut base = MemoryStore::new();
        for (order, value) in [(5u128, 5u8), (10, 10)] {
            base.entry_write(BOOK, ASKS, order, vec![value]).unwrap();
        }
        base.clear_log();
        let mut overlay = OverlayStore::new(Arc::new(base.clone()));
        let cell = key(6);
        overlay.write(cell, vec![1]).unwrap();
        overlay.entry_remove(BOOK, ASKS, 5).unwrap();
        overlay.merge_active();
        overlay.entry_write(BOOK, ASKS, 7, vec![7]).unwrap();
        overlay.remove(cell).unwrap();

        let mut collapsed = overlay.collapse_onto(base);
        assert_eq!(collapsed.read(cell).unwrap(), None);
        assert_eq!(
            collapsed.entries_in_range(BOOK, ASKS, 0, 100, 10).unwrap(),
            vec![(7, vec![7]), (10, vec![10])]
        );
    }
}
