//! The overlay differential corpus: an [`OverlayStore`] over a shared
//! base is observationally identical to a plain [`MemoryStore`] holding
//! the same state — op by op, access log included, and after collapse.
//!
//! Every generated sequence runs against both stores; a merge point
//! between the two phases pushes the first phase's effects into the
//! committed layer, so scans and reads exercise all three layers with
//! writes and tombstones in each. Locked reads are exempt by design —
//! they pin to the base, not to layered state — and are covered by the
//! overlay's unit tests.

use std::sync::Arc;

use hyperscale_vm_effects::{Address, Hash32, RoleId, SubstateKey, TestHasher, child_key};
use hyperscale_vm_kernel::{
    DeltaOp, MemoryStore, OverlayStore, SubstateStore, TxHash, encode_amount,
};
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof, proptest};

const OWNERS: [Address; 2] = [Address([0xA1; 16]), Address([0xA2; 16])];
const COLLECTIONS: [RoleId; 2] = [RoleId(3), RoleId(4)];

fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, Address([byte; 16]), RoleId(1), &[])
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

/// One store operation over small key, order, and amount domains.
#[derive(Clone, Debug)]
enum Op {
    Read(u8),
    Write(u8, Vec<u8>),
    Remove(u8),
    Lock(u8),
    QueueDelta(u8, DeltaOp),
    CommitDeltas,
    EntryRead(u8, u8, u128),
    EntryWrite(u8, u8, u128, Vec<u8>),
    EntryRemove(u8, u8, u128),
    Scan(u8, u8, u128, u128, u32),
    Judge(u8, u8, u128),
    Settle(u8, u8),
    Release(u8, u8),
}

fn arb_op() -> impl Strategy<Value = Op> {
    let key = 0u8..6;
    let owner = 0u8..2;
    let collection = 0u8..2;
    let order = 0u128..10;
    let value = vec(any::<u8>(), 0..3);
    let amount = (0u64..200).prop_map(u128::from);
    let holder = 0u8..3;
    prop_oneof![
        key.clone().prop_map(Op::Read),
        (key.clone(), value.clone()).prop_map(|(k, v)| Op::Write(k, v)),
        // Amount-encoded writes keep the delta and reservation paths
        // exercisable on the same cells.
        (key.clone(), amount.clone()).prop_map(|(k, a)| Op::Write(k, encode_amount(a).to_vec())),
        key.clone().prop_map(Op::Remove),
        key.clone().prop_map(Op::Lock),
        (key.clone(), any::<bool>(), amount.clone()).prop_map(|(k, add, a)| {
            Op::QueueDelta(
                k,
                if add {
                    DeltaOp::Add(a)
                } else {
                    DeltaOp::Sub(a)
                },
            )
        }),
        Just(Op::CommitDeltas),
        (owner.clone(), collection.clone(), order.clone())
            .prop_map(|(o, c, ord)| Op::EntryRead(o, c, ord)),
        (owner.clone(), collection.clone(), order.clone(), value)
            .prop_map(|(o, c, ord, v)| Op::EntryWrite(o, c, ord, v)),
        (owner.clone(), collection.clone(), order.clone())
            .prop_map(|(o, c, ord)| Op::EntryRemove(o, c, ord)),
        (owner, collection, order.clone(), order, 0u32..6)
            .prop_map(|(o, c, lo, hi, cap)| Op::Scan(o, c, lo, hi, cap)),
        (holder.clone(), key.clone(), amount).prop_map(|(t, k, a)| Op::Judge(t, k, a)),
        (holder.clone(), key.clone()).prop_map(|(t, k)| Op::Settle(t, k)),
        (holder, key).prop_map(|(t, k)| Op::Release(t, k)),
    ]
}

/// Apply one operation, folding the outcome to a comparable string.
fn apply<S: Store>(store: &mut S, op: &Op) -> String {
    match op {
        Op::Read(k) => format!("{:?}", store.sub().read(cell(*k))),
        Op::Write(k, v) => format!("{:?}", store.sub().write(cell(*k), v.clone())),
        Op::Remove(k) => format!("{:?}", store.sub().remove(cell(*k))),
        Op::Lock(k) => format!("{:?}", store.sub().lock(cell(*k))),
        Op::QueueDelta(k, op) => format!("{:?}", store.sub().queue_delta(cell(*k), *op)),
        Op::CommitDeltas => format!("{:?}", store.commit_deltas()),
        Op::EntryRead(o, c, ord) => format!(
            "{:?}",
            store
                .sub()
                .entry_read(OWNERS[*o as usize], COLLECTIONS[*c as usize], *ord)
        ),
        Op::EntryWrite(o, c, ord, v) => format!(
            "{:?}",
            store.sub().entry_write(
                OWNERS[*o as usize],
                COLLECTIONS[*c as usize],
                *ord,
                v.clone()
            )
        ),
        Op::EntryRemove(o, c, ord) => format!(
            "{:?}",
            store
                .sub()
                .entry_remove(OWNERS[*o as usize], COLLECTIONS[*c as usize], *ord)
        ),
        Op::Scan(o, c, lo, hi, cap) => format!(
            "{:?}",
            store.sub().scan(
                OWNERS[*o as usize],
                COLLECTIONS[*c as usize],
                *lo,
                *hi,
                *cap
            )
        ),
        Op::Judge(t, k, a) => format!("{:?}", store.judge(&[(tx(*t), cell(*k), *a)])),
        Op::Settle(t, k) => format!("{:?}", store.settle(cell(*k), tx(*t))),
        Op::Release(t, k) => format!("{:?}", store.release(cell(*k), tx(*t))),
    }
}

/// The shared surface of the two stores, for the differential driver.
trait Store {
    fn sub(&mut self) -> &mut dyn SubstateStore;
    fn commit_deltas(&mut self) -> String;
    fn judge(&mut self, requests: &[(TxHash, SubstateKey, u128)]) -> String;
    fn settle(&mut self, key: SubstateKey, tx: TxHash) -> String;
    fn release(&mut self, key: SubstateKey, tx: TxHash) -> String;
}

impl Store for MemoryStore {
    fn sub(&mut self) -> &mut dyn SubstateStore {
        self
    }
    fn commit_deltas(&mut self) -> String {
        format!("{:?}", Self::commit_deltas(self))
    }
    fn judge(&mut self, requests: &[(TxHash, SubstateKey, u128)]) -> String {
        format!("{:?}", self.judge_and_hold(requests))
    }
    fn settle(&mut self, key: SubstateKey, tx: TxHash) -> String {
        format!("{:?}", Self::settle(self, key, tx))
    }
    fn release(&mut self, key: SubstateKey, tx: TxHash) -> String {
        format!("{:?}", Self::release(self, key, tx))
    }
}

impl Store for OverlayStore {
    fn sub(&mut self) -> &mut dyn SubstateStore {
        self
    }
    fn commit_deltas(&mut self) -> String {
        format!("{:?}", Self::commit_deltas(self))
    }
    fn judge(&mut self, requests: &[(TxHash, SubstateKey, u128)]) -> String {
        format!("{:?}", self.judge_and_hold(requests))
    }
    fn settle(&mut self, key: SubstateKey, tx: TxHash) -> String {
        format!("{:?}", Self::settle(self, key, tx))
    }
    fn release(&mut self, key: SubstateKey, tx: TxHash) -> String {
        format!("{:?}", Self::release(self, key, tx))
    }
}

/// A populated base: cells (some amount-encoded), entries, and one held
/// reservation, so layered ops immediately interact with base state.
fn base_store(seed: &[(u8, u128)]) -> MemoryStore {
    let mut base = MemoryStore::new();
    for (index, (k, a)) in seed.iter().enumerate() {
        base.write(cell(*k), encode_amount(*a).to_vec()).unwrap();
        let owner = OWNERS[index % 2];
        let collection = COLLECTIONS[(index / 2) % 2];
        base.entry_write(owner, collection, u128::from(*k) % 10, vec![*k])
            .unwrap();
    }
    if let Some((k, a)) = seed.first() {
        base.write(cell(*k), encode_amount(a.saturating_add(50)).to_vec())
            .unwrap();
        base.judge_and_hold(&[(tx(0), cell(*k), 25)]).unwrap();
    }
    base.clear_log();
    base
}

proptest! {
    #[test]
    fn the_overlay_is_observationally_identical_to_the_clone_based_store(
        seed in vec((0u8..6, (0u64..200).prop_map(u128::from)), 0..6),
        first in vec(arb_op(), 0..24),
        second in vec(arb_op(), 0..24),
    ) {
        let base = base_store(&seed);
        let mut reference = base.clone();
        let mut overlay = OverlayStore::new(Arc::new(base));

        for op in &first {
            assert_eq!(apply(&mut overlay, op), apply(&mut reference, op), "{op:?}");
        }
        overlay.merge_active();
        for op in &second {
            assert_eq!(apply(&mut overlay, op), apply(&mut reference, op), "{op:?}");
        }

        // The access logs agree entry for entry.
        assert_eq!(overlay.access_log(), reference.access_log());

        // Layered probes agree with the reference across the domains.
        for k in 0..6u8 {
            assert_eq!(overlay.is_locked(cell(k)), reference.is_locked(cell(k)));
            for t in 0..3u8 {
                assert_eq!(
                    overlay.held_reservation(cell(k), tx(t)),
                    reference.held_reservation(cell(k), tx(t)),
                );
            }
        }
        let overlay_pending: Vec<_> = overlay.pending_deltas().collect();
        let reference_pending: Vec<_> = reference
            .pending_deltas()
            .map(|(key, ops)| (key, ops.to_vec()))
            .collect();
        assert_eq!(overlay_pending, reference_pending);

        // The collapsed overlay is the reference, state for state.
        let collapsed = overlay.collapse();
        let collapsed_cells: Vec<_> = collapsed
            .cells()
            .map(|(key, value)| (key, value.to_vec()))
            .collect();
        let reference_cells: Vec<_> = reference
            .cells()
            .map(|(key, value)| (key, value.to_vec()))
            .collect();
        assert_eq!(collapsed_cells, reference_cells);
        let collapsed_entries: Vec<_> = collapsed
            .collection_entries()
            .map(|(key, value)| (key, value.to_vec()))
            .collect();
        let reference_entries: Vec<_> = reference
            .collection_entries()
            .map(|(key, value)| (key, value.to_vec()))
            .collect();
        assert_eq!(collapsed_entries, reference_entries);
    }
}
