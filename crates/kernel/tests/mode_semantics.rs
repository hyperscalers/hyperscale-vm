//! The mode-semantics property corpus: outcomes of the commutative modes
//! are invariant under arrival permutation, at the pure-function level and
//! through the store lifecycle.

use std::sync::Arc;

use hyperscale_vm_effects::{Address, AddressClass, Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_kernel::{
    AmountLedger, Baseline, DeltaOp, MemoryStore, OverlayStore, TxHash, WorkingStore,
    decode_amount, encode_amount, fold_deltas, judge,
};
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, proptest};

fn arb_ops() -> impl Strategy<Value = Vec<DeltaOp>> {
    vec(
        (any::<bool>(), any::<u64>()).prop_map(|(add, amount)| {
            if add {
                DeltaOp::Add(u128::from(amount))
            } else {
                DeltaOp::Sub(u128::from(amount))
            }
        }),
        0..24,
    )
}

fn arb_requests() -> impl Strategy<Value = Vec<(TxHash, u128)>> {
    vec((any::<[u8; 32]>(), any::<u64>()), 0..12).prop_map(|raw| {
        let mut requests: Vec<(TxHash, u128)> = Vec::new();
        for (hash, amount) in raw {
            let tx = TxHash(Hash32(hash));
            if !requests.iter().any(|(existing, _)| *existing == tx) {
                requests.push((tx, u128::from(amount)));
            }
        }
        requests
    })
}

proptest! {
    #[test]
    fn delta_folds_are_permutation_invariant(
        committed in any::<u64>(),
        (ops, shuffled) in arb_ops()
            .prop_flat_map(|ops| (Just(ops.clone()), Just(ops).prop_shuffle())),
    ) {
        let committed = u128::from(committed);
        assert_eq!(fold_deltas(committed, &ops), fold_deltas(committed, &shuffled));
    }

    #[test]
    fn feasibility_verdicts_are_permutation_invariant(
        available in any::<u64>(),
        (requests, shuffled) in arb_requests()
            .prop_flat_map(|requests| (Just(requests.clone()), Just(requests).prop_shuffle())),
    ) {
        let available = u128::from(available);
        assert_eq!(judge(available, &requests), judge(available, &shuffled));
    }

    #[test]
    fn the_store_lifecycle_is_arrival_order_invariant(
        (batch, shuffled) in vec(
            ((0u8..4), any::<[u8; 32]>(), any::<bool>(), any::<u32>()),
            0..16,
        )
        .prop_map(|raw| {
            // Distinct hashes; four cells; bounded amounts.
            let mut batch: Vec<(u8, TxHash, bool, u128)> = Vec::new();
            for (cell, hash, add, amount) in raw {
                let tx = TxHash(Hash32(hash));
                if !batch.iter().any(|(_, existing, _, _)| *existing == tx) {
                    batch.push((cell, tx, add, u128::from(amount)));
                }
            }
            batch
        })
        .prop_flat_map(|batch| (Just(batch.clone()), Just(batch).prop_shuffle())),
    ) {
        let run = |batch: &[(u8, TxHash, bool, u128)]| {
            let mut store = OverlayStore::new(Arc::new(MemoryStore::new()) as Arc<dyn Baseline>);
            let cell = |byte: u8| child_key(&TestHasher, Address::new([byte; 31], AddressClass::Component), SlotId(1), &[]);
            for byte in 0u8..4 {
                store.write(cell(byte), encode_amount(1 << 40).to_vec()).unwrap();
            }
            // Deltas queue in arrival order; reservations judge as one batch.
            let mut requests = Vec::new();
            for (byte, tx, add, amount) in batch {
                if *add {
                    store.queue_delta(cell(*byte), DeltaOp::Add(*amount)).unwrap();
                } else {
                    requests.push((*tx, cell(*byte), *amount));
                }
            }
            let verdicts = store.judge_and_hold(&requests).unwrap();
            let deltas = store.commit_deltas().unwrap();
            let cells: Vec<_> = (0u8..4)
                .map(|byte| decode_amount(&store.read(cell(byte)).unwrap().unwrap()).unwrap())
                .collect();
            (verdicts, deltas, cells)
        };
        assert_eq!(run(&batch), run(&shuffled));
    }
}
