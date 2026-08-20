//! Non-fungibles and hashed entries end to end on both runtimes: mint,
//! transfer, burn, double-mint refusal, and the name registry.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{
    Hash32, TestHasher, Value, admit, collection_id, fresh_id, holdings_collection,
    instance_data_key, order_key,
};
use hyperscale_vm_fixtures::{nf, registry};
use hyperscale_vm_kernel::{MemoryStore, multiply_held_ids};
use hyperscale_vm_types::{
    AbortReason, CollectionId, EffectTarget, Outcome, Presence, TxHash, UnmetCondition,
};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// The unordered collection end to end on both runtimes: bindings land at
/// their hashed orders, a rebind overwrites in place, a mismatched check
/// traps and rolls back, and one drain crank clears the tail.
#[test]
fn the_registry_binds_checks_and_drains_hashed_entries() {
    let world = world();
    let store = MemoryStore::new();

    let bind = |name: u64, value: u128| graph(|b| registry::bind(b, registry_addr(), name, value));
    let check =
        |name: u64, expected: u128| graph(|b| registry::check(b, registry_addr(), name, expected));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&bind(7, 700), TxHash(Hash32([0x51; 32]))),
            (&bind(9, 900), TxHash(Hash32([0x52; 32]))),
            (&bind(7, 701), TxHash(Hash32([0x53; 32]))),
            (&check(7, 701), TxHash(Hash32([0x54; 32]))),
            (&check(9, 901), TxHash(Hash32([0x55; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    assert!(
        matches!(results[2], TxResult::Completed(_)),
        "a rebind lands"
    );
    assert!(
        matches!(results[3], TxResult::Completed(_)),
        "a true check passes"
    );
    assert_eq!(
        results[4],
        TxResult::Trapped(AbortReason::Unreachable),
        "a false check traps"
    );

    // Exactly two bindings, each at the order its name hashes to, holding
    // the last value bound — the rebind overwrote in place.
    let names = collection_id(&TestHasher, registry_addr(), registry::NAMES, &[]);
    let order_of = |name: u64| {
        order_key(
            &TestHasher,
            registry_addr(),
            registry::NAMES,
            &[Value::U64(name).canonical_bytes()],
        )
    };
    let entries: BTreeMap<u128, Vec<u8>> = store
        .collection_entries()
        .filter(|(key, _)| (key.owner, key.collection) == (registry_addr().into(), names))
        .map(|(key, value)| (key.order, value.to_vec()))
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[&order_of(7)], 701u128.to_le_bytes().to_vec());
    assert_eq!(entries[&order_of(9)], 900u128.to_le_bytes().to_vec());

    // One crank from the bottom of the hash order clears everything —
    // two entries against a cap of eight.
    assert!(u32::try_from(entries.len()).unwrap() <= registry::DRAIN_CAP);
    let drain = graph(|b| registry::drain(b, registry_addr(), 0));
    let (results, store) = run_both(&world, &store, &[(&drain, TxHash(Hash32([0x56; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        store.collection_entries().count(),
        0,
        "the drain left nothing"
    );
}

#[test]
fn non_fungibles_mint_transfer_and_burn_end_to_end() {
    let world = world();
    let store = MemoryStore::new();

    let resource = nf_resource();
    let holder_a = nf_holder(7);
    let holder_b = nf_holder(8);
    let a_holdings = holdings_collection(&TestHasher, holder_a, resource);
    let b_holdings = holdings_collection(&TestHasher, holder_b, resource);
    let holdings = [(holder_a.into(), a_holdings), (holder_b.into(), b_holdings)];
    let held = |store: &MemoryStore, collection: CollectionId| -> Vec<u64> {
        store
            .collection_entries()
            .filter(|(key, _)| key.collection == collection)
            .map(|(key, _)| u64::try_from(key.order).unwrap())
            .collect()
    };

    // Two mints in one manifest — distinct nodes, distinct fresh ids —
    // both deposited to A.
    let mint_to_a = graph(|b| {
        let first = nf::mint(b, nf_issuer())?;
        nf::deposit(b, holder_a, first)?;
        let second = nf::mint(b, nf_issuer())?;
        nf::deposit(b, holder_a, second)
    });
    let (results, store) = run_both(&world, &store, &[(&mint_to_a, TxHash(Hash32([0x61; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));

    // Two instances held by A, each with its data cell under the issuer
    // holding the id it was minted with.
    let ids = held(&store, a_holdings);
    assert_eq!(ids.len(), 2, "two mints, two holdings");
    for &id in &ids {
        let data = instance_data_key(&TestHasher, nf_issuer(), resource, id);
        assert_eq!(
            store.cells().find(|(key, _)| *key == data).map(|(_, v)| v),
            Some(id.to_le_bytes().as_slice()),
            "the mint wrote the instance's data cell"
        );
    }
    assert_eq!(multiply_held_ids(&store, &holdings), Vec::<u128>::new());

    // Move the first id to B; a withdrawal of an id nobody holds traps;
    // burn the second id.
    let absent = (0..=u64::MAX).find(|id| !ids.contains(id)).unwrap();
    let transfer = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[ids[0]])?;
        nf::deposit(b, holder_b, moved)
    });
    let unheld = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[absent])?;
        nf::deposit(b, holder_b, moved)
    });
    let burn = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[ids[1]])?;
        nf::burn(b, nf_issuer(), moved)
    });
    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&transfer, TxHash(Hash32([0x63; 32]))),
            (&unheld, TxHash(Hash32([0x64; 32]))),
            (&burn, TxHash(Hash32([0x65; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        results[1],
        // The kernel's own class, not a guest's assertion: taking an
        // instance is where the removal happens, so it is where the
        // refusal belongs.
        TxResult::Trapped(AbortReason::InstanceNotHeld),
        "moving an id you do not hold aborts"
    );
    assert!(matches!(results[2], TxResult::Completed(_)));

    // A holds nothing, B holds exactly the moved id, no id is anywhere
    // twice, and the burned instance's data cell survives unmoved.
    assert_eq!(held(&store, a_holdings), Vec::<u64>::new());
    assert_eq!(held(&store, b_holdings), vec![ids[0]]);
    assert_eq!(multiply_held_ids(&store, &holdings), Vec::<u128>::new());
    let burned = instance_data_key(&TestHasher, nf_issuer(), resource, ids[1]);
    assert!(
        store.cells().any(|(key, _)| key == burned),
        "burn consumes the edge and leaves the data where the mint put it"
    );
}

/// A mint creates an instance's data cell; it never rewrites one.
///
/// The fresh id is derived from the manifest's identity and the minting
/// node's position, so two mints agreeing on one is not something a
/// sender can arrange — which leaves putting the cell where this mint's
/// own derivation lands as the only way to witness the requirement. What
/// answers is the declared precondition, judged by the shard holding the
/// leaf before any body runs.
#[test]
fn a_mint_onto_an_instance_already_there_is_refused() {
    let world = world();

    let mint = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        nf::deposit(b, nf_holder(7), minted)
    });

    let admitted = admit(&mint, ALICE, &world.0, &world.1, &TestHasher).unwrap();
    let id = fresh_id(&TestHasher, admitted.identity(), 0, 0);
    let data = instance_data_key(&TestHasher, nf_issuer(), nf_resource(), id);

    let mut store = MemoryStore::new();
    store.write(data, id.to_le_bytes().to_vec()).unwrap();

    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&mint, TxHash(Hash32([0x66; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(data),
                required: Presence::Absent,
            },
        })],
        "an instance already there is a refusal, never an overwrite"
    );
}
