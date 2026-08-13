//! Conservation over the amount cells: the shard's supply accumulator
//! equals the sum of its cells through same-shard transfers, and moves
//! only on mint and cross-shard legs.

use hyperscale_vm_effects::{
    Address, AddressClass, Hash32, RoleId, SubstateKey, TestHasher, Value, child_key,
};
use hyperscale_vm_kernel::{
    DeltaOp, MemoryStore, SupplyLedger, TxHash, WorkingStore, decode_amount, encode_amount,
};

const VAULT: RoleId = RoleId(1);

fn vault(owner: u8, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([owner; 31], AddressClass::Component),
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell_total(store: &mut MemoryStore, cells: &[SubstateKey]) -> u128 {
    cells
        .iter()
        .map(|key| {
            store
                .read(*key)
                .unwrap()
                .map_or(0, |cell| decode_amount(&cell).unwrap())
        })
        .sum()
}

#[test]
fn supply_tracks_cells_through_transfers_and_cross_shard_legs() {
    let resource = Address::new([0xEE; 31], AddressClass::Component);
    let alice = vault(1, resource);
    let bob = vault(2, resource);
    let cells = [alice, bob];

    let mut store = MemoryStore::new();
    let mut supply = SupplyLedger::new();

    // Mint: the only same-shard event that credits supply.
    store.write(alice, encode_amount(100).to_vec()).unwrap();
    supply.credit(resource, 100).unwrap();
    assert_eq!(cell_total(&mut store, &cells), supply.amount(resource));

    // A same-shard transfer: reserve-settle out of one cell, delta into
    // the other. Supply is untouched and conservation holds.
    let verdicts = store.judge_and_hold(&[(tx(1), alice, 30)]).unwrap();
    assert!(verdicts[&(tx(1), alice)].is_feasible());
    store.settle(alice, tx(1)).unwrap();
    store.queue_delta(bob, DeltaOp::Add(30)).unwrap();
    store.commit_deltas().unwrap();
    assert_eq!(cell_total(&mut store, &cells), 100);
    assert_eq!(supply.amount(resource), 100);

    // An outbound cross-shard leg: the settled amount leaves the shard,
    // and the ledger debits with it.
    let verdicts = store.judge_and_hold(&[(tx(2), alice, 20)]).unwrap();
    assert!(verdicts[&(tx(2), alice)].is_feasible());
    let outbound = store.settle(alice, tx(2)).unwrap();
    supply.debit(resource, outbound).unwrap();
    assert_eq!(cell_total(&mut store, &cells), 80);
    assert_eq!(supply.amount(resource), 80);

    // The matching inbound leg on another shard would credit 20 there:
    // composing the two ledgers restores the original total.
    let mut remote = SupplyLedger::new();
    remote.credit(resource, outbound).unwrap();
    assert_eq!(supply.compose(&remote).unwrap().amount(resource), 100);
}
