//! The order book end to end on both runtimes: per-side denominations,
//! interval provisioning, and price-time priority.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{AdmissionError, Hash32, ManifestGraph, TestHasher, admit, fresh_id};
use hyperscale_vm_fixtures::book;
use hyperscale_vm_harness::driver::{amount_of, vault};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{Address, EffectTarget, EntryKey, TxHash, encode_amount};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

fn place_graph() -> ManifestGraph {
    graph(|b| {
        let maker = account::authorize(b, MAKER)?;
        let funds = b.presenting(maker, |b| account::withdraw(b, MAKER, BASE, 50))?;
        book().place_ask(b, 3, funds)
    })
}

/// A book means its configured pair, so each side takes the resource its
/// own vault holds and refuses the other before the transaction exists.
///
/// Both directions matter and they fail differently in the world without
/// the check: an ask escrowed in something the book does not sell stands
/// on the ladder at any price a maker likes, and a fill paid in something
/// the book does not price buys real base with it.
#[test]
fn each_side_of_the_book_takes_only_its_own_resource() {
    let chain = world();
    let refused = |graph: &ManifestGraph, signer| {
        admit(graph, signer, &chain, &TestHasher).expect_err("the book declares which side this is")
    };

    // A maker escrowing quote where the book escrows base.
    let wrong_ask = graph(|b| {
        let maker = account::authorize(b, MAKER)?;
        let funds = b.presenting(maker, |b| account::withdraw(b, MAKER, QUOTE, 50))?;
        book().place_ask(b, 3, funds)
    });
    assert!(
        matches!(
            refused(&wrong_ask, MAKER),
            AdmissionError::WrongDenomination { param: 1, expected, found, .. }
                if expected == BASE.address() && found == QUOTE.address()
        ),
        "an ask escrows the base side"
    );

    // A taker paying base where the book is paid in quote.
    let wrong_fill = graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = b.presenting(taker, |b| account::withdraw(b, TAKER, BASE, 100))?;
        let [bought, refund] = book().fill_asks(b, 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    });
    assert!(
        matches!(
            refused(&wrong_fill, TAKER),
            AdmissionError::WrongDenomination { param: 2, expected, found, .. }
                if expected == QUOTE.address() && found == BASE.address()
        ),
        "a fill pays the quote side"
    );

    // The controls: each side in the resource it is declared in.
    admit(&place_graph(), MAKER, &chain, &TestHasher).expect("an ask in base admits");
    admit(&fill_graph(), TAKER, &chain, &TestHasher).expect("a fill in quote admits");
}

#[test]
fn fill_provisions_the_interval_and_the_fence() {
    let world = world();
    let routing = sharded_routing(&world, &fill_graph());
    let book_set = &routing.per_shard[&shard_of(book())];
    // The write interval and the fence's leaf are the provisioned
    // targets: the escrow legs are deltas and carry nothing.
    assert_eq!(
        book_set.provision_targets(),
        [
            EffectTarget::Point(config_leaf(book())),
            EffectTarget::Range {
                owner: book().into(),
                collection: asks(),
                lo: 3u128 << 64,
                hi: (5u128 << 64) | u128::from(u64::MAX),
                cap: book::FILL_CAP,
            },
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn the_order_book_matches_by_price_time_priority_on_both_runtimes() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(MAKER, BASE), encode_amount(60).to_vec());
    store.write(vault(TAKER, QUOTE), encode_amount(150).to_vec());
    // A resting ask at price 5 from an earlier session, escrow included.
    store.entry_write(
        Address::from(book()),
        asks(),
        (5u128 << 64) | 7,
        encode_amount(10).to_vec(),
    );
    store.write(vault(book(), BASE), encode_amount(10).to_vec());

    let place = place_graph();
    let fill = fill_graph();
    let (results, final_store) = run_both(
        &world,
        &store,
        &[
            (&place, TxHash(Hash32([0x04; 32]))),
            (&fill, TxHash(Hash32([0x05; 32]))),
        ],
    );

    let TxResult::Completed(place_receipt) = &results[0] else {
        panic!("place must complete");
    };
    let TxResult::Completed(fill_receipt) = &results[1] else {
        panic!("fill must complete");
    };

    // The placed ask landed at the declared fresh sequence.
    let admitted = admit(&place, MAKER, &world, &TestHasher).unwrap();
    let seq = fresh_id(&TestHasher, admitted.identity(), 2, 0);
    let placed_ask = EntryKey {
        owner: Address::from(book()),
        collection: asks(),
        order: (3u128 << 64) | u128::from(seq),
    };
    assert_eq!(
        place_receipt.delta.entries.get(&placed_ask),
        Some(&Some(encode_amount(50).to_vec()))
    );

    // The fill: budget 100 at price 3 buys 33 (cost 99), leaving change 1;
    // the price-5 ask is untouched. Partial fill rewrote the entry.
    // The quote vault is credited with what was spent: the change comes
    // off the payment before the rest of it goes in, so the movement is
    // the net and neither half is a number the body wrote down.
    assert_eq!(
        fill_receipt.delta.entries.get(&placed_ask),
        Some(&Some(encode_amount(17).to_vec()))
    );
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(book(), BASE))
            .unwrap()
            .debit,
        33
    );
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(book(), QUOTE))
            .unwrap()
            .credit,
        99
    );
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(book(), QUOTE))
            .unwrap()
            .debit,
        0
    );

    assert_eq!(amount_of(&final_store, vault(TAKER, BASE)), 33);
    assert_eq!(amount_of(&final_store, vault(TAKER, QUOTE)), 51);
    assert_eq!(amount_of(&final_store, vault(book(), BASE)), 27);
    assert_eq!(amount_of(&final_store, vault(book(), QUOTE)), 99);
    assert_eq!(amount_of(&final_store, vault(MAKER, BASE)), 10);
    let entries: BTreeMap<_, _> = final_store
        .collection_entries()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    assert_eq!(entries.get(&placed_ask), Some(&encode_amount(17).to_vec()));
    assert_eq!(
        entries.get(&EntryKey {
            order: (5u128 << 64) | 7,
            ..placed_ask
        }),
        Some(&encode_amount(10).to_vec())
    );
}

/// A book quoting in half a quote subunit fills at a price no integer
/// names.
///
/// Three ticks of half a subunit is one and a half quote per base — a
/// price the old integer ladder could only round to one or two. The
/// ladder itself is unchanged: three is still what the key packs and
/// still what the walk compares.
///
/// Sixty of budget at three halves buys forty, costing exactly sixty.
/// The arithmetic is stated here rather than read off the body.
#[test]
fn a_finer_tick_prices_between_two_integers_on_both_runtimes() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(TAKER, QUOTE), encode_amount(60).to_vec());
    store.entry_write(
        Address::from(fine_book()),
        fine_asks(),
        (3u128 << 64) | 1,
        encode_amount(100).to_vec(),
    );
    store.write(vault(fine_book(), BASE), encode_amount(100).to_vec());

    let fill = graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = b.presenting(taker, |b| account::withdraw(b, TAKER, QUOTE, 60))?;
        let [bought, change] = fine_book().fill_asks(b, 1, 9, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, change)
    });
    let (results, final_store) = run_both(&world, &store, &[(&fill, TxHash(Hash32([0x06; 32])))]);

    let TxResult::Completed(_) = &results[0] else {
        panic!("the fill must complete");
    };
    assert_eq!(
        amount_of(&final_store, vault(TAKER, BASE)),
        40,
        "sixty of quote at one and a half buys forty of base"
    );
    assert_eq!(
        amount_of(&final_store, vault(TAKER, QUOTE)),
        0,
        "and spends the whole budget, because it divides exactly"
    );
}
