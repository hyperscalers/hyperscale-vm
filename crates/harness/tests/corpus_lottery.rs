//! The lottery end to end on both runtimes: the draw settles on the
//! entrant the transaction's randomness picks.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{Hash32, TestHasher, Value, child_key, collection_id, order_key};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_harness::driver::{amount_of, vault};
use hyperscale_vm_kernel::{MemoryStore, Substates};
use hyperscale_vm_sdk::hbor::from_slice;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{CollectionId, PrincipalAddr, TxHash, encode_amount};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// The lottery's entrants collection, as its declarations derive it.
fn tickets() -> CollectionId {
    collection_id(&TestHasher, lottery_addr(), lottery::TICKETS, &[])
}

/// Where an entrant's ticket sits in the collection's order space.
fn ticket_order(who: PrincipalAddr) -> u128 {
    order_key(
        &TestHasher,
        lottery_addr(),
        lottery::TICKETS,
        &[Value::Address(who.address()).canonical_bytes()],
    )
}

/// The lottery's settled-round cell.
/// The settled round, decoded through the package's own type — so what
/// this reads back is what that package says it wrote, rather than a
/// layout restated here.
fn settled_round(store: &MemoryStore) -> Option<lottery::Outcome> {
    draw_cell(store)
        .map(|bytes| from_slice(&bytes).expect("the lottery writes its own outcome type"))
}

fn draw_cell(store: &MemoryStore) -> Option<Vec<u8>> {
    store.cell(child_key(
        &TestHasher,
        lottery_addr(),
        lottery::OUTCOME,
        &[],
    ))
}

/// Randomness reaching a guest, on both runtimes: two entries and a
/// draw that settles on one of them.
///
/// What the result cell holds is the draw itself beside the winner, and
/// the draw is asserted to be the environment's — the whole property the
/// package exists to witness, since a winner is only as unchosen as the
/// value that picked it.
///
/// The winning index is re-derived here from the entrants' hash order
/// rather than read back from the guest, so the assertion is an
/// independent computation of who should have won and not a restatement
/// of what did.
#[test]
fn the_draw_settles_on_the_entrant_the_transactions_randomness_picks() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(BOB, RES_X), encode_amount(150).to_vec())
        .unwrap();

    let enter = |who: PrincipalAddr, stake: u128| {
        graph(move |b| {
            let proof = account::authorize(b, who)?;
            let funds = account::withdraw(b, proof, RES_X, stake)?;
            lottery_addr().enter(b, who, funds)
        })
    };
    let draw = graph(|b| lottery_addr().draw(b, u64::from(lottery::ROUND_CAP)));

    // The empty round first: nobody has entered, and the draw still
    // settles — recording what it drew and naming no winner.
    let (results, store) = run_both(&world, &store, &[(&draw, TxHash(Hash32([0x60; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
    let empty_store = store.clone();
    assert_eq!(
        settled_round(&empty_store),
        Some(lottery::Outcome {
            draw: env().randomness,
            winner: None,
        }),
        "an unentered round records its draw and no winner"
    );

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter(ALICE, 100), TxHash(Hash32([0x61; 32]))),
            (&enter(BOB, 40), TxHash(Hash32([0x62; 32]))),
            (&draw, TxHash(Hash32([0x63; 32]))),
        ],
    );
    assert!(results.iter().all(|r| matches!(r, TxResult::Completed(_))));

    // One ticket per entrant, each holding the entrant it was bought
    // for, and the stakes pooled into the lottery's own vault.
    let entries: BTreeMap<u128, Vec<u8>> = store
        .collection_entries()
        .filter(|(key, _)| (key.owner, key.collection) == (lottery_addr().into(), tickets()))
        .map(|(key, value)| (key.order, value.to_vec()))
        .collect();
    assert_eq!(entries.len(), 2);
    for who in [ALICE, BOB] {
        assert_eq!(
            entries[&ticket_order(who)],
            who.address().to_bytes().to_vec(),
            "a ticket holds its entrant"
        );
    }
    assert!(u32::try_from(entries.len()).unwrap() <= lottery::ROUND_CAP);
    assert_eq!(amount_of(&store, vault(lottery_addr(), RES_X)), 140);

    // Ascending order is the index space the draw reduces into, so who
    // sits at which index is the hash order and nothing else.
    let ascending: Vec<PrincipalAddr> = {
        let mut both = [ALICE, BOB];
        both.sort_by_key(|who| ticket_order(*who));
        both.to_vec()
    };
    let seed = u128::from_le_bytes(env().randomness[..16].try_into().unwrap());
    let expected = ascending[(seed % 2) as usize];

    assert_eq!(
        settled_round(&store),
        Some(lottery::Outcome {
            draw: env().randomness,
            winner: Some(expected.address()),
        }),
        "the round settles on the draw and the entrant it selects"
    );
}

/// The page a draw reads is the caller's choice, and the caller's bill:
/// one method, two calls, two caps — priced apart by exactly the entries
/// the larger page may walk.
#[test]
fn the_same_draw_at_two_caps_is_priced_apart() {
    use hyperscale_vm_effects::{DEPTH_UNITS, footprint};

    let world = world();
    let declared = |cap: u64| {
        let graph = graph_in(&world, |b| lottery_addr().draw(b, cap));
        sharded_routing(&world, &graph)
            .per_shard
            .values()
            .map(footprint)
            .sum::<u64>()
    };
    let (page, larger) = (declared(64), declared(640));
    assert_eq!(larger - page, DEPTH_UNITS * (640 - 64));
}

/// No constant stands between a caller and the page a draw reads: a cap
/// past the old publish-time ceiling admits, executes on both runtimes,
/// and settles on the same entrant a page-sized draw would have —
/// bounded by what the caller paid for, not by a number nobody chose.
#[test]
fn a_draw_buys_a_page_past_any_ceiling() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();

    let enter = graph(|b| {
        let proof = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, proof, RES_X, 100)?;
        lottery_addr().enter(b, ALICE, funds)
    });
    let draw = graph(|b| lottery_addr().draw(b, 5_000));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter, TxHash(Hash32([0x70; 32]))),
            (&draw, TxHash(Hash32([0x71; 32]))),
        ],
    );
    assert!(results.iter().all(|r| matches!(r, TxResult::Completed(_))));
    assert_eq!(
        settled_round(&store),
        Some(lottery::Outcome {
            draw: env().randomness,
            winner: Some(ALICE.address()),
        }),
        "one entrant under a five-thousand-entry page still wins their own round"
    );
}

/// Which tickets count is nobody's choice: the kernel answers whether
/// the page covered the round, so a short page declines and a page
/// exactly the round's size settles — no headroom entry is bought just
/// to prove the walk complete. Every settled winner was therefore drawn
/// over every ticket, at a cost that rises with the round.
#[test]
fn a_draw_declines_a_page_that_did_not_cover_the_round() {
    let world = world();
    let mut store = MemoryStore::new();
    for who in [ALICE, BOB] {
        store
            .write(vault(who, RES_X), encode_amount(150).to_vec())
            .unwrap();
    }

    let enter = |who: PrincipalAddr| {
        graph(move |b| {
            let proof = account::authorize(b, who)?;
            let funds = account::withdraw(b, proof, RES_X, 100)?;
            lottery_addr().enter(b, who, funds)
        })
    };
    let draw_at = |cap: u64| graph(move |b| lottery_addr().draw(b, cap));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter(ALICE), TxHash(Hash32([0x80; 32]))),
            (&enter(BOB), TxHash(Hash32([0x81; 32]))),
            // A one-entry page over a two-ticket round leaves a ticket
            // unwalked, and the round declines.
            (&draw_at(1), TxHash(Hash32([0x82; 32]))),
            // A page exactly the round's size covers it: the kernel
            // probes past the page's last entry and finds nothing.
            (&draw_at(2), TxHash(Hash32([0x83; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    assert_eq!(results[2], TxResult::Declined(lottery::ROUND_TRUNCATED));
    assert!(matches!(results[3], TxResult::Completed(_)));
    assert!(
        settled_round(&store).is_some_and(|outcome| outcome.winner.is_some()),
        "the whole round settled on a winner"
    );
}
