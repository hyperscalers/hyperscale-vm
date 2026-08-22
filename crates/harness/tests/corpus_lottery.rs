//! The lottery end to end on both runtimes: a round closes on a seal
//! and settles on the entrant the sealed draw picks.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{Hash32, TestHasher, Value, child_key, collection_id, order_key};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_harness::driver::{amount_of, test_hash, vault};
use hyperscale_vm_kernel::{DOMAIN_SEALED_DRAW, MemoryStore, Substates};
use hyperscale_vm_sdk::hbor::from_slice;
use hyperscale_vm_sdk::state::Word;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    CollectionId, EffectTarget, Outcome, Presence, PrincipalAddr, SubstateKey, TxHash,
    UnmetCondition, encode_amount,
};

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

/// The cell holding the round's seal.
fn round_cell() -> SubstateKey {
    child_key(&TestHasher, lottery_addr(), lottery::ROUND, &[])
}

/// The word a round sealed in this lane's epoch opens onto, built here
/// from the preimage the kernel states rather than read back from what
/// the guest wrote — so a change to the derivation fails here rather
/// than agreeing with itself.
fn sealed_word() -> Word {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(DOMAIN_SEALED_DRAW);
    preimage.extend_from_slice(&MATURED_SEED);
    preimage.extend_from_slice(&round_cell().to_bytes());
    Word::from_protocol(&test_hash(&preimage))
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

/// A sealed draw reaching a guest, on both runtimes: two entries, a
/// close, and a settlement on one of them.
///
/// What the result cell holds is the draw itself beside the winner, and
/// the draw is asserted to be the one the round's seal commits to — the
/// whole property the package exists to witness, since a winner is only
/// as unchosen as the value that picked it.
///
/// The winning index is re-derived here from the entrants' hash order
/// rather than read back from the guest, so the assertion is an
/// independent computation of who should have won and not a restatement
/// of what did.
#[test]
fn the_round_settles_on_the_entrant_its_sealed_draw_picks() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    store.write(vault(BOB, RES_X), encode_amount(150).to_vec());

    let enter = |who: PrincipalAddr, stake: u128| {
        graph(move |b| {
            let proof = account::authorize(b, who)?;
            let funds = account::withdraw(b, proof, RES_X, stake)?;
            lottery_addr().enter(b, who, funds)
        })
    };
    let close = graph(|b| lottery_addr().close(b));
    let settle = graph(|b| lottery_addr().settle(b, u64::from(lottery::ROUND_CAP)));

    // The empty round: nobody has entered, and it still settles —
    // recording what it drew and naming no winner. Its own branch of the
    // store, because a round settles once and a settled one is settled.
    let (results, empty_store) = run_both(
        &world,
        &store,
        &[
            (&close, TxHash(Hash32([0x5F; 32]))),
            (&settle, TxHash(Hash32([0x60; 32]))),
        ],
    );
    assert!(results.iter().all(|r| matches!(r, TxResult::Completed(_))));
    assert_eq!(
        settled_round(&empty_store),
        Some(lottery::Outcome {
            draw: sealed_word(),
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
            (&close, TxHash(Hash32([0x63; 32]))),
            (&settle, TxHash(Hash32([0x64; 32]))),
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
    let reduced = u128::from_le_bytes(sealed_word().as_bytes()[..16].try_into().unwrap());
    let expected = ascending[(reduced % 2) as usize];

    assert_eq!(
        settled_round(&store),
        Some(lottery::Outcome {
            draw: sealed_word(),
            winner: Some(expected.address()),
        }),
        "the round settles on the draw and the entrant it selects"
    );
}

/// A settled round is settled. The outcome is written where nothing
/// was, so a second settlement is infeasible and the kernel says so
/// before the guest runs.
///
/// The seal already makes re-settling pointless — every attempt opens
/// the same word — so this is the second half of the same argument: not
/// only does a loser gain nothing by trying again, they cannot try.
#[test]
fn a_settled_round_refuses_a_second_settlement() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    let enter = graph(|b| {
        let proof = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, proof, RES_X, 100)?;
        lottery_addr().enter(b, ALICE, funds)
    });
    let close = graph(|b| lottery_addr().close(b));
    let settle = graph(|b| lottery_addr().settle(b, u64::from(lottery::ROUND_CAP)));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter, TxHash(Hash32([0x80; 32]))),
            (&close, TxHash(Hash32([0x81; 32]))),
            (&settle, TxHash(Hash32([0x82; 32]))),
        ],
    );
    assert!(results.iter().all(|r| matches!(r, TxResult::Completed(_))));
    let settled = settled_round(&store).expect("the round settled");

    let (results, after) = run_both(&world, &store, &[(&settle, TxHash(Hash32([0x83; 32])))]);
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(child_key(
                    &TestHasher,
                    lottery_addr(),
                    lottery::OUTCOME,
                    &[],
                )),
                required: Presence::Absent,
            },
        })],
        "a round that has a winner cannot be settled again"
    );
    assert_eq!(
        settled_round(&after),
        Some(settled),
        "the refused settlement left the round it found"
    );
}

/// The page a settlement reads is the caller's choice, and the caller's
/// bill: one method, two calls, two caps — priced apart by exactly the
/// entries the larger page may walk.
#[test]
fn the_same_settlement_at_two_caps_is_priced_apart() {
    use hyperscale_vm_effects::{DEPTH_UNITS, footprint};

    let world = world();
    let declared = |cap: u64| {
        let graph = graph_in(&world, |b| lottery_addr().settle(b, cap));
        sharded_routing(&world, &graph)
            .per_shard
            .values()
            .map(footprint)
            .sum::<u64>()
    };
    let (page, larger) = (declared(64), declared(640));
    assert_eq!(larger - page, DEPTH_UNITS * (640 - 64));
}

/// No constant stands between a caller and the page a settlement reads:
/// a cap past the old publish-time ceiling admits, executes on both
/// runtimes, and settles on the same entrant a page-sized walk would
/// have — bounded by what the caller paid for, not by a number nobody
/// chose.
#[test]
fn a_settlement_buys_a_page_past_any_ceiling() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    let enter = graph(|b| {
        let proof = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, proof, RES_X, 100)?;
        lottery_addr().enter(b, ALICE, funds)
    });
    let close = graph(|b| lottery_addr().close(b));
    let settle = graph(|b| lottery_addr().settle(b, 5_000));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter, TxHash(Hash32([0x70; 32]))),
            (&close, TxHash(Hash32([0x71; 32]))),
            (&settle, TxHash(Hash32([0x72; 32]))),
        ],
    );
    assert!(results.iter().all(|r| matches!(r, TxResult::Completed(_))));
    assert_eq!(
        settled_round(&store),
        Some(lottery::Outcome {
            draw: sealed_word(),
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
fn a_settlement_declines_a_page_that_did_not_cover_the_round() {
    let world = world();
    let mut store = sealed_store();
    for who in [ALICE, BOB] {
        store.write(vault(who, RES_X), encode_amount(150).to_vec());
    }

    let enter = |who: PrincipalAddr| {
        graph(move |b| {
            let proof = account::authorize(b, who)?;
            let funds = account::withdraw(b, proof, RES_X, 100)?;
            lottery_addr().enter(b, who, funds)
        })
    };
    let close = graph(|b| lottery_addr().close(b));
    let settle_at = |cap: u64| graph(move |b| lottery_addr().settle(b, cap));

    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&enter(ALICE), TxHash(Hash32([0x80; 32]))),
            (&enter(BOB), TxHash(Hash32([0x81; 32]))),
            (&close, TxHash(Hash32([0x82; 32]))),
            // A one-entry page over a two-ticket round leaves a ticket
            // unwalked, and the round declines.
            (&settle_at(1), TxHash(Hash32([0x83; 32]))),
            // A page exactly the round's size covers it: the kernel
            // probes past the page's last entry and finds nothing.
            (&settle_at(2), TxHash(Hash32([0x84; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    assert!(matches!(results[2], TxResult::Completed(_)));
    assert_eq!(results[3], TxResult::Declined(lottery::ROUND_TRUNCATED));
    assert!(matches!(results[4], TxResult::Completed(_)));
    assert!(
        settled_round(&store).is_some_and(|outcome| outcome.winner.is_some()),
        "the whole round settled on a winner"
    );
}
