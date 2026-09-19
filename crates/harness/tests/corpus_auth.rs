//! Authority end to end on both runtimes: sign-in rules, securify,
//! chained rules, minted proofs, recovery proposals, and the custody
//! gates badges open.

use hyperscale_hbor::Capped;
use hyperscale_vm_effects::{
    Authority, Claim, ClaimRef, GraphArg, GraphNode, Hash32, InstanceMeta, IntentTree,
    ManifestGraph, Marked, Marker, PrincipalRule, Records, RuleBytes, StoredRule, TestHasher,
    Value, holdings_collection, never,
};
use hyperscale_vm_fixtures::nf;
use hyperscale_vm_harness::driver::{amount_of, cells, vault};
use hyperscale_vm_kernel::{MemoryStore, Receipt, Substates};
use hyperscale_vm_sdk::hbor::to_vec;
use hyperscale_vm_sdk::{Declines, nobody};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    EffectTarget, Event, Outcome, Presence, PrincipalAddr, TxHash, UnmetCondition, encode_amount,
};
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// A refused sign-in takes the whole transaction with it, and nothing
/// the transaction would have done happens.
///
/// The condition lands at materialization, before any body runs, so the
/// withdrawal that would have spent on Alice's authority never runs —
/// which is what makes the claim riding her signature sound with nothing
/// checking it later.
#[test]
fn a_refused_sign_in_takes_its_transaction_with_it() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    // Her cell admits her own key and nothing else, and Bob's is what
    // attests the intent.
    store.write(auth(ALICE), governing(ALICE));

    let graph = transfer_graph();
    let (results, final_store) = run_both_attested_at(
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0B; 32])), ALICE, BOB)],
        env().clock_ms,
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        })]
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 0);
}

/// Alice and Bob trade across their own accounts in one intent: her X
/// for his Y, each withdrawal gated on its own account and answered by
/// the one signature.
fn swap_across_own_accounts() -> ManifestGraph {
    graph_acting_as(&[ALICE, BOB], |b| {
        let x = account::withdraw(b, ALICE, RES_X, 100)?;
        account::deposit(b, BOB, x)?;
        let y = account::withdraw(b, BOB, RES_Y, 10)?;
        account::deposit(b, ALICE, y)
    })
}

/// The store both accounts trade from.
fn two_account_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    store.write(vault(BOB, RES_Y), encode_amount(20).to_vec());
    store
}

/// An intent acting as two accounts commits on both sign-ins: its one
/// signature answers each account's gate, and the run writes a
/// nullifier under each account's prefix.
#[test]
fn an_intent_acting_as_two_accounts_commits_on_both_sign_ins() {
    let world = world();
    let tree = acting_as(&[ALICE, BOB], swap_across_own_accounts());
    let (outcome, end, admitted) = run_both_tree_admitted(&world, &two_account_store(), &tree)
        .expect("one intent acts as both");
    let tx = TxHash(tree.hash(&TestHasher).0);
    assert!(
        matches!(outcome.receipts[&tx].outcome, Outcome::Completed { .. }),
        "both sign-ins admit; got {:?}",
        outcome.receipts[&tx].outcome
    );
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);
    assert_eq!(amount_of(&end, vault(BOB, RES_Y)), 10);
    assert_eq!(amount_of(&end, vault(ALICE, RES_Y)), 10);

    let [record] = admitted.intents() else {
        panic!("one intent");
    };
    let written = cells(&end);
    assert_eq!(record.nullifiers.len(), 2);
    for nullifier in &record.nullifiers {
        assert_eq!(
            written.get(&nullifier.key),
            Some(
                &Marker {
                    tx,
                    expiry_ms: record.expiry_ms,
                    marks: Marked::Spent(record.intent),
                }
                .to_bytes()
            ),
            "{:?} spent its own nullifier",
            nullifier.account
        );
    }
}

/// One account's rule refusing the attesting set refuses the whole
/// intent at materialization: nothing moves on either account, and
/// neither nullifier is written — the one Alice's shard would have
/// admitted included.
#[test]
fn one_refusing_rule_refuses_the_whole_intent() {
    let world = world();
    let mut store = two_account_store();
    // Bob's cell admits his own key alone; Alice's is unwritten and
    // admits hers. Only Alice attests.
    store.write(auth(BOB), governing(BOB));
    let mut tree = acting_as(&[ALICE, BOB], swap_across_own_accounts());
    tree.root.attested_by = Capped::new(vec![ALICE]).unwrap();
    let (outcome, end, admitted) =
        run_both_tree_admitted(&world, &store, &tree).expect("admissible");
    let tx = TxHash(tree.hash(&TestHasher).0);
    assert_eq!(
        outcome.receipts[&tx].outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: BOB.address(),
            },
        }
    );
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 0);
    assert_eq!(amount_of(&end, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&end, vault(ALICE, RES_Y)), 0);
    let written = cells(&end);
    for nullifier in &admitted.intents()[0].nullifiers {
        assert!(
            !written.contains_key(&nullifier.key),
            "{:?} spent nothing",
            nullifier.account
        );
    }
}

/// A threshold is a property of one intent's attesting set: an account
/// whose rule wants two of two keys opens to an intent both attest and
/// stays shut to one only one of them attests, at the sign-in judged on
/// its own shard.
#[test]
fn a_threshold_rule_is_judged_over_the_intents_attesting_set() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    let two_of_two = StoredRule::CountOf {
        count: 2,
        rules: Capped::new(vec![
            StoredRule::claim(Claim::of_subject(BOB)),
            StoredRule::claim(Claim::of_subject(MAKER)),
        ])
        .unwrap(),
    };
    store.write(
        auth(ALICE),
        Authority::primary_only(
            RuleBytes::try_from(&two_of_two).expect("a rule within the vocabulary caps"),
        )
        .in_cell(),
    );
    let tx = |tree: &IntentTree| TxHash(tree.hash(&TestHasher).0);

    let mut both = acting_as(&[ALICE], transfer_graph());
    both.root.attested_by = Capped::new(vec![BOB, MAKER]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &both).expect("admissible");
    assert!(
        matches!(
            outcome.receipts[&tx(&both)].outcome,
            Outcome::Completed { .. }
        ),
        "two of two attest; got {:?}",
        outcome.receipts[&tx(&both)].outcome
    );
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);

    let mut one = acting_as(&[ALICE], transfer_graph());
    one.root.attested_by = Capped::new(vec![BOB]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &one).expect("admissible");
    assert_eq!(
        outcome.receipts[&tx(&one)].outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        }
    );
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 0);
}

/// The governing record's second rule is a second factor: an account
/// whose confirmation names the maker's key opens only to an intent Bob
/// and the maker both attest, and Bob's key alone — the phone without
/// the card — is refused at the same sign-in, on the same shard.
#[test]
fn a_second_factor_is_required_beside_the_primary() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    store.write(
        auth(ALICE),
        Authority {
            primary: stored_rule(BOB),
            confirmation: stored_rule(MAKER),
        }
        .in_cell(),
    );
    let tx = |tree: &IntentTree| TxHash(tree.hash(&TestHasher).0);

    let mut both = acting_as(&[ALICE], transfer_graph());
    both.root.attested_by = Capped::new(vec![BOB, MAKER]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &both).expect("admissible");
    assert!(
        matches!(
            outcome.receipts[&tx(&both)].outcome,
            Outcome::Completed { .. }
        ),
        "phone and card attest; got {:?}",
        outcome.receipts[&tx(&both)].outcome
    );
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);

    let mut phone = acting_as(&[ALICE], transfer_graph());
    phone.root.attested_by = Capped::new(vec![BOB]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &phone).expect("admissible");
    assert_eq!(
        outcome.receipts[&tx(&phone)].outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        },
        "the primary alone is not the account"
    );
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 0);
}

/// The whole of a card, end to end: an account that securifies with a
/// second factor opens only to the phone and the card together, and
/// rotating either factor takes both — the sign-in is what admits the
/// rotation, and the sign-in is the conjunction.
#[test]
fn a_card_is_required_from_securify_on_and_takes_both_to_rotate() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    let tx = |tree: &IntentTree| TxHash(tree.hash(&TestHasher).0);
    let signed_in = |outcome: &Outcome| {
        *outcome
            == Outcome::ConditionUnmet {
                condition: UnmetCondition::SignedIn {
                    account: ALICE.address(),
                },
            }
    };

    // Alice's own key is the phone; the maker's is the card.
    let securify = graph(|b| {
        account::securify(
            b,
            ALICE,
            governing_rule(ALICE),
            governing_rule(MAKER),
            stored_rule(BOB),
            nobody(),
            DAY_MS,
        )
    });
    let (results, store) = run_both(&world, &store, &[(&securify, TxHash(Hash32([0xF0; 32])))]);
    assert!(matches!(&results[0], TxResult::Completed(_)));

    let mut phone = acting_as(&[ALICE], transfer_graph());
    phone.root.attested_by = Capped::new(vec![ALICE]).unwrap();
    let (outcome, _) = run_both_tree(&world, &store, &phone).expect("admissible");
    assert!(
        signed_in(&outcome.receipts[&tx(&phone)].outcome),
        "the phone alone is not the account"
    );
    let mut both = acting_as(&[ALICE], transfer_graph());
    both.root.attested_by = Capped::new(vec![ALICE, MAKER]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &both).expect("admissible");
    assert!(matches!(
        outcome.receipts[&tx(&both)].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);

    // Dropping the card takes the card: the phone alone is refused at
    // the sign-in, and both together rewrite the record at once.
    let rotate = graph(|b| account::rotate(b, ALICE, governing_rule(ALICE), no_factor()));
    let mut alone = acting_as(&[ALICE], rotate.clone());
    alone.root.attested_by = Capped::new(vec![ALICE]).unwrap();
    let (outcome, _) = run_both_tree(&world, &store, &alone).expect("admissible");
    assert!(
        signed_in(&outcome.receipts[&tx(&alone)].outcome),
        "rotating a factor takes every factor"
    );
    let mut together = acting_as(&[ALICE], rotate);
    together.root.attested_by = Capped::new(vec![ALICE, MAKER]).unwrap();
    let (outcome, store) = run_both_tree(&world, &store, &together).expect("admissible");
    assert!(matches!(
        outcome.receipts[&tx(&together)].outcome,
        Outcome::Completed { .. }
    ));
    assert_acts(&world, &store, ALICE, env().clock_ms, true, 0xF1);
}

/// A guardian who passes the card's rule back leaves an account the new
/// primary cannot spend from alone: what colluding guardians get is a
/// new primary, and the card is still the holder's.
#[test]
fn a_recovery_that_keeps_the_card_leaves_the_card_in_the_way() {
    let world = world();
    let mut store = recovered_store();
    store.write(
        auth(ALICE),
        Authority {
            primary: stored_rule(ALICE),
            confirmation: stored_rule(MAKER),
        }
        .in_cell(),
    );
    let t0 = env().clock_ms;
    let tx = |tree: &IntentTree| TxHash(tree.hash(&TestHasher).0);

    let keeping = graph_signed(BOB, |b| {
        account::propose(b, ALICE, governing_rule(BOB), governing_rule(MAKER))
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&keeping, TxHash(Hash32([0xF2; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let at = t0 + DAY_MS;
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0xF3; 32])))],
        Some(BOB),
        at,
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // Bob is the primary now, and Bob alone is still not the account.
    assert_acts(&world, &store, BOB, at, false, 0xF4);
    let mut both = acting_as(&[ALICE], transfer_graph());
    both.root.attested_by = Capped::new(vec![BOB, MAKER]).unwrap();
    let (outcome, end) = run_both_tree(&world, &store, &both).expect("admissible");
    assert!(
        matches!(
            outcome.receipts[&tx(&both)].outcome,
            Outcome::Completed { .. }
        ),
        "the new primary and the card together are; got {:?}",
        outcome.receipts[&tx(&both)].outcome
    );
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);
}

/// Lost card: a guardian passes the phone's rule back with a new card,
/// and after the delay the phone opens the account beside the new card
/// and not the old — the primary's bytes never moved.
#[test]
fn a_lost_card_is_replaced_by_a_guardian_around_the_phone() {
    let world = world();
    let store = carded_store();
    let t0 = env().clock_ms;

    let new_card = graph_signed(BOB, |b| {
        account::propose(b, ALICE, governing_rule(ALICE), governing_rule(TAKER))
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&new_card, TxHash(Hash32([0xF5; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    // The phone alone cannot sign in to finish it — that is the card's
    // whole point — so a stranger does, promotion being nobody's gate.
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&promote_by(TAKER), TxHash(Hash32([0xF6; 32])))],
        Some(TAKER),
        t0 + DAY_MS,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("promote must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(
            Authority {
                primary: stored_rule(ALICE),
                confirmation: stored_rule(TAKER),
            }
            .in_cell()
        )),
        "the card moved and the phone did not"
    );

    assert_acts_together(&world, &store, &[ALICE, TAKER], true);
    assert_acts_together(&world, &store, &[ALICE, MAKER], false);
    assert_acts_together(&world, &store, &[ALICE], false);
}

/// Both stolen: the freeze closes the primary and leaves the card
/// standing, so nobody acts — the thief with phone and card included;
/// the veto gives the primary back with the card still in place; and
/// enacting the proposal writes both factors it names.
#[test]
fn a_freeze_leaves_the_card_standing() {
    let world = world();
    let store = carded_store();
    let t0 = env().clock_ms;
    let both_new = graph_signed(BOB, |b| {
        account::freeze(b, ALICE, governing_rule(BOB), governing_rule(TAKER))
    });

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&both_new, TxHash(Hash32([0xF7; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("freeze must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(frozen(stored_rule(MAKER)))),
        "the primary closes and the card stands"
    );
    assert_acts_together(&world, &store, &[ALICE, MAKER], false);
    assert_acts_together(&world, &store, &[BOB, TAKER], false);

    // The veto ends it: the phone is back beside the card it never lost.
    let veto = graph_signed(TAKER, |b| account::veto(b, ALICE, FIRST));
    let (results, restored) = run_both_signed(
        &world,
        &store,
        &[(&veto, TxHash(Hash32([0xF8; 32])))],
        Some(TAKER),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("veto must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(
            Authority {
                primary: stored_rule(ALICE),
                confirmation: stored_rule(MAKER),
            }
            .in_cell()
        ))
    );
    assert_acts_together(&world, &restored, &[ALICE, MAKER], true);

    // Or the clock does, and both factors are the proposal's.
    let (results, enacted) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0xF9; 32])))],
        Some(BOB),
        t0 + DAY_MS,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("promote must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(
            Authority {
                primary: stored_rule(BOB),
                confirmation: stored_rule(TAKER),
            }
            .in_cell()
        ))
    );
    assert_acts_together(&world, &enacted, &[BOB, TAKER], true);
    assert_acts_together(&world, &enacted, &[BOB, MAKER], false);
    assert_acts_together(&world, &enacted, &[ALICE, MAKER], false);
}

/// Rotating an account that has not securified is refused at the
/// governing cell's door: a rotation is a rewrite through the presence
/// requirement, never a securify without its roles.
#[test]
fn rotate_needs_a_governing_cell() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    let rotate = graph(|b| account::rotate(b, ALICE, governing_rule(BOB), no_factor()));
    let (results, _) = run_both(&world, &store, &[(&rotate, TxHash(Hash32([0xFA; 32])))]);
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(auth(ALICE)),
                required: Presence::Present,
                node: Some(0),
            },
        })]
    );
}

/// One hour, against the corpus day: a delay an amendment may name and
/// this account does not yet hold.
const HOUR_MS: u64 = 3_600_000;

/// Alice amends her roles: the taker may recover her, Bob may veto, and
/// the hour is the delay from there on.
fn amend_graph() -> ManifestGraph {
    graph(|b| account::amend(b, ALICE, stored_rule(TAKER), stored_rule(BOB), HOUR_MS))
}

/// The roles Alice's amendment names, as the record carries them.
fn roles() -> account::Replacement {
    account::Replacement::Roles {
        recovery: stored_rule(TAKER),
        veto: stored_rule(BOB),
        delay_ms: HOUR_MS,
    }
}

/// An amendment enacts after the delay that governed when it was made
/// and writes the three roles: from then on the taker may recover, Bob
/// may veto, and the hour governs the next wait.
#[test]
fn an_amendment_enacts_after_the_delay_and_writes_the_roles() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&amend_graph(), TxHash(Hash32([0x40; 32])))],
        Some(ALICE),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("amend must complete; got {:?}", results[0]);
    };
    let mut waiting = MemoryStore::new();
    seed_proposal(&mut waiting, ALICE, FIRST, t0 + DAY_MS, roles());
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&waiting.cell(own_cell(ALICE, 2))),
        "the amendment serves the delay that governs now"
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 0)),
        None,
        "and nothing governs until it is enacted"
    );

    // Unmatured, the promotion is refused; matured, anyone finishes it.
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&promote_by(ALICE), TxHash(Hash32([0x41; 32])))],
        Some(ALICE),
        t0 + DAY_MS - 1,
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::Unmatured.code())]
    );
    let at = t0 + DAY_MS;
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&promote_by(TAKER), TxHash(Hash32([0x42; 32])))],
        Some(TAKER),
        at,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("promote must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 0)),
        Some(&Some(stored_rule(TAKER).in_cell()))
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 1)),
        Some(&Some(stored_rule(BOB).in_cell()))
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 3)),
        Some(&Some(HOUR_MS.to_le_bytes().to_vec()))
    );
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "an amendment touches no factor"
    );
}

/// Once an amendment is enacted the new guardian may recover, the old
/// one may not, and the delay it carried is the one the next wait
/// serves.
#[test]
fn an_enacted_amendment_hands_recovery_to_the_new_guardian() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&amend_graph(), TxHash(Hash32([0x4D; 32])))],
        Some(ALICE),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let at = t0 + DAY_MS;
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&promote_by(TAKER), TxHash(Hash32([0x4E; 32])))],
        Some(TAKER),
        at,
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x43; 32])))],
        Some(BOB),
        at,
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        })],
        "the old guardian is out"
    );
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&propose_by(TAKER), TxHash(Hash32([0x44; 32])))],
        Some(TAKER),
        at,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the new guardian proposes; got {:?}", results[0]);
    };
    let mut sooner = MemoryStore::new();
    seed_proposal(
        &mut sooner,
        ALICE,
        FIRST + 1,
        at + HOUR_MS,
        factors(&stored_rule(BOB), None),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&sooner.cell(own_cell(ALICE, 2))),
        "and the delay the amendment carried is the one the next wait serves"
    );
}

/// An amendment is the guardians' to cancel and the veto's to end: a
/// thief evicting the guardians is stopped by them, and the roles stand.
#[test]
fn an_amendment_is_cancelled_by_the_guardians_or_the_veto() {
    let world = world();
    let store = recovered_store();

    for (who, tag) in [(BOB, 0x45), (MAKER, 0x47)] {
        let (results, store) = run_both_signed(
            &world,
            &store,
            &[(&amend_graph(), TxHash(Hash32([tag; 32])))],
            Some(ALICE),
        );
        assert!(matches!(&results[0], TxResult::Completed(_)));
        let verdict = if who == BOB {
            cancel_by(BOB)
        } else {
            veto_by(MAKER)
        };
        let (results, store) = run_both_signed(
            &world,
            &store,
            &[(&verdict, TxHash(Hash32([tag + 1; 32])))],
            Some(who),
        );
        let TxResult::Completed(receipt) = &results[0] else {
            panic!("the verdict must complete; got {:?}", results[0]);
        };
        assert_eq!(
            receipt.delta.cells.get(&own_cell(ALICE, 2)),
            Some(&Some(Vec::new())),
            "no amendment waits"
        );
        assert_eq!(receipt.delta.cells.get(&own_cell(ALICE, 0)), None);
        let far = env().clock_ms + 10 * DAY_MS;
        let (results, _) = run_both_at(
            &world,
            &store,
            &[(&promote_by(ALICE), TxHash(Hash32([tag + 0x10; 32])))],
            Some(ALICE),
            far,
        );
        assert_eq!(
            results,
            vec![TxResult::Declined(account::Error::NoSuchProposal.code())],
            "a cancelled amendment never governs"
        );
    }
}

/// A recovery proposal outranks an amendment: one is refused while a
/// proposal waits, and a freeze retires one already waiting — so the
/// primary can never stall the guardians.
#[test]
fn a_recovery_proposal_outranks_an_amendment() {
    let world = world();
    let store = recovered_store();

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x48; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&amend_graph(), TxHash(Hash32([0x49; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::Outranked.code())],
        "an amendment is refused while a recovery proposal waits"
    );

    // The other order: the amendment is waiting, and the freeze retires
    // it along with the primary.
    let store = recovered_store();
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&amend_graph(), TxHash(Hash32([0x4A; 32])))],
        Some(ALICE),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&freeze_by(BOB), TxHash(Hash32([0x4B; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("freeze must complete; got {:?}", results[0]);
    };
    let mut retired = MemoryStore::new();
    seed_proposal(
        &mut retired,
        ALICE,
        FIRST + 1,
        env().clock_ms + DAY_MS,
        factors(&stored_rule(BOB), Some(&stored_rule(ALICE))),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&retired.cell(own_cell(ALICE, 2))),
        "a recovery filing retires the amendment: one cell, and the freeze holds it"
    );
    let far = env().clock_ms + 10 * DAY_MS;
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0x4C; 32])))],
        Some(BOB),
        far,
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::NoSuchProposal.code())],
        "the amendment's serial names nothing now"
    );
}

/// Sign in and hand the account to Bob's rule, uniformly.
fn securify_graph(rule: &StoredRule) -> ManifestGraph {
    graph(|b| account::securify_uniform(b, ALICE, rule, DAY_MS))
}

/// The whole one-way door, end to end on both runtimes: an account
/// securifies to another principal's rule; its old key stops opening
/// its own sign-in, the new rule's key does, and a second securify
/// refuses.
#[test]
fn securify_retires_the_old_key_and_installs_the_rule() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    // Alice's last act under the virtual rule: signing in for its
    // retirement. Everything she stores from here is governed by Bob.
    let securify = securify_graph(&StoredRule::claim(Claim::of_subject(BOB)));
    let (results, store) = run_both(&world, &store, &[(&securify, TxHash(Hash32([0x51; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("securify must complete; got {:?}", results[0]);
    };
    let cell_bytes = governing(BOB);
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(cell_bytes)),
        "the guest's spliced frame is the codec's encoding, byte for byte"
    );

    // The old key still derives Alice's address, and that identity is
    // exactly what her rule no longer admits: her own sign-in refuses,
    // and everything behind it is unreachable.
    let transfer = transfer_graph();
    let (results, store) = run_both(&world, &store, &[(&transfer, TxHash(Hash32([0x52; 32])))]);
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        })],
        "the retired key must not open the account"
    );

    // Bob's key attests an intent acting as Alice, her shard judges it
    // against the rule she stored, and her claim rides its signature
    // into her guarded methods — with no node anywhere in it.
    let (results, store) = run_both_attested_at(
        &world,
        &store,
        &[(&transfer_graph(), TxHash(Hash32([0x53; 32])), ALICE, BOB)],
        env().clock_ms,
    );
    assert!(
        matches!(&results[0], TxResult::Completed(_)),
        "the installed rule must govern; got {:?}",
        results[0]
    );
    assert_eq!(amount_of(&store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&store, vault(BOB, RES_X)), 100);

    // Nothing re-securifies, and the refusal is the protocol's rather
    // than the guest's: `securify` declares a write requiring the cell
    // to be absent, so the shard holding it judges the door against
    // committed state and the body never runs.
    let again = graph(|b| {
        account::securify_uniform(b, ALICE, &StoredRule::claim(Claim::of_subject(BOB)), DAY_MS)
    });
    let (results, _) = run_both_attested_at(
        &world,
        &store,
        &[(&again, TxHash(Hash32([0x54; 32])), ALICE, BOB)],
        env().clock_ms,
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(auth(ALICE)),
                required: Presence::Absent,
                node: Some(0),
            },
        })],
        "a one-way door is a declared precondition, not a guest panic — and \
         losing the race to it is priced as one"
    );
}

/// A store where Alice's rule names Bob's key and the maker's names
/// Alice's, so an intent acting as the maker is attested by whichever
/// key the maker's own cell admits and by no other.
fn chained_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(MAKER, RES_X), encode_amount(150).to_vec());
    store.write(auth(ALICE), governing(BOB));
    store.write(auth(MAKER), governing(ALICE));
    store
}

/// An `auth` cell names keys, so delegation through one is one level
/// deep and never two.
///
/// Bob's key opens Alice's account and Alice's opens the maker's, and
/// that is not a chain: what the maker's cell names is the key Alice's
/// address derives, so Bob's key attests nothing there however far his
/// authority reaches elsewhere. Reaching the maker on Alice's *account*
/// is the socket's job, not the cell's.
#[test]
fn an_auth_cell_names_a_key_and_delegates_one_level() {
    let world = world();
    let store = chained_store();

    // Bob's key on an intent acting as the maker: admissible, and the
    // maker's own shard refuses it before any body runs.
    let transfer = graph_signed(MAKER, |b| {
        let funds = account::withdraw(b, MAKER, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    });
    let (results, store) = run_both_attested_at(
        &world,
        &store,
        &[(&transfer, TxHash(Hash32([0x61; 32])), MAKER, BOB)],
        env().clock_ms,
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: MAKER.address(),
            },
        })],
        "the maker's cell names Alice's key, and Bob's opening Alice's is not that"
    );

    // Alice's key is what it names, and her own account having moved to
    // Bob's is no part of the question.
    let (results, store) = run_both_attested_at(
        &world,
        &store,
        &[(&transfer, TxHash(Hash32([0x62; 32])), MAKER, ALICE)],
        env().clock_ms,
    );
    assert!(
        matches!(&results[0], TxResult::Completed(_)),
        "the key the cell names must open the maker's account; got {:?}",
        results[0]
    );
    assert_eq!(amount_of(&store, vault(MAKER, RES_X)), 50);
    assert_eq!(amount_of(&store, vault(BOB, RES_X)), 100);
}

/// A key retired at its own account is refused there and nowhere else.
///
/// Alice's rule names Bob and the maker's names Alice. Her own key no
/// longer attests an intent acting as her, which her shard says at her
/// cell; the maker's cell names that key rather than her account, so her
/// rotation is no part of what it admits. Two cells, two questions, and
/// the retirement answers only the first.
#[test]
fn a_retired_key_is_refused_at_its_own_account_and_nowhere_else() {
    let world = world();
    let store = chained_store();

    // Her own account: the cell she wrote names Bob, and her key is not
    // Bob's.
    let hers = graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    });
    let (results, store) = run_both(&world, &store, &[(&hers, TxHash(Hash32([0x65; 32])))]);
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        })],
        "the retired key is refused where a signature is judged"
    );

    // The maker's: the same key, admitted, because what the cell names
    // is the key and not the account it belongs to.
    let theirs = graph_signed(MAKER, |b| {
        let funds = account::withdraw(b, MAKER, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    });
    let (results, _) = run_both_attested_at(
        &world,
        &store,
        &[(&theirs, TxHash(Hash32([0x66; 32])), MAKER, ALICE)],
        env().clock_ms,
    );
    assert!(
        matches!(&results[0], TxResult::Completed(_)),
        "a key retired at one account still opens another that names it; got {:?}",
        results[0]
    );
}

/// A signature opens only the account its intent acts as: aimed at
/// another's guarded method it is inadmissible, so it never reaches a
/// block at all.
///
/// Written by hand, because no builder composes it: the claim Alice's
/// intent carries is her own, and a gate naming Bob is one it cannot
/// answer.
#[test]
fn a_signature_opens_only_the_account_its_intent_acts_as() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(BOB, RES_X), encode_amount(150).to_vec());

    let theft = ManifestGraph {
        nodes: Capped::from_array([GraphNode {
            target: BOB.into(),
            method: "withdraw".into(),
            args: vec![
                GraphArg::Literal(Value::Address(RES_X.address())),
                GraphArg::Literal(Value::U128(100)),
            ],
            evidence: Capped::from_members([ClaimRef::Account(ALICE)]),
        }]),
    };
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&theft, TxHash(Hash32([0x63; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Inadmissible(0)],
        "a signature is its own account's identity and no other's"
    );
}

/// Seed `owner`'s authority as the account writes it: the rule that
/// governs, the one that may replace it, the one that may veto a
/// replacement, and the delay a replacement waits.
fn seed_authority(
    store: &mut MemoryStore,
    owner: PrincipalAddr,
    governing: &RuleBytes,
    replaces: &RuleBytes,
    vetoes: &RuleBytes,
    delay_ms: u64,
) {
    store.write(
        auth(owner),
        Authority::primary_only(governing.clone()).in_cell(),
    );
    store.write(own_cell(owner, 0), replaces.in_cell());
    store.write(own_cell(owner, 1), vetoes.in_cell());
    store.write(own_cell(owner, 3), delay_ms.to_le_bytes().to_vec());
}

/// The proposal `owner` has waiting, as the account writes it, and the
/// count of proposals that makes `serial` the one it took.
fn seed_proposal(
    store: &mut MemoryStore,
    owner: PrincipalAddr,
    serial: u64,
    at_ms: u64,
    replaces: account::Replacement,
) {
    let proposal = account::Proposal {
        serial,
        effective_at_ms: at_ms,
        replaces,
    };
    store.write(own_cell(owner, 2), account::encode_proposal(&proposal));
    store.write(own_cell(owner, 4), serial.to_le_bytes().to_vec());
}

/// A replacement of the factors: `rule` as the primary, no second
/// factor, and the primary a freeze displaced where the account is
/// frozen.
fn factors(rule: &RuleBytes, frozen: Option<&RuleBytes>) -> account::Replacement {
    account::Replacement::Factors {
        primary: PrincipalRule(rule.0.clone()),
        confirmation: no_factor(),
        frozen: frozen.cloned(),
    }
}

/// The governing record a freeze writes: the rule nobody satisfies as
/// the primary, and `confirmation` left as it stood.
fn frozen(confirmation: RuleBytes) -> Vec<u8> {
    Authority {
        primary: RuleBytes::try_from(&never()).expect("the empty threshold encodes"),
        confirmation,
    }
    .in_cell()
}

/// No second factor, as the governing record holds it.
fn no_card() -> RuleBytes {
    RuleBytes(no_factor().0)
}

/// Whether `keys` together open Alice's sign-in: her whole transfer
/// completes, or refuses at her cell.
fn assert_acts_together(
    world: &Records,
    store: &MemoryStore,
    keys: &[PrincipalAddr],
    admits: bool,
) {
    let mut tree = acting_as(&[ALICE], transfer_graph());
    tree.root.attested_by = Capped::new(keys.to_vec()).unwrap();
    let (outcome, _) = run_both_tree(world, store, &tree).expect("admissible");
    let tx = TxHash(tree.hash(&TestHasher).0);
    let got = &outcome.receipts[&tx].outcome;
    if admits {
        assert!(
            matches!(got, Outcome::Completed { .. }),
            "{keys:?} together must open the account; got {got:?}"
        );
    } else {
        assert_eq!(
            *got,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::SignedIn {
                    account: ALICE.address(),
                },
            },
            "{keys:?} together must not open the account"
        );
    }
}

/// Alice with a card: her own key is the phone, the maker's the card,
/// Bob may recover her and the taker may veto.
fn carded_store() -> MemoryStore {
    let mut store = recovered_store();
    store.write(
        auth(ALICE),
        Authority {
            primary: stored_rule(ALICE),
            confirmation: stored_rule(MAKER),
        }
        .in_cell(),
    );
    store.write(own_cell(ALICE, 1), stored_rule(TAKER).in_cell());
    store
}

/// The split setup every recovery test starts from: Alice governs, Bob
/// may replace her, the maker may veto a replacement, and the corpus
/// delay separates a replacement from the instant it may be enacted.
///
/// Three cells rather than a table behind one, because a rule in a cell
/// is a rule in a cell — and each gate reads the one it needs.
fn recovered_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    store.write(auth(ALICE), governing(ALICE));
    store.write(own_cell(ALICE, 0), stored_rule(BOB).in_cell());
    store.write(own_cell(ALICE, 1), stored_rule(MAKER).in_cell());
    store.write(own_cell(ALICE, 3), DAY_MS.to_le_bytes().to_vec());
    store
}

/// The serial every proposal in these tests is: each makes one, on an
/// account that has made none.
const FIRST: u64 = 1;

/// Each of Alice's verdicts on her first proposal, composed by `signer`:
/// for anyone but Alice the builder signs them in at their own account
/// first, and the verdict is the second node.
fn cancel_by(signer: PrincipalAddr) -> ManifestGraph {
    graph_signed(signer, |b| account::cancel(b, ALICE, FIRST))
}

fn veto_by(signer: PrincipalAddr) -> ManifestGraph {
    graph_signed(signer, |b| account::veto(b, ALICE, FIRST))
}

/// Alice's recovery freezes her and proposes Bob in one call, composed
/// by `signer`.
fn freeze_by(signer: PrincipalAddr) -> ManifestGraph {
    graph_signed(signer, |b| {
        account::freeze(b, ALICE, governing_rule(BOB), no_factor())
    })
}

fn cancel_graph() -> ManifestGraph {
    cancel_by(ALICE)
}

fn promote_by(signer: PrincipalAddr) -> ManifestGraph {
    graph_signed(signer, |b| account::promote(b, ALICE, FIRST))
}

/// What Alice's account said about a replacement, at the index the
/// package's event table fixes: `proposed` is 2, `enacted` 3 and
/// `cancelled` 4.
fn said(event_type: u32, payload: Vec<u8>) -> Event {
    Event {
        emitter: ALICE.address(),
        event_type,
        payload: payload.try_into().unwrap(),
    }
}

fn proposed(serial: u64, effective_at_ms: u64) -> Vec<u8> {
    to_vec(&account::Proposed {
        serial,
        effective_at_ms,
    })
    .expect("an event encodes")
}

fn enacted(serial: u64) -> Vec<u8> {
    to_vec(&account::Enacted { serial }).expect("an event encodes")
}

fn cancelled(serial: u64) -> Vec<u8> {
    to_vec(&account::Cancelled { serial }).expect("an event encodes")
}

/// The one receipt a completed transaction leaves.
fn completed(results: &[TxResult]) -> &Receipt {
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the transaction must complete; got {:?}", results[0]);
    };
    receipt
}

/// Every transition says which proposal it answers, under the account's
/// own address: a filing carries its serial and the instant it may be
/// enacted from, and each verdict the serial it answered — so a wallet
/// watching the prefix can put the verdict on the notification.
#[test]
fn a_recovery_proposal_names_its_serial_at_every_transition() {
    let world = world();
    let t0 = env().clock_ms;
    let (results, filed) = run_both_signed(
        &world,
        &recovered_store(),
        &[(&propose_by(BOB), TxHash(Hash32([0xC0; 32])))],
        Some(BOB),
    );
    assert_eq!(
        completed(&results).events,
        vec![said(2, proposed(FIRST, t0 + DAY_MS))]
    );

    let (results, _) = run_both_at(
        &world,
        &filed,
        &[(&promote_by(TAKER), TxHash(Hash32([0xC1; 32])))],
        Some(TAKER),
        t0 + DAY_MS,
    );
    assert_eq!(completed(&results).events, vec![said(3, enacted(FIRST))]);

    let (results, _) = run_both_signed(
        &world,
        &filed,
        &[(&cancel_by(BOB), TxHash(Hash32([0xC2; 32])))],
        Some(BOB),
    );
    assert_eq!(completed(&results).events, vec![said(4, cancelled(FIRST))]);
}

/// A freeze and an amendment are filings too, and a veto is a verdict:
/// the same three words cover every transition, whichever record and
/// whichever role.
#[test]
fn a_freeze_an_amendment_and_a_veto_speak_the_same_words() {
    let world = world();
    let t0 = env().clock_ms;
    let (results, frozen) = run_both_signed(
        &world,
        &recovered_store(),
        &[(&freeze_by(BOB), TxHash(Hash32([0xC3; 32])))],
        Some(BOB),
    );
    assert_eq!(
        completed(&results).events,
        vec![said(2, proposed(FIRST, t0 + DAY_MS))]
    );

    let (results, _) = run_both_signed(
        &world,
        &frozen,
        &[(&veto_by(MAKER), TxHash(Hash32([0xC4; 32])))],
        Some(MAKER),
    );
    assert_eq!(completed(&results).events, vec![said(4, cancelled(FIRST))]);

    let (results, _) = run_both_signed(
        &world,
        &recovered_store(),
        &[(&amend_graph(), TxHash(Hash32([0xC5; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        completed(&results).events,
        vec![said(2, proposed(FIRST, t0 + DAY_MS))]
    );
}

/// Whether `signer`'s key opens Alice's sign-in at `clock_ms`: her whole
/// transfer completes, or refuses.
///
/// One judgment wherever the answer lands. Her shard reads her `auth`
/// cell against the keys attesting the intent, before any node runs, so
/// every key the rule turns away is turned away in the same place and
/// with the same verdict.
fn assert_acts(
    world: &Records,
    store: &MemoryStore,
    signer: PrincipalAddr,
    clock_ms: u64,
    admits: bool,
    tag: u8,
) {
    let transfer = transfer_graph();
    let (results, _) = run_both_attested_at(
        world,
        store,
        &[(&transfer, TxHash(Hash32([tag; 32])), ALICE, signer)],
        clock_ms,
    );
    if admits {
        assert!(
            matches!(&results[0], TxResult::Completed(_)),
            "the rule must admit this signer at {clock_ms}; got {:?}",
            results[0]
        );
    } else {
        assert_eq!(
            results,
            vec![TxResult::Refused(Outcome::ConditionUnmet {
                condition: UnmetCondition::SignedIn {
                    account: ALICE.address(),
                },
            })],
            "the rule must refuse this signer at {clock_ms}"
        );
    }
}

/// A proposal matures on its own: nothing applies it, and the verdict
/// flips at the instant — the retired primary refuses, the proposed one
/// signs in, on both runtimes.
#[test]
fn a_proposal_governs_from_its_instant_with_nothing_applying_it() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    // The primary cannot propose and the recovery key cannot spend:
    // each role opens its own gate and no other.
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x60; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        })],
        "primary is not recovery"
    );

    // Bob proposes himself; the instant is the clock plus the stored
    // delay, and the written frame is the codec's encoding exactly.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x61; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("propose must complete; got {:?}", results[0]);
    };
    let mut waiting = MemoryStore::new();
    seed_proposal(
        &mut waiting,
        ALICE,
        FIRST,
        t0 + DAY_MS,
        factors(&stored_rule(BOB), None),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&waiting.cell(own_cell(ALICE, 2))),
        "the guest's spliced frame is the codec's encoding, byte for byte"
    );
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "and a replacement waiting is not one enacted: the governing rule \
         is untouched until something enacts it"
    );

    // Before the instant, nothing enacts it however hard anyone tries:
    // a promotion is refused as unmatured, and Alice still acts while
    // Bob still does not.
    let before = t0 + DAY_MS - 1;
    let at = t0 + DAY_MS;
    let (results, early) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0x62; 32])))],
        Some(BOB),
        before,
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::Unmatured.code())],
        "the clock has not licensed it"
    );
    assert_acts(&world, &early, ALICE, before, true, 0x63);
    assert_acts(&world, &early, BOB, before, false, 0x64);

    // At the instant anyone may enact it, a stranger included: the
    // record was authorized by the gate that wrote it, and the clock is
    // the only condition left. The verdicts swap on the write rather
    // than on the read.
    let (results, enacted) = run_both_at(
        &world,
        &store,
        &[(&promote_by(TAKER), TxHash(Hash32([0x65; 32])))],
        Some(TAKER),
        at,
    );
    assert!(
        matches!(&results[0], TxResult::Completed(_)),
        "a matured proposal is anyone's to finish; got {:?}",
        results[0]
    );
    assert_acts(&world, &enacted, BOB, at, true, 0x66);
    assert_acts(&world, &enacted, ALICE, at, false, 0x67);

    // A later cancel by the new holder names a proposal that no longer
    // waits: what enacting moved is the governing rule, and a verdict
    // reaches only what is still pending.
    let (results, after) = run_both_at(
        &world,
        &enacted,
        &[(&cancel_by(BOB), TxHash(Hash32([0x68; 32])))],
        Some(BOB),
        at,
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::NoSuchProposal.code())],
        "a cancel never reaches what already governs"
    );
    assert_acts(&world, &after, BOB, at, true, 0x69);
    assert_acts(&world, &after, ALICE, at, false, 0x6A);
}

/// Recovery withdraws its own unmatured proposal — a proposal is its
/// proposer's to cancel, and nobody else's: the compromised primary
/// cannot cancel its own replacement, so there is no cancel war for it
/// to win. Every later verdict — however far past the would-be maturity
/// — is under the old roles, as if nothing had been proposed.
#[test]
fn recovery_withdraws_its_own_unmatured_proposal() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x68; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // The primary's cancel refuses at the gate: cancel is recovery's.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel_graph(), TxHash(Hash32([0x69; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        })],
        "a proposal is not the primary's to cancel"
    );

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel_by(BOB), TxHash(Hash32([0x6E; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("cancel must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "the governing rule is exactly what securify wrote"
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&Some(Vec::new())),
        "and what a cancel leaves is no replacement at all"
    );

    // Far past the would-be maturity, the old roles still govern: a
    // cancelled proposal never does.
    let long_after = t0 + 10 * DAY_MS;
    assert_acts(&world, &store, ALICE, long_after, true, 0x6A);
    assert_acts(&world, &store, BOB, long_after, false, 0x6B);

    // With nothing pending, a veto names a proposal that is not there:
    // refused rather than a clean no-op, so the vetoer is told that what
    // they saw was withdrawn before their verdict landed.
    let (results, after) = run_both_signed(
        &world,
        &store,
        &[(&veto_by(MAKER), TxHash(Hash32([0x6C; 32])))],
        Some(MAKER),
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::NoSuchProposal.code())],
        "nothing pending is nothing to veto"
    );
    assert_acts(&world, &after, ALICE, long_after, true, 0x6D);
}

/// A compromised primary cannot outlast its replacement: recovery
/// freezes the acting power and proposes in one call, then waits. The
/// frozen key can neither spend nor cancel, and the rotation lands on
/// the frozen account when the clock licenses it.
#[test]
fn recovery_rotates_a_hostile_primary_out() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    // A freeze is a proposal with the primary closed: the acting entry
    // goes, the displaced rule rides the proposal, and everything else
    // stands.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&freeze_by(BOB), TxHash(Hash32([0x90; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("freeze must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(frozen(no_card()))),
        "a freeze writes the rule nobody satisfies, rather than removing \
         one — an unwritten cell is what the address's own key still \
         governs, so a removal would hand the account back to the key \
         being frozen out"
    );
    let mut waiting = MemoryStore::new();
    seed_proposal(
        &mut waiting,
        ALICE,
        FIRST,
        t0 + DAY_MS,
        factors(&stored_rule(BOB), Some(&stored_rule(ALICE))),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&waiting.cell(own_cell(ALICE, 2))),
        "and the proposal carries the primary it displaced"
    );

    // The frozen key neither acts nor cancels.
    assert_acts(&world, &store, ALICE, t0, false, 0x91);
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel_graph(), TxHash(Hash32([0x92; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::SignedIn {
                account: ALICE.address(),
            },
        })]
    );

    // The clock licenses the rotation, and enacting it ends the freeze
    // with the primary the proposal named.
    let at = t0 + DAY_MS;
    let (results, enacted) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0x96; 32])))],
        Some(BOB),
        at,
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    assert_acts(&world, &enacted, ALICE, at, false, 0x97);
    assert_acts(&world, &enacted, BOB, at, true, 0x98);
}

/// A proposal while frozen carries the displaced primary forward: the
/// freeze is the proposal's, so replacing the proposal neither lifts
/// the freeze nor loses the rule a cancel gives back.
#[test]
fn a_proposal_while_frozen_carries_the_displaced_primary_forward() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&freeze_by(BOB), TxHash(Hash32([0xA0; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // A second proposal replaces the first and keeps the account frozen.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0xA1; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("propose must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "a proposal touches no governing rule, so the freeze stands"
    );
    let mut waiting = MemoryStore::new();
    seed_proposal(
        &mut waiting,
        ALICE,
        FIRST + 1,
        t0 + DAY_MS,
        factors(&stored_rule(BOB), Some(&stored_rule(ALICE))),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&waiting.cell(own_cell(ALICE, 2))),
        "and the replacement carries the displaced primary forward"
    );
    assert_acts(&world, &store, ALICE, t0, false, 0xA2);

    // Cancelling the second gives back what the first displaced.
    let cancel = graph_signed(BOB, |b| account::cancel(b, ALICE, FIRST + 1));
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel, TxHash(Hash32([0xA3; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("cancel must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(governing(ALICE))),
        "the primary the freeze displaced comes back"
    );
    assert_acts(&world, &store, ALICE, t0, true, 0xA4);
    assert_acts(&world, &store, BOB, t0, false, 0xA5);
}

/// A cancelled freeze gives the primary back: the freeze is the
/// proposal's, so the verdict that drops the proposal restores what it
/// displaced, and the account is where it was before.
#[test]
fn a_cancelled_freeze_gives_the_primary_back() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&freeze_by(BOB), TxHash(Hash32([0xA5; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    assert_acts(&world, &store, ALICE, t0, false, 0xA6);

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel_by(BOB), TxHash(Hash32([0xA7; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("cancel must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(governing(ALICE))),
        "the governing rule is exactly what securify wrote"
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&Some(Vec::new())),
        "and no replacement waits"
    );
    assert_acts(&world, &store, ALICE, t0, true, 0xA8);
    assert_acts(&world, &store, BOB, t0, false, 0xA9);
}

/// A hostile recovery under an effectively infinite delay matures
/// nothing on its own: the proposal waits forever, the old primary acts
/// throughout, and the veto is what ends it — the dial an owner sets
/// against the factor it trusts least.
#[test]
fn an_infinite_delay_keeps_a_hostile_recovery_waiting() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    seed_authority(
        &mut store,
        ALICE,
        &stored_rule(ALICE),
        &stored_rule(BOB),
        &stored_rule(MAKER),
        u64::MAX,
    );
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x97; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // However far out, the proposal has not matured and the old primary
    // still acts alone.
    let far = t0 + 100 * DAY_MS;
    assert_acts(&world, &store, ALICE, far, true, 0x98);
    assert_acts(&world, &store, BOB, far, false, 0x99);

    // The veto ends it, and nothing about the account has moved.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&veto_by(MAKER), TxHash(Hash32([0x9A; 32])))],
        Some(MAKER),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("veto must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&Some(Vec::new())),
        "a veto drops the proposal"
    );
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "and reaches no governing rule that was not frozen"
    );
    assert_acts(&world, &store, ALICE, far, true, 0x9B);
    assert_acts(&world, &store, BOB, far, false, 0x9C);
}

/// A hostile freeze under an effectively infinite delay waits on a
/// verdict rather than maturing: nobody acts however far out, the
/// proposal the freeze rides never reaches its instant, securify's door
/// stays shut, and the veto is what ends it — giving the displaced
/// primary back, so the funds were locked and never stolen.
#[test]
fn a_vetoed_freeze_gives_the_primary_back() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    seed_authority(
        &mut store,
        ALICE,
        &stored_rule(ALICE),
        &stored_rule(BOB),
        &stored_rule(MAKER),
        u64::MAX,
    );
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&freeze_by(BOB), TxHash(Hash32([0xB0; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("freeze must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(frozen(no_card()))),
        "an unmet delay gates a takeover, never the freeze"
    );

    // However far out, nobody acts: the primary entry is gone and the
    // proposal that would restore one never matures.
    let far = t0 + 1_000 * DAY_MS;
    assert_acts(&world, &store, ALICE, far, false, 0xB1);
    assert_acts(&world, &store, BOB, far, false, 0xB2);
    assert_acts(&world, &store, MAKER, far, false, 0xB3);
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&promote_by(BOB), TxHash(Hash32([0xB4; 32])))],
        Some(BOB),
        far,
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::Unmatured.code())],
        "a delay past the clock's reach is a proposal that never matures"
    );

    // Nor does securify: it is a one-way door and the cell is on the
    // far side of it.
    let securify = securify_graph(&StoredRule::claim(Claim::of_subject(ALICE)));
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&securify, TxHash(Hash32([0xB6; 32])))],
        Some(ALICE),
        far,
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(auth(ALICE)),
                required: Presence::Absent,
                // The securify, not the sign-in that precedes it: the
                // door is the second node's own.
                node: Some(0),
            },
        })],
        "securify is a one-way door and the cell is on the far side of it"
    );
    assert_eq!(amount_of(&store, vault(ALICE, RES_X)), 150);

    // The veto is what ends it: the displaced primary comes back.
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&veto_by(MAKER), TxHash(Hash32([0xB7; 32])))],
        Some(MAKER),
        far,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("veto must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(governing(ALICE))),
        "a veto gives back what the freeze displaced"
    );
    assert_acts(&world, &store, ALICE, far, true, 0xB8);
    assert_acts(&world, &store, BOB, far, false, 0xB9);
    assert_eq!(amount_of(&store, vault(ALICE, RES_X)), 150);
}

/// A veto ends a proposal: the recovery role cannot veto its own, and
/// the veto role enacts nothing — after it the account is exactly as
/// it was before the proposal.
#[test]
fn a_veto_ends_a_proposal_and_enacts_nothing() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x6D; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // The recovery key cannot veto its own proposal.
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&veto_by(BOB), TxHash(Hash32([0x6E; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        })],
        "recovery is not veto"
    );

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&veto_by(MAKER), TxHash(Hash32([0x6F; 32])))],
        Some(MAKER),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("veto must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&Some(Vec::new())),
        "a veto drops the proposal"
    );
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        None,
        "and enacts nothing"
    );

    // Past the instant the proposal named, Alice still governs and Bob
    // still does not.
    assert_acts(&world, &store, ALICE, t0 + DAY_MS, true, 0x70);
    assert_acts(&world, &store, BOB, t0 + DAY_MS, false, 0x71);
}

/// Nobody can veto where the account names no veto: the rule nobody
/// satisfies is what an account without an arbiter stores, and the
/// recovery role then wins every contest after the delay.
#[test]
fn an_account_without_a_veto_admits_no_veto() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    let t0 = env().clock_ms;
    let securify = securify_graph(&StoredRule::claim(Claim::of_subject(BOB)));
    let (results, store) = run_both(&world, &store, &[(&securify, TxHash(Hash32([0xE0; 32])))]);
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let hostile = graph_signed(BOB, |b| {
        account::propose(b, ALICE, governing_rule(MAKER), no_factor())
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&hostile, TxHash(Hash32([0xE1; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    for (who, tag) in [(BOB, 0xE2), (MAKER, 0xE3)] {
        let (results, _) = run_both_signed(
            &world,
            &store,
            &[(&veto_by(who), TxHash(Hash32([tag; 32])))],
            Some(who),
        );
        assert_eq!(
            results,
            vec![TxResult::Refused(Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { node: 0 },
            })],
            "the rule nobody satisfies admits nobody"
        );
    }

    // With no arbiter, the delay is the whole of the defence: past it
    // the proposal governs, and the key it named is the account.
    let at = t0 + DAY_MS;
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&promote_by(TAKER), TxHash(Hash32([0xE4; 32])))],
        Some(TAKER),
        at,
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    assert_acts(&world, &store, MAKER, at, true, 0xE5);
    assert_acts(&world, &store, BOB, at, false, 0xE6);
}

/// A verdict names the proposal its signer saw. A veto signed against
/// the first proposal and included after a second replaced it is refused
/// rather than answering the second in its place — and the second is
/// ended by the verdict that names it.
#[test]
fn a_verdict_names_the_proposal_its_signer_saw() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0xD0; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // Bob replaces his proposal with the maker's rule before the
    // maker's veto of the first is included.
    let replace = graph_signed(BOB, |b| {
        account::propose(b, ALICE, governing_rule(MAKER), no_factor())
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&replace, TxHash(Hash32([0xD1; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // The veto the maker signed names the first, and answers nothing:
    // the second still waits.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&veto_by(MAKER), TxHash(Hash32([0xD2; 32])))],
        Some(MAKER),
    );
    assert_eq!(
        results,
        vec![TxResult::Declined(account::Error::NoSuchProposal.code())],
        "a verdict on a superseded proposal answers nothing"
    );

    // Naming the second ends the second.
    let second = graph_signed(MAKER, |b| account::veto(b, ALICE, FIRST + 1));
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&second, TxHash(Hash32([0xD5; 32])))],
        Some(MAKER),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!(
            "the verdict naming the proposal waiting ends it; got {:?}",
            results[0]
        );
    };
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&Some(Vec::new())),
        "no replacement waits"
    );
    assert_acts(&world, &store, ALICE, t0 + DAY_MS, true, 0xD6);
    assert_acts(&world, &store, MAKER, t0 + DAY_MS, false, 0xD7);
}

/// A second propose replaces an unmatured proposal — its timer restarts
/// from the replacing clock — and an unsecurified account has nothing
/// to propose against: the filing is refused on the governing cell's
/// absence.
#[test]
fn propose_replaces_a_pending_proposal_and_needs_a_cell() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_by(BOB), TxHash(Hash32([0x72; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // Replace it half a day later: one proposal, the fresh instant.
    let later = t0 + DAY_MS / 2;
    let replace = graph_signed(BOB, |b| {
        account::propose(b, ALICE, governing_rule(MAKER), no_factor())
    });
    let (results, _) = run_both_at(
        &world,
        &store,
        &[(&replace, TxHash(Hash32([0x73; 32])))],
        Some(BOB),
        later,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("propose must complete; got {:?}", results[0]);
    };
    let mut replaced = MemoryStore::new();
    seed_proposal(
        &mut replaced,
        ALICE,
        FIRST + 1,
        later + DAY_MS,
        factors(&stored_rule(MAKER), None),
    );
    assert_eq!(
        receipt.delta.cells.get(&own_cell(ALICE, 2)),
        Some(&replaced.cell(own_cell(ALICE, 2))),
        "one replacement waiting, restarted from the replacing clock"
    );

    // A virtual account has nothing stored anywhere, so the address's
    // own key is what governs every one of its rules — including the one
    // that may replace them. The gate admits the owner; the filing does
    // not: the recovery surface exists only once the account has
    // securified, since no verdict could reach a record filed before,
    // and the door is the governing cell's presence.
    let mut virtual_store = sealed_store();
    virtual_store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());
    let own_propose = graph(|b| account::propose(b, ALICE, governing_rule(BOB), no_factor()));
    let (results, _) = run_both_signed(
        &world,
        &virtual_store,
        &[(&own_propose, TxHash(Hash32([0x74; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(auth(ALICE)),
                required: Presence::Present,
                node: Some(0),
            },
        })],
        "an account still governed by its own key has nothing to propose against"
    );

    // A stranger meets the same door, judged before the gate the
    // absent recovery cell would have refused them at.
    let (results, _) = run_both_signed(
        &world,
        &virtual_store,
        &[(&propose_by(BOB), TxHash(Hash32([0x75; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(auth(ALICE)),
                required: Presence::Present,
                node: Some(0),
            },
        })],
        "the door is the same whoever knocks"
    );
}

#[test]
fn custody_opens_for_the_holder_and_only_the_holder() {
    let world = world();
    let store = sealed_store();

    let badge = nf_resource();
    let gated = gated_by(badge.address(), 9);
    let operate_as = |who: PrincipalAddr, id: u64| {
        graph_signed(who, |b| {
            let held = account::present_instance(b, who, badge, id)?;
            nf::operate(b, gated, held)
        })
    };

    // Seat the badge: one minted instance into Alice's holdings.
    let seat = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, minted)
    });
    let (results, store) = run_both(&world, &store, &[(&seat, TxHash(Hash32([0x71; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
    let held = |store: &MemoryStore| -> Vec<u64> {
        store
            .collection_entries()
            .filter(|(key, _)| {
                (key.owner, key.collection)
                    == (
                        ALICE.address(),
                        holdings_collection(&TestHasher, ALICE, badge),
                    )
            })
            .map(|(key, _)| u64::try_from(key.order).unwrap())
            .collect()
    };
    let id = held(&store)[0];

    // The holder operates; a non-holder's own custody refuses on
    // possession; and the holder's custody presented by somebody else is
    // inadmissible — holding is the holder's to present.
    let (results, store) = run_both_each(
        &world,
        &store,
        &[
            (&operate_as(ALICE, id), TxHash(Hash32([0x72; 32])), ALICE),
            (&operate_as(BOB, id), TxHash(Hash32([0x73; 32])), BOB),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    // A non-holder fails the possession condition, judged by the shard
    // holding the entry before anything runs.
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Entry {
                    owner: BOB.into(),
                    collection: holdings_collection(&TestHasher, BOB, badge),
                    order: u128::from(id),
                },
                required: Presence::Present,
                node: Some(0),
            },
        })
    );
    // And the holder's custody presented by somebody else does not
    // compose at all: a custody gate names the holder, and Bob's intent
    // speaks for Bob. Written by hand, because the builder refuses it.
    let presented_by_bob = ManifestGraph {
        nodes: Capped::from_array([GraphNode {
            target: ALICE.into(),
            method: "present_instance".into(),
            args: vec![
                GraphArg::Literal(Value::Address(badge.address())),
                GraphArg::Literal(Value::U64(id)),
            ],
            evidence: Capped::from_members([ClaimRef::Account(BOB)]),
        }]),
    };
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&presented_by_bob, TxHash(Hash32([0x74; 32])))],
        Some(BOB),
    );
    assert_eq!(results[0], TxResult::Inadmissible(0));

    // The badge moves to Bob: operatorship moves with it, and the
    // seller's custody opens nothing.
    let transfer = graph(|b| {
        let moved = account::withdraw_nf(b, ALICE, badge, &[id])?;
        account::deposit_nf(b, BOB, moved)
    });
    let (results, _) = run_both_each(
        &world,
        &store,
        &[
            (&transfer, TxHash(Hash32([0x75; 32])), ALICE),
            (&operate_as(BOB, id), TxHash(Hash32([0x76; 32])), BOB),
            (&operate_as(ALICE, id), TxHash(Hash32([0x77; 32])), ALICE),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    // The seller no longer holds the instance, so the possession
    // condition refuses before anything about authority is asked.
    assert_eq!(
        results[2],
        TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Entry {
                    owner: ALICE.into(),
                    collection: holdings_collection(&TestHasher, ALICE, badge),
                    order: u128::from(id),
                },
                required: Presence::Present,
                node: Some(0),
            },
        })
    );
}

/// One badge resource, one instance per admin: the shape every real
/// permission system takes, and the one the whole plan exists to reach.
///
/// Two holders of distinct instances of one resource present distinct
/// claims, so a gate naming one instance refuses the holder of the
/// other. The resource-naming gate still admits both, because a holder
/// of an instance holds the badge — which is what makes revoking an
/// admin a burn rather than a redeploy.
#[test]
fn distinct_instances_of_one_badge_are_distinct_authorities() {
    let mut world = world();
    let store = sealed_store();
    let badge = nf_resource();

    // Seat one instance on each holder.
    let seat = graph(|b| {
        let first = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, first)?;
        let second = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, BOB, second)
    });
    let (results, mut store) = run_both(&world, &store, &[(&seat, TxHash(Hash32([0x81; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
    let held = |store: &MemoryStore, who: PrincipalAddr| -> Vec<u64> {
        store
            .collection_entries()
            .filter(|(key, _)| {
                (key.owner, key.collection)
                    == (who.address(), holdings_collection(&TestHasher, who, badge))
            })
            .map(|(key, _)| u64::try_from(key.order).unwrap())
            .collect()
    };
    let alices = held(&store, ALICE)[0];
    let bobs = held(&store, BOB)[0];
    assert_ne!(alices, bobs, "the two hold different instances");

    // A consumer gated on Alice's instance, and one gated on the badge
    // resource at large. Both are ordinary instances of the same
    // package; what differs is the configuration each names.
    let by_instance = InstanceMeta {
        package: pkg("nf"),
        config: Capped::new(vec![Value::Address(badge.address()), Value::U64(alices)]).unwrap(),
        salt: Hash32([12; 32]),
    };
    let by_instance_addr = by_instance.address(&TestHasher);
    seal(&mut store, &by_instance);
    world.instances.create(&TestHasher, by_instance);
    let by_resource = gated_by(badge.address(), 9);

    let operate_instance = |who: PrincipalAddr, id: u64| {
        graph_signed_in(&world, who, |b| {
            let held = account::present_instance(b, who, badge, id)?;
            nf::operate_instance(b, by_instance_addr, held)
        })
    };
    let operate_resource = |who: PrincipalAddr, id: u64| {
        graph_signed_in(&world, who, |b| {
            let held = account::present_instance(b, who, badge, id)?;
            nf::operate(b, by_resource, held)
        })
    };

    // The instance the gate names opens it; the sibling instance does
    // not, though it is the same resource and its holder holds it.
    let (results, _) = run_both_each(
        &world,
        &store,
        &[
            (
                &operate_instance(ALICE, alices),
                TxHash(Hash32([0x82; 32])),
                ALICE,
            ),
            (
                &operate_instance(BOB, bobs),
                TxHash(Hash32([0x83; 32])),
                BOB,
            ),
        ],
    );
    assert!(
        matches!(results[0], TxResult::Completed(_)),
        "the named instance's holder acts"
    );
    assert_eq!(
        results[1],
        TxResult::Inadmissible(1),
        "a sibling instance of the same resource is a different authority"
    );

    // The resource-naming gate admits either holder: the instance claim
    // carries the badge it is an instance of.
    let (results, _) = run_both_each(
        &world,
        &store,
        &[
            (
                &operate_resource(ALICE, alices),
                TxHash(Hash32([0x84; 32])),
                ALICE,
            ),
            (
                &operate_resource(BOB, bobs),
                TxHash(Hash32([0x85; 32])),
                BOB,
            ),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
}

/// A fixed admin set, expressed once: three badge instances in
/// configuration, any two of which open the surface.
///
/// The asymmetry this closes is that a *stored* rule always had the
/// threshold algebra while a *compile-time* gate had `contains` and
/// nothing else, so an object whose admins are fixed at publish could
/// not say "two of these three" and an account whose keys are stored
/// could.
///
/// What the gate counts is claims, not signers: the three instances are
/// seated on one holder here because one intent carries one signature,
/// and a deployment seating them on three accounts composes the same
/// presentations across three signed intents.
#[test]
fn a_declared_threshold_admits_exactly_its_quorum() {
    let mut world = world();
    let store = sealed_store();
    let badge = nf_resource();

    // Four instances: three the configuration names, one it does not.
    let seat = graph(|b| {
        for _ in 0..4 {
            let minted = nf::mint(b, nf_issuer())?;
            account::deposit_nf(b, ALICE, minted)?;
        }
        Ok(())
    });
    let (results, mut store) = run_both(&world, &store, &[(&seat, TxHash(Hash32([0x91; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
    let mut ids: Vec<u64> = store
        .collection_entries()
        .filter(|(key, _)| {
            (key.owner, key.collection)
                == (
                    ALICE.address(),
                    holdings_collection(&TestHasher, ALICE, badge),
                )
        })
        .map(|(key, _)| u64::try_from(key.order).unwrap())
        .collect();
    ids.sort_unstable();
    let (admins, rest) = ids.split_at(3);
    let outsider = rest[0];

    // The consumer names the three and asks for two.
    let quorum = InstanceMeta {
        package: pkg("nf"),
        config: Capped::new(vec![
            Value::Address(badge.address()),
            Value::U64(admins[0]),
            Value::U64(admins[1]),
            Value::U64(admins[2]),
        ])
        .unwrap(),
        salt: Hash32([13; 32]),
    };
    let quorum_addr = quorum.address(&TestHasher);
    seal(&mut store, &quorum);
    world.instances.create(&TestHasher, quorum);

    let operate = |presented: &[u64]| {
        let presented = presented.to_vec();
        graph_in(&world, |b| {
            let proofs = presented
                .into_iter()
                .map(|id| account::present_instance(b, ALICE, badge, id))
                .collect::<Result<Vec<_>, _>>()?;
            nf::operate_quorum(b, quorum_addr, &proofs)
        })
    };

    // Two of the three opens it, in either pairing.
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (
                &operate(&[admins[0], admins[1]]),
                TxHash(Hash32([0x92; 32])),
            ),
            (
                &operate(&[admins[1], admins[2]]),
                TxHash(Hash32([0x93; 32])),
            ),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));

    // One is not a quorum, and an instance the configuration does not
    // name is not an admin — so a pair including it is one branch short,
    // though its holder holds the badge and every instance is real.
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (&operate(&[admins[0]]), TxHash(Hash32([0x94; 32]))),
            (&operate(&[admins[0], outsider]), TxHash(Hash32([0x95; 32]))),
        ],
    );
    assert_eq!(results[0], TxResult::Inadmissible(1));
    assert_eq!(results[1], TxResult::Inadmissible(2));
}

#[test]
fn a_fungible_badge_is_custody_while_the_vault_is_funded() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(1).to_vec());

    let gated = gated_by(RES_X.address(), 10);
    let operate_as = |who: PrincipalAddr| {
        graph_signed(who, |b| {
            let held = account::present_badge(b, who, RES_X)?;
            nf::operate(b, gated, held)
        })
    };
    let (results, _) = run_both_each(
        &world,
        &store,
        &[
            (&operate_as(ALICE), TxHash(Hash32([0x78; 32])), ALICE),
            (&operate_as(BOB), TxHash(Hash32([0x79; 32])), BOB),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    // A non-holder fails the possession condition at its own vault.
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(vault(BOB, RES_X)),
                required: Presence::Present,
                node: Some(0),
            },
        })
    );
}

/// Spending the last of a badge closes the custody it opened.
///
/// Fungible possession is leaf-presence, and what makes that the same
/// question as "holds any of it" is delete-at-zero: a drained vault is
/// absent, not a cell holding zero. A lingering leaf would keep the
/// gate open for a holder who has nothing, so this pins the drain and
/// the refusal it causes as one fact.
#[test]
fn a_drained_badge_vault_closes_the_custody_it_opened() {
    let world = world();
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(1).to_vec());

    // Alice spends the whole of it, so the leaf is removed rather than
    // written back as zero.
    let drain = graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 1)?;
        account::deposit(b, BOB, funds)
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&drain, TxHash(Hash32([0x7A; 32])))],
        Some(ALICE),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    assert_eq!(
        store.cell(vault(ALICE, RES_X)),
        None,
        "a drained value leaf is absent, not zero bytes"
    );

    // And the gate that her holding opened is shut, refused at the
    // vault she no longer has.
    let gated = gated_by(RES_X.address(), 10);
    let operate = graph(|b| {
        let held = account::present_badge(b, ALICE, RES_X)?;
        nf::operate(b, gated, held)
    });
    let (results, _) = run_both(&world, &store, &[(&operate, TxHash(Hash32([0x7B; 32])))]);
    assert_eq!(
        results[0],
        TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(vault(ALICE, RES_X)),
                required: Presence::Present,
                node: Some(0),
            },
        })
    );
}
