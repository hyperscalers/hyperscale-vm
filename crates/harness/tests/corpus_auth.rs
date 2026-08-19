//! Authority end to end on both runtimes: sign-in rules, securify,
//! chained rules, minted proofs, recovery proposals, and the custody
//! gates badges open.

use hyperscale_vm_effects::{
    AuthBase, AuthCell, Hash32, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache,
    Presented, Proposal, RoleSet, StoredRule, TestHasher, Value, holdings_collection,
};
use hyperscale_vm_fixtures::nf;
use hyperscale_vm_harness::driver::{amount_of, vault};
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    AbortReason, EffectTarget, Outcome, Presence, PrincipalAddr, TxHash, encode_amount,
};
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

#[test]
fn a_refused_authorization_takes_its_consumers_with_it() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();

    // Bob's signature behind Alice's sign-in: admission passes — the
    // evidence is present, and whether it satisfies the target is the
    // target's question — and the authorizing node's own gate refuses at
    // execution, taking the whole transaction with it. This is what
    // makes the minted proof sound with nothing checking it later: the
    // withdrawal that would have spent on it never runs.
    let graph = authorized_transfer_graph();
    let (results, final_store) = run_both_signed(
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0B; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })]
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 0);
}

/// Sign in and hand the account to Bob's rule, uniformly.
fn securify_graph(rule: StoredRule) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        account::securify_uniform(b, alice, rule, DAY_MS)
    })
}

/// The whole one-way door, end to end on both runtimes: an account
/// securifies to another principal's rule; its old key stops opening
/// its own sign-in, the new rule's key does, and a second securify
/// refuses.
#[test]
fn securify_retires_the_old_key_and_installs_the_rule() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();

    // Alice's last act under the virtual rule: signing in for its
    // retirement. Everything she stores from here is governed by Bob.
    let securify = securify_graph(StoredRule::Require(Presented::of_address(BOB.address())));
    let (results, store) = run_both(&world, &store, &[(&securify, TxHash(Hash32([0x51; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("securify must complete; got {:?}", results[0]);
    };
    let cell_bytes = AuthCell::new(uniform_base(BOB.address()))
        .to_bytes()
        .unwrap();
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(cell_bytes)),
        "the guest's spliced frame is the codec's encoding, byte for byte"
    );

    // The old key still derives Alice's address, and that identity is
    // exactly what her rule no longer admits: her own sign-in refuses,
    // and everything behind it is unreachable.
    let transfer = authorized_transfer_graph();
    let (results, store) = run_both(&world, &store, &[(&transfer, TxHash(Hash32([0x52; 32])))]);
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })],
        "the retired key must not open the account"
    );

    // Bob's signature carries Bob's identity, the stored rule admits
    // it, and the minted proof opens Alice's guarded methods.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&transfer, TxHash(Hash32([0x53; 32])))],
        Some(BOB),
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
    let again = securify_graph(StoredRule::Require(Presented::of_address(BOB.address())));
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&again, TxHash(Hash32([0x54; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::PresenceUnmet {
            target: EffectTarget::Point(auth(ALICE)),
            required: Presence::Absent,
        })],
        "a one-way door is a declared precondition, not a guest panic — and \
         losing the race to it is priced as one"
    );
}

/// A store where entry to one account chains through another: Alice's
/// rule names Bob's key, and the maker's rule names Alice's account —
/// so the maker's funds move only through a proof minted inside the
/// same transaction.
fn chained_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(MAKER, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(
            auth(ALICE),
            AuthCell::new(uniform_base(BOB.address()))
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
    store
        .write(
            auth(MAKER),
            AuthCell::new(uniform_base(ALICE.address()))
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
    store
}

/// Two stored rules deep, on both runtimes: Bob's signature opens
/// Alice's sign-in, and the proof it mints opens the maker's — an entry
/// no signature reaches directly, since the maker's rule names an
/// account rather than a key the intent could carry.
#[test]
fn a_chained_sign_in_acts_two_rules_deep() {
    let world = world();
    let store = chained_store();

    // The direct route refuses: Bob's own sign-in mints Bob's identity,
    // and the maker's rule admits only Alice's.
    let direct = graph(|b| {
        let bob = account::authorize(b, BOB)?;
        let maker = account::authorize_as(b, bob, MAKER)?;
        let funds = account::withdraw(b, maker, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&direct, TxHash(Hash32([0x61; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 1 })],
        "the maker's rule names Alice's account, not Bob's"
    );

    let transfer = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let maker = account::authorize_as(b, alice, MAKER)?;
        let funds = account::withdraw(b, maker, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    });
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&transfer, TxHash(Hash32([0x62; 32])))],
        Some(BOB),
    );
    assert!(
        matches!(&results[0], TxResult::Completed(_)),
        "the chain must open the maker's account; got {:?}",
        results[0]
    );
    assert_eq!(amount_of(&store, vault(MAKER, RES_X)), 50);
    assert_eq!(amount_of(&store, vault(BOB, RES_X)), 100);
}

/// A minted proof opens only its own account: presented at another's
/// guarded method it refuses at that node's gate, however valid the
/// sign-in that minted it.
#[test]
fn a_proof_opens_only_the_account_that_minted_it() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(BOB, RES_X), encode_amount(150).to_vec())
        .unwrap();

    // Alice signs in as herself, then aims her proof at Bob's vault —
    // composable and admissible, and dead at Bob's gate.
    let theft = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = b
            .call_as(alice, BOB, "withdraw", (RES_X, 100_u128))?
            .one()?;
        account::deposit(b, ALICE, funds)
    });
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&theft, TxHash(Hash32([0x63; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 1 })],
        "a proof is its own account's identity and no other's"
    );
}

/// The split-role setup every recovery test starts from: Alice holds
/// primary, Bob recovery, the maker confirmation, and the corpus delay
/// separates a proposal from its maturity.
const fn split_roles() -> RoleSet {
    RoleSet {
        primary: StoredRule::Require(Presented::of_address(ALICE.address())),
        recovery: StoredRule::Require(Presented::of_address(BOB.address())),
        confirmation: StoredRule::Require(Presented::of_address(MAKER.address())),
    }
}

fn split_base() -> AuthBase {
    AuthBase::new(DAY_MS, &split_roles()).expect("a rule within the vocabulary caps")
}

/// A store holding Alice's funds and her securified split-role cell,
/// written as the guest would write it.
fn recovered_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(auth(ALICE), AuthCell::new(split_base()).to_bytes().unwrap())
        .unwrap();
    store
}

fn cancel_graph() -> ManifestGraph {
    graph(|b| account::cancel(b, ALICE))
}

fn confirm_graph() -> ManifestGraph {
    graph(|b| account::confirm(b, ALICE))
}

/// Whether `signer` opens Alice's sign-in at `clock_ms`: the whole
/// authorized transfer completes, or refuses at its authorize node.
fn assert_acts(
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    signer: PrincipalAddr,
    clock_ms: u64,
    admits: bool,
    tag: u8,
) {
    let transfer = authorized_transfer_graph();
    let (results, _) = run_both_at(
        world,
        store,
        &[(&transfer, TxHash(Hash32([tag; 32])))],
        Some(signer),
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
            vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })],
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
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })],
        "primary is not recovery"
    );

    // Bob proposes himself; the instant is the clock plus the stored
    // delay, and the written frame is the codec's encoding exactly.
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x61; 32])))],
        Some(BOB),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("propose must complete; got {:?}", results[0]);
    };
    let pending = AuthCell {
        base: split_base(),
        proposal: Some(Proposal {
            effective_at_ms: t0 + DAY_MS,
            base: uniform_base(BOB.address()),
        }),
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(pending.to_bytes().unwrap())),
        "the guest's spliced frame is the codec's encoding, byte for byte"
    );

    // One instant before maturity the old roles govern whole: Alice
    // acts, Bob does not. At the instant the verdicts swap, with no
    // write between: the matured proposal governs at read time.
    let before = t0 + DAY_MS - 1;
    let at = t0 + DAY_MS;
    assert_acts(&world, &store, ALICE, before, true, 0x62);
    assert_acts(&world, &store, BOB, before, false, 0x63);
    assert_acts(&world, &store, BOB, at, true, 0x64);
    assert_acts(&world, &store, ALICE, at, false, 0x65);

    // A later cancel by the new primary compacts the matured proposal
    // into the base — it cannot cancel what already governs — and the
    // old primary stays retired.
    let (results, store) = run_both_at(
        &world,
        &store,
        &[(&cancel_graph(), TxHash(Hash32([0x66; 32])))],
        Some(BOB),
        at,
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("cancel must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(
            AuthCell::new(uniform_base(BOB.address()))
                .to_bytes()
                .unwrap()
        )),
        "cancelling a matured proposal is compaction, not reversal"
    );
    assert_acts(&world, &store, ALICE, at, false, 0x67);
}

/// Primary cancels an unmatured proposal, and every later verdict —
/// however far past the would-be maturity — is under the old roles, as
/// if nothing had been proposed.
#[test]
fn primary_cancels_an_unmatured_proposal() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x68; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&cancel_graph(), TxHash(Hash32([0x69; 32])))],
        Some(ALICE),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("cancel must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(AuthCell::new(split_base()).to_bytes().unwrap())),
        "the cell is exactly what securify wrote"
    );

    // Far past the would-be maturity, the old roles still govern: a
    // cancelled proposal never does.
    let long_after = t0 + 10 * DAY_MS;
    assert_acts(&world, &store, ALICE, long_after, true, 0x6A);
    assert_acts(&world, &store, BOB, long_after, false, 0x6B);

    // With nothing pending, confirm is the guest's own refusal.
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&confirm_graph(), TxHash(Hash32([0x6C; 32])))],
        Some(MAKER),
    );
    assert_eq!(results, vec![TxResult::Trapped(AbortReason::Unreachable)]);
}

/// Confirmation enacts a proposal early: the new roles govern from the
/// confirm, a day before the instant would have arrived on its own.
#[test]
fn confirmation_enacts_a_proposal_early() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x6D; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // The recovery key cannot confirm its own proposal.
    let (results, _) = run_both_signed(
        &world,
        &store,
        &[(&confirm_graph(), TxHash(Hash32([0x6E; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })],
        "recovery is not confirmation"
    );

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&confirm_graph(), TxHash(Hash32([0x6F; 32])))],
        Some(MAKER),
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("confirm must complete; got {:?}", results[0]);
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(
            AuthCell::new(uniform_base(BOB.address()))
                .to_bytes()
                .unwrap()
        )),
        "confirm promotes the proposal whole"
    );

    // Bob governs now — a day early — and Alice is retired now.
    assert_acts(&world, &store, BOB, t0, true, 0x70);
    assert_acts(&world, &store, ALICE, t0, false, 0x71);
}

/// A second propose replaces an unmatured proposal — its timer restarts
/// from the replacing clock — and an unsecurified account has nothing
/// to propose against.
#[test]
fn propose_replaces_a_pending_proposal_and_needs_a_cell() {
    let world = world();
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x72; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // Replace it half a day later: one proposal, the fresh instant.
    let later = t0 + DAY_MS / 2;
    let replace = graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(StoredRule::Require(Presented::of_address(MAKER.address()))),
            DAY_MS,
        )
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
    let replaced = AuthCell {
        base: split_base(),
        proposal: Some(Proposal {
            effective_at_ms: later + DAY_MS,
            base: uniform_base(MAKER.address()),
        }),
    };
    assert_eq!(
        receipt.delta.cells.get(&auth(ALICE)),
        Some(&Some(replaced.to_bytes().unwrap())),
        "one proposal, restarted from the replacing clock"
    );

    // A virtual account has no cell, so `propose` is refused where it
    // declares one: the write requires the leaf to be there, and the
    // shard holding it judges that against committed state after the
    // virtual rule signed the caller in and before the body runs.
    let mut virtual_store = MemoryStore::new();
    virtual_store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    let own_propose = graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(StoredRule::Require(Presented::of_address(BOB.address()))),
            DAY_MS,
        )
    });
    let (results, _) = run_both_signed(
        &world,
        &virtual_store,
        &[(&own_propose, TxHash(Hash32([0x74; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::PresenceUnmet {
            target: EffectTarget::Point(auth(ALICE)),
            required: Presence::Present,
        })]
    );
}

#[test]
fn custody_opens_for_the_holder_and_only_the_holder() {
    let world = world();
    let store = MemoryStore::new();

    let badge = nf_resource();
    let gated = gated_by(badge.address(), 9);
    let operate_as = |who: PrincipalAddr, id: u64| {
        graph(|b| {
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
    // possession; and the holder's custody presented by somebody else
    // refuses on the rule — holding is the holder's to present.
    let (results, store) = run_both(
        &world,
        &store,
        &[
            (&operate_as(ALICE, id), TxHash(Hash32([0x72; 32]))),
            (&operate_as(BOB, id), TxHash(Hash32([0x73; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::Unauthorized { node: 0 })
    );
    let (results, store) = run_both_signed(
        &world,
        &store,
        &[(&operate_as(ALICE, id), TxHash(Hash32([0x74; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results[0],
        TxResult::Refused(Outcome::Unauthorized { node: 0 })
    );

    // The badge moves to Bob: operatorship moves with it, and the
    // seller's custody opens nothing.
    let transfer = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let moved = account::withdraw_nf(b, alice, badge, &[id])?;
        account::deposit_nf(b, BOB, moved)
    });
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (&transfer, TxHash(Hash32([0x75; 32]))),
            (&operate_as(BOB, id), TxHash(Hash32([0x76; 32]))),
            (&operate_as(ALICE, id), TxHash(Hash32([0x77; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    assert_eq!(
        results[2],
        TxResult::Refused(Outcome::Unauthorized { node: 0 })
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
    let (cache, mut instances) = world();
    let store = MemoryStore::new();
    let badge = nf_resource();

    // Seat one instance on each holder.
    let seat = graph(|b| {
        let first = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, first)?;
        let second = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, BOB, second)
    });
    let (results, store) = run_both(
        &(cache.clone(), instances.clone()),
        &store,
        &[(&seat, TxHash(Hash32([0x81; 32])))],
    );
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
        config: vec![Value::Address(badge.address()), Value::U64(alices)],
        salt: Hash32([12; 32]),
    };
    let by_instance_addr = by_instance.address(&TestHasher);
    instances.create(&TestHasher, by_instance);
    let world = (cache, instances);
    let by_resource = gated_by(badge.address(), 9);

    let operate_instance = |who: PrincipalAddr, id: u64| {
        graph_in(&world, |b| {
            let held = account::present_instance(b, who, badge, id)?;
            nf::operate_instance(b, by_instance_addr, held)
        })
    };
    let operate_resource = |who: PrincipalAddr, id: u64| {
        graph_in(&world, |b| {
            let held = account::present_instance(b, who, badge, id)?;
            nf::operate(b, by_resource, held)
        })
    };

    // The instance the gate names opens it; the sibling instance does
    // not, though it is the same resource and its holder holds it.
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (&operate_instance(ALICE, alices), TxHash(Hash32([0x82; 32]))),
            (&operate_instance(BOB, bobs), TxHash(Hash32([0x83; 32]))),
        ],
    );
    assert!(
        matches!(results[0], TxResult::Completed(_)),
        "the named instance's holder acts"
    );
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::Unauthorized { node: 1 }),
        "a sibling instance of the same resource is a different authority"
    );

    // The resource-naming gate admits either holder: the instance claim
    // carries the badge it is an instance of.
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (&operate_resource(ALICE, alices), TxHash(Hash32([0x84; 32]))),
            (&operate_resource(BOB, bobs), TxHash(Hash32([0x85; 32]))),
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
    let (cache, mut instances) = world();
    let store = MemoryStore::new();
    let badge = nf_resource();

    // Four instances: three the configuration names, one it does not.
    let seat = graph(|b| {
        for _ in 0..4 {
            let minted = nf::mint(b, nf_issuer())?;
            account::deposit_nf(b, ALICE, minted)?;
        }
        Ok(())
    });
    let (results, store) = run_both(
        &(cache.clone(), instances.clone()),
        &store,
        &[(&seat, TxHash(Hash32([0x91; 32])))],
    );
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
        config: vec![
            Value::Address(badge.address()),
            Value::U64(admins[0]),
            Value::U64(admins[1]),
            Value::U64(admins[2]),
        ],
        salt: Hash32([13; 32]),
    };
    let quorum_addr = quorum.address(&TestHasher);
    instances.create(&TestHasher, quorum);
    let world = (cache, instances);

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
    assert_eq!(
        results[0],
        TxResult::Refused(Outcome::Unauthorized { node: 1 })
    );
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::Unauthorized { node: 2 })
    );
}

#[test]
fn a_fungible_badge_is_custody_while_the_vault_is_funded() {
    let world = world();
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(1).to_vec())
        .unwrap();

    let gated = gated_by(RES_X.address(), 10);
    let operate_as = |who: PrincipalAddr| {
        graph(|b| {
            let held = account::present_badge(b, who, RES_X)?;
            nf::operate(b, gated, held)
        })
    };
    let (results, _) = run_both(
        &world,
        &store,
        &[
            (&operate_as(ALICE), TxHash(Hash32([0x78; 32]))),
            (&operate_as(BOB), TxHash(Hash32([0x79; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        results[1],
        TxResult::Refused(Outcome::Unauthorized { node: 0 })
    );
}
