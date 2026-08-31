//! The composed-transaction fixture: a two-signer envelope tree —
//! composer and subintent trading across yield edges — admitted,
//! routed, and executed through the batch executor on both runtimes,
//! with the nullifier making the subintent once-only.

use std::sync::LazyLock;

use hyperscale_vm_effects::{
    AdmittedTree, Constraint, EnvelopeTree, Hasher, IntentHeader, NullifierCell, PackageHash,
    PrefixShardResolver, Records, TestHasher, admit_tree, route_tree,
};
use hyperscale_vm_harness::driver::{Lanes, amount_of, cells, run_lanes, seed_vault, vault};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_kernel::{BatchOutcome, BatchTx, EnvInputs, MemoryStore};
use hyperscale_vm_manifest_builder::EnvelopeBuilder;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{AbortReason, NetworkId, Outcome, PrincipalAddr, ResourceAddr, TxHash};
use wasmtime::Result;
use wasmtime::error::{Context, ensure};

/// Any network; these tests only need every intent to name the same one.
const TEST_NETWORK: NetworkId = NetworkId(242);

/// Any window; these tests never validate one against a clock.
const TEST_HEADER: IntentHeader = IntentHeader {
    network: TEST_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const CAROL: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

const fn env() -> EnvInputs {
    EnvInputs::unsealed(3_000)
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> Records {
    let mut chain = Records::new();
    chain.packages.publish_unchecked(pkg(), account::metadata());
    chain.instances.serve_principals(pkg());
    chain
}

/// The composition: the composer pays `pay` of X for the subintent's 10
/// Y — each side withdraws its leg, exports it, and deposits the other's
/// yield. Neither graph names the other; the envelope is the two edges
/// between them.
fn composed_tree(composer: PrincipalAddr, pay: u128) -> EnvelopeTree {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, composer, TEST_HEADER);

    let taken = root.declare(RES_Y, [Constraint::MinAmount(10)]);
    let funds = account::withdraw(&mut root, composer, RES_X, pay).expect("withdraw types");
    let paid_x = root.export(funds);
    account::deposit(&mut root, composer, taken).expect("deposit types");

    let mut sub = env.subintent(BOB, TEST_HEADER);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, 10).expect("withdraw types");
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken).expect("deposit types");

    let wants_y = env
        .seal(root)
        .expect("the root discharges its declaration")
        .one()
        .expect("the root declares one socket");
    let wants_x = env
        .seal(sub)
        .expect("the subintent discharges its declaration")
        .one()
        .expect("the subintent declares one socket");
    env.bind(wants_y, paid_y).expect("the socket takes an edge");
    env.bind(wants_x, paid_x).expect("the socket takes an edge");
    env.build().expect("every socket is bound")
}

/// Admit and route one envelope into its batch entry, plus the manifest
/// its runner walks.
fn batch_entry(
    world: &Records,
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
) -> Result<(BatchTx, AdmittedTree)> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, composer, identity, world, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    // The null resolver puts every effect on one shard, so the whole
    // declaration is the sole entry — taken as that rather than by naming
    // an id the resolver is free to choose.
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    // The whole declaration, both views, straight from the fold: the
    // clause order is what a handle's rep indexes into, so taking the
    // folded set's order instead would hand the guest a table the
    // lowered calls were not resolved against.
    let declaration = routing.declaration().clone();
    let entry = BatchTx::new(TxHash(identity.0), declaration, env())
        .with_calls(routing.calls)
        .with_nullifiers(admitted.subintents.clone());
    Ok((entry, admitted))
}

/// The lanes, seeded once per binary: the account guest compiled and
/// decoded, plus its native body.
static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let bytes = build_guest("account").expect("the account guest builds");
    let mut lanes = Lanes::new();
    lanes.seed(pkg(), &bytes);
    lanes.seed_native(pkg(), account::invoke);
    lanes
});

fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> (BatchOutcome, MemoryStore) {
    run_lanes(&LANES, store, batch)
}

fn seeded_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    seed_vault(&mut store, ALICE, RES_X, 150);
    seed_vault(&mut store, CAROL, RES_X, 150);
    seed_vault(&mut store, BOB, RES_Y, 30);
    store
}

#[test]
fn a_composed_transaction_settles_on_both_runtimes() -> Result<()> {
    let world = world();
    let tree = composed_tree(ALICE, 100);
    let (entry, admitted) = batch_entry(&world, &tree, ALICE)?;
    let record = admitted.subintents[0];
    let nullifier = record.nullifier;

    let (outcome, end) = run_both(&seeded_store(), std::slice::from_ref(&entry));
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&end, vault(ALICE, RES_Y)), 10);
    assert_eq!(amount_of(&end, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 100);
    // The spent nullifier records the subintent it consumed, the
    // transaction that consumed it, and when the record stops being
    // owed — receipt and state alike.
    let spend = NullifierCell {
        subintent: record.subintent,
        tx: entry.tx,
        expiry_ms: record.expiry_ms,
    }
    .to_bytes();
    assert_eq!(cells(&end).get(&nullifier), Some(&spend));
    assert_eq!(
        outcome.receipts[&entry.tx].delta.cells.get(&nullifier),
        Some(&Some(spend))
    );
    Ok(())
}

#[test]
fn racing_compositions_commit_exactly_one() -> Result<()> {
    // Two composers carry the same signed subintent: same nullifier,
    // one conflict group, canonical order picks the winner.
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100), ALICE)?;
    let (carol_entry, carol_admitted) = batch_entry(&world, &composed_tree(CAROL, 120), CAROL)?;
    assert_eq!(
        alice_admitted.subintents[0].nullifier,
        carol_admitted.subintents[0].nullifier
    );
    let alice_wins = alice_entry.tx < carol_entry.tx;
    let batch = vec![alice_entry.clone(), carol_entry.clone()];
    let (outcome, end) = run_both(&seeded_store(), &batch);

    let (winner, loser, pay) = if alice_wins {
        (&alice_entry, &carol_entry, 100)
    } else {
        (&carol_entry, &alice_entry, 120)
    };
    assert!(
        matches!(
            outcome.receipts[&winner.tx].outcome,
            Outcome::Completed { .. }
        ),
        "winner: {:?}",
        outcome.receipts[&winner.tx].outcome,
    );
    // A lost race, not a defect: canonical order picked the winner and
    // the loser could not have known which it would be.
    assert_eq!(
        outcome.receipts[&loser.tx].outcome,
        Outcome::NullifierSpent {
            key: alice_admitted.subintents[0].nullifier,
        }
    );

    let (winner_addr, loser_addr) = if alice_wins {
        (ALICE, CAROL)
    } else {
        (CAROL, ALICE)
    };
    assert_eq!(amount_of(&end, vault(winner_addr, RES_X)), 150 - pay);
    assert_eq!(amount_of(&end, vault(winner_addr, RES_Y)), 10);
    assert_eq!(amount_of(&end, vault(loser_addr, RES_X)), 150);
    assert_eq!(amount_of(&end, vault(loser_addr, RES_Y)), 0);
    // The subintent leg settled exactly once.
    assert_eq!(amount_of(&end, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), pay);
    let record = alice_admitted.subintents[0];
    assert_eq!(
        cells(&end).get(&record.nullifier),
        Some(
            &NullifierCell {
                subintent: record.subintent,
                tx: winner.tx,
                expiry_ms: record.expiry_ms,
            }
            .to_bytes()
        )
    );
    Ok(())
}

#[test]
fn a_spent_nullifier_blocks_the_next_batch() -> Result<()> {
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100), ALICE)?;
    let (carol_entry, _) = batch_entry(&world, &composed_tree(CAROL, 120), CAROL)?;
    let nullifier = alice_admitted.subintents[0].nullifier;

    let (_, committed) = run_both(&seeded_store(), std::slice::from_ref(&alice_entry));

    let (second, second_end) = run_both(&committed, std::slice::from_ref(&carol_entry));
    assert_eq!(
        second.receipts[&carol_entry.tx].outcome,
        Outcome::NullifierSpent { key: nullifier }
    );
    assert_eq!(amount_of(&second_end, vault(CAROL, RES_X)), 150);
    assert_eq!(amount_of(&second_end, vault(BOB, RES_Y)), 20);
    Ok(())
}

/// A transaction that spends its signed ceiling aborts the same way on
/// both runtimes, and applies nothing.
///
/// The budget is per transaction, not per invocation: a manifest's nodes
/// draw from one allowance, so what the sender declared bounds the whole
/// transaction rather than each of its calls. Exhaustion is the sender's
/// own defect and prices as one — and the reason is fixed here rather
/// than taken from the trap, because each engine words its own and the
/// classification is consensus content.
#[test]
fn a_transaction_that_spends_its_gas_limit_aborts_on_both_runtimes() -> Result<()> {
    let world = world();
    let (entry, _) = batch_entry(&world, &composed_tree(ALICE, 100), ALICE)?;

    // Enough to enter the guest and not enough to leave it. The figure
    // is between the two and moves with the code: below it the walk
    // refuses before the invocation, above it the whole tree settles.
    let starved = entry.with_gas_limit(1000);
    let (outcome, end) = run_both(&seeded_store(), std::slice::from_ref(&starved));

    match &outcome.receipts[&starved.tx].outcome {
        Outcome::UserError { reason } => assert_eq!(*reason, AbortReason::OutOfGas),
        other => panic!("expected the gas ceiling to abort it, got {other:?}"),
    }
    // Nothing moved: the seeded balances stand.
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&end, vault(BOB, RES_X)), 0);
    Ok(())
}
