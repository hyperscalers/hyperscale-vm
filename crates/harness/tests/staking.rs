//! The stake pool: a delegation and its return, walked across two
//! packages in one transaction and executed identically on both runtimes.
//!
//! Every earlier corpus fixture runs one package's code. A delegation
//! runs two — the account's withdraw and deposit either side of the
//! pool's stake — so the backend resolves each call's code by the package
//! its lowered call names, which is the property the walk was built for
//! and which no single-package fixture can exercise.
//!
//! The assertion that matters for the beacon is the emitted event: its
//! payload is what the witness lift decodes into a stake-deposit, so the
//! bytes are pinned here at the boundary that produces them.
//!
//! Both packages run from their committed blobs rather than a rebuild,
//! so this is also the stake pool's conformance lane: what a consumer
//! embeds is what these assertions hold for.

use std::sync::LazyLock;

use hyperscale_vm_effects::vocabulary::CONFIG;
use hyperscale_vm_effects::{
    AdmissionError, EnvelopeTree, Hash32, Hasher, InstanceMeta, IntentDecl, ManifestGraph,
    PackageHash, PrefixShardResolver, Records, ResourceKind, ResourceRecord, TestHasher, Value,
    admit_tree, child_key, holdings_collection, instance_data_key, issued_resource,
    resource_record_key, route_tree,
};
use hyperscale_vm_harness::driver::{Lanes, amount_of, cells, run_lanes, seed_vault, vault};
use hyperscale_vm_kernel::{BatchOutcome, BatchTx, EnvInputs, MemoryStore, Substates};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_sdk::hbor::{from_slice, to_vec};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, STAKING_COMPONENT, account, staking};
use hyperscale_vm_types::{
    Address, Outcome, Presence, PrincipalAddr, ResourceAddr, SubstateKey, TxHash, UnmetCondition,
    encode_amount,
};
use wasmtime::Result;
use wasmtime::error::{Context, ensure};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// The resource a delegation is denominated in.
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
/// The resource this pool issues against delegations — derived from the
/// pool, not configured, which is what the signature's `SelfResource`
/// evaluates to.
fn unit() -> ResourceAddr {
    issued_resource(
        &TestHasher,
        pool(),
        ResourceKind::Fungible,
        staking::STAKE_UNIT,
    )
}
/// The pool's owner badge — the same derivation the operator gate
/// evaluates.
fn badge() -> ResourceAddr {
    issued_resource(
        &TestHasher,
        pool(),
        ResourceKind::NonFungible,
        staking::OWNER_BADGE,
    )
}
/// The badge instance the operator holds in these tests.
const BADGE_ID: u64 = 0;

/// Seal the pool: the cells its instantiation writes — the
/// configuration leaf that makes its methods reachable at all, and the
/// record of each mark it issues.
fn seal_pool(store: &mut MemoryStore) {
    store.write(
        child_key(&TestHasher, pool(), CONFIG, &[]),
        pool_meta().leaf_bytes().unwrap(),
    );
    store.write(
        resource_record_key(&TestHasher, pool(), unit()),
        UNIT_RECORD.to_cell().unwrap(),
    );
    store.write(
        resource_record_key(&TestHasher, pool(), badge()),
        BADGE_RECORD.to_cell().unwrap(),
    );
}

/// The records the pool's instantiation writes: one per mark it
/// declares, whether or not anything has been issued at it yet.
const UNIT_RECORD: ResourceRecord = ResourceRecord::Fungible { divisibility: 18 };
const BADGE_RECORD: ResourceRecord = ResourceRecord::NonFungible;

/// A store where [`OPERATOR`] holds the pool's owner badge — what every
/// operator-surface test starts from.
fn operator_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    seal_pool(&mut store);
    store.entry_write(
        OPERATOR.address(),
        holdings_collection(&TestHasher, OPERATOR, badge()),
        u128::from(BADGE_ID),
        Vec::new(),
    );
    store
}
/// The account holding the pool's owner badge: the operator surface
/// admits whoever presents it, and these tests seed it here.
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x0B; 31]);

/// A validator the pool operates, and the consensus material a
/// registration carries for it.
const VALIDATOR: u64 = 42;
const PUBKEY: [u8; 48] = [0xC1; 48];
const POSSESSION_PROOF: [u8; 96] = [0xC2; 96];

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 3_000,
        randomness: [6; 32],
    }
}

fn account_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn staking_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"staking"]))
}

/// Two packages, two kinds of instance: the account, and the pool with its
/// creation-fixed configuration — the resource it stakes. The units it
/// issues and the badge its operator surface admits derive from the pool's
/// own address; nothing configures which pool it is, the emitter answers
/// that.
fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(account_pkg(), account::metadata());
    chain
        .packages
        .publish_unchecked(staking_pkg(), staking::metadata());
    chain.instances.serve_principals(account_pkg());
    chain.instances.create(&TestHasher, pool_meta());
    chain
}

/// The pool's record: what it stakes. The resource it *issues* and the
/// owner badge its operator surface admits are both derived from the
/// pool, so they are deliberately not here.
fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: staking_pkg(),
        config: vec![
            Value::Address(XRD.address()),
            Value::Address(OPERATOR.address()),
        ],
        salt: Hash32([2; 32]),
    }
}

/// The pool instance, at the address its record derives.
fn pool() -> staking::Staking {
    staking::Staking::at(pool_meta().address(&TestHasher))
}

/// Build against this world's metadata, so every call is typed by the
/// signature it names and every edge carries the resource that signature
/// declares — neither of which is written out below.
fn graph(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher);
    write(&mut b).expect("every call types against its signature");
    b.build().expect("every output is consumed")
}

/// `alice.withdraw(XRD) -> pool.stake -> alice.deposit(units)`: the
/// delegation goes in and the position comes back as an ordinary balance.
fn stake_graph(amount: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, XRD, amount)?;
        let units = pool().stake(b, funds)?;
        account::deposit(b, ALICE, units)
    })
}

/// `alice.withdraw(UNIT) -> pool.unstake`: the units are destroyed.
/// Nothing comes back — the release leg is not built.
fn unstake_graph(amount: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let units = account::withdraw(b, alice, unit(), amount)?;
        pool().unstake(b, units)
    })
}

/// A delegation is denominated by the pool's configuration, so paying in
/// anything else is refused before the transaction exists.
///
/// The units a pool issues are a claim on what it holds; a pool crediting
/// its staked vault with some other resource would be issuing claims
/// against value it never took in.
#[test]
fn a_delegation_in_the_wrong_resource_is_refused_at_admission() {
    let world = world();
    let tree = single_intent(graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, unit(), 40)?;
        let units = pool().stake(b, funds)?;
        account::deposit(b, ALICE, units)
    }));
    let identity = tree.hash(&TestHasher);
    let refused = admit_tree(&tree, ALICE, identity, &world, &TestHasher)
        .expect_err("the pool takes its staked resource and this pays units");

    assert!(
        matches!(
            refused,
            AdmissionError::WrongDenomination { param: 0, expected, .. } if expected == XRD.address()
        ),
        "the refusal names the staked resource: {refused:?}"
    );
}

/// The control: the same delegation in the pool's own resource admits.
#[test]
fn a_delegation_in_the_pools_own_resource_admits() -> Result<()> {
    let world = world();
    let tree = single_intent(stake_graph(40));
    let identity = tree.hash(&TestHasher);
    admit_tree(&tree, ALICE, identity, &world, &TestHasher)
        .context("the pool's own resource is what it asks for")?;
    Ok(())
}

/// The pool's own record of one validator it operates.
fn validator_leaf(pool: impl Into<Address>, validator: u64) -> SubstateKey {
    child_key(
        &TestHasher,
        pool,
        staking::VALIDATORS,
        &[Value::U64(validator).canonical_bytes()],
    )
}

/// A one-node graph naming a validator on the pool's operator surface.
/// The method is a parameter because the tests below are about two of
/// them behaving alike, which is not a shape a wrapper per method has.
fn operator_graph(method: &str, validator: u64) -> ManifestGraph {
    graph(|b| {
        let operator = account::present_instance(b, OPERATOR, badge(), BADGE_ID)?;
        b.call_as(operator, pool(), method, (validator,))?.none()
    })
}

fn register_graph(validator: u64) -> ManifestGraph {
    graph(|b| {
        let operator = account::present_instance(b, OPERATOR, badge(), BADGE_ID)?;
        pool().register_validator(
            b,
            operator,
            validator,
            PUBKEY.to_vec(),
            POSSESSION_PROOF.to_vec(),
        )
    })
}

const fn single_intent(graph: ManifestGraph) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    }
}

/// Admit and route one envelope into its batch entry.
fn batch_entry(world: &Records, tree: &EnvelopeTree, composer: PrincipalAddr) -> Result<BatchTx> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, composer, identity, world, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().clone();
    Ok(BatchTx::new(TxHash(identity.0), declaration, env()).with_calls(routing.calls))
}

fn seeded_store(xrd: u128, units: u128) -> MemoryStore {
    let mut store = MemoryStore::new();
    seal_pool(&mut store);
    seed_vault(&mut store, ALICE, XRD, xrd);
    if units > 0 {
        seed_vault(&mut store, ALICE, unit(), units);
    }
    store
}

/// The lanes, seeded once per binary from the committed blobs, plus the
/// packages' own native bodies.
static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let mut lanes = Lanes::new();
    lanes.seed(account_pkg(), ACCOUNT_COMPONENT);
    lanes.seed(staking_pkg(), STAKING_COMPONENT);
    lanes.seed_native(account_pkg(), account::invoke);
    lanes.seed_native(staking_pkg(), staking::invoke);
    lanes
});

fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> (BatchOutcome, MemoryStore) {
    run_lanes(&LANES, store, batch)
}

/// The fence: a delegation to a pool whose creation never finished is
/// refused as the leaf's unmet presence, judged where the leaf lives,
/// before any body runs — so nothing vaults the funds and nothing mints
/// units against an object with no operator.
#[test]
fn a_delegation_to_an_unsealed_pool_is_refused_where_the_leaf_lives() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(stake_graph(100)), ALICE)?;

    let mut store = MemoryStore::new();
    store.write(
        resource_record_key(&TestHasher, pool(), unit()),
        UNIT_RECORD.to_cell().unwrap(),
    );
    seed_vault(&mut store, ALICE, XRD, 150);

    let (outcome, end) = run_both(&store, std::slice::from_ref(&entry));
    assert!(
        matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Present,
                    ..
                },
            }
        ),
        "refused as the unmet presence: {:?}",
        outcome.receipts[&entry.tx].outcome,
    );
    assert_eq!(amount_of(&end, vault(ALICE, XRD)), 150);
    assert_eq!(amount_of(&end, vault(pool(), XRD)), 0);
    assert_eq!(amount_of(&end, vault(ALICE, unit())), 0);
    Ok(())
}

#[test]
fn a_delegation_lands_in_the_pool_and_returns_units() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(stake_graph(100)), ALICE)?;

    let (outcome, end) = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry));
    let receipt = &outcome.receipts[&entry.tx];
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));

    // The delegation left the delegator and reached the pool.
    assert_eq!(amount_of(&end, vault(ALICE, XRD)), 50);
    assert_eq!(amount_of(&end, vault(pool(), XRD)), 100);
    // The position came back as an ordinary balance, at par.
    assert_eq!(amount_of(&end, vault(ALICE, unit())), 100);

    // What the beacon's witness lift consumes, pinned at the boundary that
    // produces it: the pool's own identifier and the staked amount.
    let staked = receipt
        .events
        .iter()
        .find(|event| event.emitter == Address::from(pool()))
        .expect("the pool emitted its event");
    assert_eq!(staked.event_type, 0);
    assert_eq!(staked.payload, encode_amount(100));
    Ok(())
}

#[test]
fn returned_units_are_destroyed_and_the_pool_says_what_it_owes() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(unstake_graph(40)), ALICE)?;

    let (outcome, end) = run_both(&seeded_store(0, 100), std::slice::from_ref(&entry));
    let receipt = &outcome.receipts[&entry.tx];
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));

    assert_eq!(amount_of(&end, vault(ALICE, unit())), 60);
    // The returned units are destroyed rather than parked, so the pool
    // holds no leaf of them and the shard's supply of them fell.
    assert_eq!(receipt.supply.burned(unit()), 40);
    // Nothing came back either: the release leg is a later method, so the
    // delegator holds no claim on the pool's vault yet.
    assert_eq!(amount_of(&end, vault(ALICE, XRD)), 0);
    assert_eq!(amount_of(&end, vault(pool(), XRD)), 0);

    let unstaked = receipt
        .events
        .iter()
        .find(|event| event.emitter == Address::from(pool()))
        .expect("the pool emitted its event");
    assert_eq!(unstaked.event_type, 1);
    assert_eq!(unstaked.payload, encode_amount(40));
    Ok(())
}

#[test]
fn the_emitter_names_the_pool_and_the_guest_cannot() -> Result<()> {
    // The pool a fact concerns is the instance that emitted it, stamped by
    // the kernel from the invocation it was running. Nothing in the signed
    // manifest, the guest's arguments, or the instance's configuration
    // names a pool — so a second instance of this same package emits facts
    // about itself and can never emit one about this pool.
    let world = world();
    let entry = batch_entry(&world, &single_intent(stake_graph(10)), ALICE)?;
    let (outcome, _) = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry));

    let events = &outcome.receipts[&entry.tx].events;
    let from_pool: Vec<_> = events
        .iter()
        .filter(|e| e.emitter == Address::from(pool()))
        .collect();
    assert_eq!(from_pool.len(), 1, "the pool spoke once");
    // The payload is the amount and nothing else: there is no field in it a
    // guest could have put the wrong pool into.
    assert_eq!(from_pool[0].payload, encode_amount(10));

    // The account's own events carry its address, not the pool's — the
    // stamp follows the invocation rather than the transaction.
    assert!(
        events.iter().any(|e| e.emitter == ALICE),
        "the account emitted under its own address",
    );
    Ok(())
}

/// The registration payload the beacon's witness lift decodes, pinned at
/// the boundary that produces it.
fn registration_payload(validator: u64) -> Vec<u8> {
    let mut payload = validator.to_le_bytes().to_vec();
    payload.extend_from_slice(&PUBKEY);
    payload.extend_from_slice(&POSSESSION_PROOF);
    payload
}

/// The single event a pool emitted in `outcome` for `entry`.
fn pool_event(outcome: &BatchOutcome, entry: &BatchTx) -> (u32, Vec<u8>) {
    let events = &outcome.receipts[&entry.tx].events;
    let from_pool: Vec<_> = events
        .iter()
        .filter(|e| e.emitter == Address::from(pool()))
        .collect();
    assert_eq!(from_pool.len(), 1, "the pool spoke once");
    (from_pool[0].event_type, from_pool[0].payload.clone())
}

/// What the pool holds for `validator`, decoded through the type the
/// package declared.
fn registered(end: &MemoryStore, validator: u64) -> Option<staking::Validator> {
    cells(end)
        .get(&validator_leaf(pool(), validator))
        .map(|bytes| from_slice(bytes).expect("the pool writes its own validator type"))
}

/// The same record as stored bytes, for a store seeded by hand.
///
/// The record's own encoding and not an `Option`'s: a record cell holds
/// the value, and absence is no bytes at all.
fn registered_bytes() -> Vec<u8> {
    to_vec(&staking::Validator { pubkey: PUBKEY }).expect("a validator record encodes")
}

#[test]
fn a_registration_records_the_validator_and_reports_it() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(register_graph(VALIDATOR)), OPERATOR)?;
    let (outcome, end) = run_both(&operator_store(), std::slice::from_ref(&entry));
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));

    // The pool keeps the key it registered — the whole of its claim on
    // this validator, and what makes a second registration refusable.
    // Read back through the package's own type, so what this asserts is
    // what that package says it wrote.
    assert_eq!(
        registered(&end, VALIDATOR),
        Some(staking::Validator { pubkey: PUBKEY }),
    );
    assert_eq!(
        pool_event(&outcome, &entry),
        (2, registration_payload(VALIDATOR)),
    );
    Ok(())
}

#[test]
fn a_second_registration_of_one_validator_is_refused() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(register_graph(VALIDATOR)), OPERATOR)?;

    // The leaf already holds a key, which is the state a first
    // registration leaves behind.
    let mut store = operator_store();
    store.write(validator_leaf(pool(), VALIDATOR), registered_bytes());

    let (outcome, _) = run_both(&store, std::slice::from_ref(&entry));
    assert!(
        !matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a validator id this pool already took on is spent",
    );
    Ok(())
}

/// Bringing the pool up: one node, sealing its record, writing the
/// record of each mark it issues, and minting the owner badge it comes
/// up holding — filed in the founder's own account.
fn bring_up_graph() -> ManifestGraph {
    graph(|b| {
        let founder = account::authorize(b, OPERATOR)?;
        let badge = pool().instantiate(b, founder)?;
        account::deposit_nf(b, OPERATOR, badge)
    })
}

/// A pool brings itself up and reaches its own operator surface: one
/// node seals its record, writes the record of each mark it issues,
/// mints the owner badge and files it in the founder's account — and
/// the surface opens to whoever presents it. The cells a seated pool
/// holds, written by the vocabulary instead of by genesis.
#[test]
fn a_pool_brings_itself_up_and_reaches_its_operator_surface() -> Result<()> {
    let world = world();
    let store = MemoryStore::new();

    let found = batch_entry(&world, &single_intent(bring_up_graph()), OPERATOR)?;
    let (outcome, after_found) = run_both(&store, std::slice::from_ref(&found));
    assert!(
        matches!(
            outcome.receipts[&found.tx].outcome,
            Outcome::Completed { .. }
        ),
        "{:?}",
        outcome.receipts[&found.tx].outcome,
    );

    // The cells genesis writes for a seated pool, byte for byte: the
    // seal, a record per mark, the instance's data cell, and the
    // holdings entry.
    assert_eq!(
        after_found.cell(child_key(&TestHasher, pool(), CONFIG, &[])),
        Some(pool_meta().leaf_bytes().unwrap()),
    );
    assert_eq!(
        after_found.cell(resource_record_key(&TestHasher, pool(), unit())),
        Some(UNIT_RECORD.to_cell().unwrap()),
    );
    assert_eq!(
        after_found.cell(resource_record_key(&TestHasher, pool(), badge())),
        Some(BADGE_RECORD.to_cell().unwrap()),
    );
    assert_eq!(
        after_found.cell(instance_data_key(&TestHasher, pool(), badge(), BADGE_ID)),
        Some(vec![1]),
    );
    let holdings: Vec<_> = after_found
        .collection_entries()
        .filter(|(key, _)| key.collection == holdings_collection(&TestHasher, OPERATOR, badge()))
        .map(|(key, held)| (key.order, held.to_vec()))
        .collect();
    assert_eq!(holdings, vec![(u128::from(BADGE_ID), Vec::new())]);

    // And the surface is open: the founder registers a validator with
    // the badge the bring-up minted.
    let register = batch_entry(&world, &single_intent(register_graph(VALIDATOR)), OPERATOR)?;
    let (outcome, end) = run_both(&after_found, std::slice::from_ref(&register));
    assert!(matches!(
        outcome.receipts[&register.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        registered(&end, VALIDATOR),
        Some(staking::Validator { pubkey: PUBKEY }),
    );
    Ok(())
}

/// The one-way door: a second bring-up is refused as the seal's unmet
/// absence, judged where the leaf lives, before any body runs.
#[test]
fn a_second_bring_up_is_refused_where_the_seal_lives() -> Result<()> {
    let world = world();
    let store = MemoryStore::new();
    let found = batch_entry(&world, &single_intent(bring_up_graph()), OPERATOR)?;
    let (_, after_found) = run_both(&store, std::slice::from_ref(&found));

    let again = batch_entry(&world, &single_intent(bring_up_graph()), OPERATOR)?;
    let (outcome, _) = run_both(&after_found, std::slice::from_ref(&again));
    assert!(
        matches!(
            outcome.receipts[&again.tx].outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Absent,
                    ..
                },
            }
        ),
        "refused as the unmet absence: {:?}",
        outcome.receipts[&again.tx].outcome,
    );
    Ok(())
}

#[test]
fn a_pool_cannot_speak_about_a_validator_it_never_took_on() -> Result<()> {
    // The local half of the rule that a fact's subject is its emitter:
    // the beacon refuses a witness naming another pool's validator, and
    // the pool refuses to produce one in the first place.
    let world = world();
    for method in ["deactivate-validator", "unjail"] {
        let graph = operator_graph(method, VALIDATOR);
        let entry = batch_entry(&world, &single_intent(graph), OPERATOR)?;
        let (outcome, _) = run_both(&operator_store(), std::slice::from_ref(&entry));
        assert!(
            !matches!(
                outcome.receipts[&entry.tx].outcome,
                Outcome::Completed { .. }
            ),
            "{method} spoke about a validator with no record",
        );
    }
    Ok(())
}

#[test]
fn retiring_and_unjailing_name_the_validator_and_nothing_else() -> Result<()> {
    let world = world();
    let mut store = operator_store();
    store.write(validator_leaf(pool(), VALIDATOR), registered_bytes());

    for (method, event_type) in [("deactivate-validator", 3), ("unjail", 4)] {
        let graph = operator_graph(method, VALIDATOR);
        let entry = batch_entry(&world, &single_intent(graph), OPERATOR)?;
        let (outcome, end) = run_both(&store, std::slice::from_ref(&entry));
        assert!(matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ));
        assert_eq!(
            pool_event(&outcome, &entry),
            (event_type, VALIDATOR.to_le_bytes().to_vec()),
            "{method}",
        );
        // The record outlives the retirement: a validator id this pool
        // took on is spent for the life of the chain, which is the
        // beacon's own rule held locally.
        assert_eq!(
            registered(&end, VALIDATOR),
            Some(staking::Validator { pubkey: PUBKEY }),
            "{method}",
        );
    }
    Ok(())
}

#[test]
fn two_validators_registrations_touch_different_leaves() -> Result<()> {
    // Per validator rather than per pool, so two operator actions on two
    // validators commute rather than taking turns.
    let world = world();
    let first = batch_entry(&world, &single_intent(register_graph(VALIDATOR)), OPERATOR)?;
    let second = batch_entry(
        &world,
        &single_intent(register_graph(VALIDATOR + 1)),
        OPERATOR,
    )?;
    let (outcome, end) = run_both(&operator_store(), &[first.clone(), second.clone()]);

    for entry in [&first, &second] {
        assert!(matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ));
    }
    let held = staking::Validator { pubkey: PUBKEY };
    assert_eq!(registered(&end, VALIDATOR), Some(held.clone()));
    assert_eq!(registered(&end, VALIDATOR + 1), Some(held));
    Ok(())
}

/// The pool's vote leaf: one per pool, holding whatever it currently
/// backs.
fn vote_leaf(pool: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, pool, staking::VOTE, &[])
}

/// The parameters a cast carries, in the order the guest lays them out.
const SPLIT_BYTES: u64 = 9_000;
const IMPOUND_EPOCHS: u64 = 30;
const ACTIVATE_AT: u64 = 12;

fn cast_payload() -> Vec<u8> {
    let mut payload = SPLIT_BYTES.to_le_bytes().to_vec();
    payload.extend_from_slice(&IMPOUND_EPOCHS.to_le_bytes());
    payload.extend_from_slice(&ACTIVATE_AT.to_le_bytes());
    payload
}

fn cast_graph() -> ManifestGraph {
    graph(|b| {
        let operator = account::present_instance(b, OPERATOR, badge(), BADGE_ID)?;
        pool().cast_param_vote(b, operator, SPLIT_BYTES, IMPOUND_EPOCHS, ACTIVATE_AT)
    })
}

#[test]
fn a_cast_vote_is_held_on_the_pools_own_leaf_and_reported() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(cast_graph()), OPERATOR)?;
    let (outcome, end) = run_both(&operator_store(), std::slice::from_ref(&entry));
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));

    // The parameters travel as themselves: what the pool holds and what
    // it reports are the same bytes, laid out in the declared order.
    assert_eq!(cells(&end).get(&vote_leaf(pool())), Some(&cast_payload()));
    assert_eq!(pool_event(&outcome, &entry), (5, cast_payload()));
    Ok(())
}

#[test]
fn clearing_a_vote_empties_the_leaf_and_reports_nothing_else() -> Result<()> {
    let world = world();
    let mut store = operator_store();
    store.write(vote_leaf(pool()), cast_payload());

    let cleared = graph(|b| {
        let operator = account::present_instance(b, OPERATOR, badge(), BADGE_ID)?;
        pool().clear_param_vote(b, operator)
    });
    let entry = batch_entry(&world, &single_intent(cleared), OPERATOR)?;
    let (outcome, end) = run_both(&store, std::slice::from_ref(&entry));
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));

    // A pool backing nothing holds nothing, and the fact carries no
    // parameters because there are none to carry.
    assert_eq!(
        cells(&end).get(&vote_leaf(pool())).map(Vec::as_slice),
        Some(&[][..]),
    );
    assert_eq!(pool_event(&outcome, &entry), (6, Vec::new()));
    Ok(())
}

#[test]
fn a_second_cast_replaces_the_first() -> Result<()> {
    // One pool, one vote: the network counts it once, so the leaf holds
    // the latest rather than accumulating.
    let world = world();
    let mut store = operator_store();
    store.write(vote_leaf(pool()), vec![0xAA; 24]);

    let entry = batch_entry(&world, &single_intent(cast_graph()), OPERATOR)?;
    let (_, end) = run_both(&store, std::slice::from_ref(&entry));
    assert_eq!(cells(&end).get(&vote_leaf(pool())), Some(&cast_payload()));
    Ok(())
}
