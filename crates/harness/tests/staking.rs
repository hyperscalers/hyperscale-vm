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

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    Address, ComponentAddr, EnvelopeTree, Fungibility, Hash32, Hasher, InstanceMeta,
    InstanceRegistry, IntentDecl, ManifestGraph, MetadataCache, PackageHash, PrefixShardResolver,
    PrincipalAddr, ResourceAddr, ResourceRecord, SubstateKey, TestHasher, Value, admit_tree,
    child_key, holdings_collection, resource_address, resource_record_key, route_tree,
};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    AbortReason, BatchOutcome, BatchTx, CellKind, EnvInputs, ExecutionMode, GuestArg, GuestBackend,
    GuestCall, InvokeResult, Invoked, KernelSession, Locality, ManifestWalk, MemoryStore, Outcome,
    TxHash, WorkingStore, decode_amount, encode_amount, execute_batch,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, ResourceKind, Trap as RefTrap,
};
use hyperscale_vm_runtime::{
    CellKind as HostCellKind, HostArg, Returned, add_kernel_to_linker, blessed_engine, call_export,
    classify, exhausted, validate_component,
};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, STAKING_COMPONENT, account, staking};
use wasmtime::component::{Component, Linker};
use wasmtime::error::{Context, ensure};
use wasmtime::{Engine, Result, Store};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// The resource a delegation is denominated in.
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
/// The resource this pool issues against delegations — derived from the
/// pool, not configured, which is what the signature's `SelfResource`
/// evaluates to.
fn unit() -> ResourceAddr {
    resource_address(&TestHasher, pool(), &[])
}
/// The pool's owner badge — the same derivation the operator gate
/// evaluates.
fn badge() -> ResourceAddr {
    resource_address(
        &TestHasher,
        pool(),
        &[Value::Bytes(staking::OWNER_BADGE.to_vec()).canonical_bytes()],
    )
}
/// The badge instance the operator holds in these tests.
const BADGE_ID: u128 = 1;

/// A store where [`OPERATOR`] holds the pool's owner badge — what every
/// operator-surface test starts from.
fn operator_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .entry_write(
            OPERATOR.address(),
            holdings_collection(&TestHasher, OPERATOR, badge()),
            BADGE_ID,
            vec![1],
        )
        .unwrap();
    store.clear_log();
    store
}
/// The account holding the pool's owner badge: the operator surface
/// admits whoever presents it, and these tests seed it here.
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x0B; 31]);
const FUEL: u64 = 1_000_000_000;

/// A validator the pool operates, and the consensus material a
/// registration carries for it.
const VALIDATOR: u64 = 42;
const PUBKEY: [u8; 48] = [0xC1; 48];
const POSSESSION_PROOF: [u8; 96] = [0xC2; 96];

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

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
fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(account_pkg(), account::metadata());
    cache.publish(staking_pkg(), staking::metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(account_pkg());
    instances.create(&TestHasher, pool_meta());
    (cache, instances)
}

/// The pool's record: what it stakes. The resource it *issues* and the
/// owner badge its operator surface admits are both derived from the
/// pool, so they are deliberately not here.
fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: staking_pkg(),
        config: vec![Value::Address(XRD.address())],
        salt: Hash32([2; 32]),
    }
}

/// The pool instance, at the address its record derives.
fn pool() -> ComponentAddr {
    pool_meta().address(&TestHasher)
}

fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

fn unbonding(pool: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        pool,
        staking::UNBONDING,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// Build against this world's metadata, so every call is typed by the
/// signature it names and every edge carries the resource that signature
/// declares — neither of which is written out below.
fn graph(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    write(&mut b).expect("every call types against its signature");
    b.build().expect("every output is consumed")
}

/// `alice.withdraw(XRD) -> pool.stake -> alice.deposit(units)`: the
/// delegation goes in and the position comes back as an ordinary balance.
fn stake_graph(amount: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, XRD, amount)?;
        let units = staking::stake(b, pool(), funds)?;
        account::deposit(b, ALICE, units)
    })
}

/// `alice.withdraw(UNIT) -> pool.unstake`: the units are consumed and the
/// pool's unbonding total grows. Nothing comes back — the release leg is
/// not built.
fn unstake_graph(amount: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let units = account::withdraw(b, alice, unit(), amount)?;
        staking::unstake(b, pool(), units)
    })
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
        let operator = account::present_badge(b, OPERATOR, badge())?;
        b.call_as(operator, pool(), method, (validator,))?.none()
    })
}

fn register_graph(validator: u64) -> ManifestGraph {
    graph(|b| {
        let operator = account::present_badge(b, OPERATOR, badge())?;
        staking::register_validator(
            b,
            operator,
            pool(),
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
    }
}

/// Admit and route one envelope into its batch entry.
fn batch_entry(
    world: &(MetadataCache, InstanceRegistry),
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
) -> Result<BatchTx> {
    let (cache, instances) = world;
    let identity = tree.hash(&TestHasher);
    let admitted =
        admit_tree(tree, composer, identity, cache, instances, &TestHasher).context("admission")?;
    let routing = route_tree(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )
    .context("routing")?;
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().context("declaration")?;
    Ok(BatchTx::new(
        TxHash(identity.0),
        declaration,
        env().clock_ms,
        env().randomness,
    )
    .with_calls(routing.calls))
}

/// A backend over more than one package: each call names its own code by
/// content address, so resolution is a lookup rather than an assumption.
struct BlessedPackages {
    engine: Engine,
    components: BTreeMap<PackageHash, Component>,
}

impl GuestBackend for BlessedPackages {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let component = self
            .components
            .get(&call.package)
            .expect("the call names a published package");
        let mut linker = Linker::<SessionHost>::new(&self.engine);
        add_kernel_to_linker(&mut linker).expect("wiring");
        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let instance = linker
            .instantiate(&mut store, component)
            .expect("instantiate");
        let args: Vec<HostArg<'_>> = call.args.iter().map(host_arg).collect();
        let outcome = call_export(&mut store, &instance, call.export, &args);
        let exhausted = outcome.as_ref().err().is_some_and(exhausted);
        let result = invoked(outcome);
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        InvokeResult {
            session: store.into_data().0,
            fuel,
            result,
            exhausted,
        }
    }
}

/// The reference interpreter over the same package set.
struct RefPackages {
    components: BTreeMap<PackageHash, RefComponent>,
}

impl GuestBackend for RefPackages {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let component = self
            .components
            .get(&call.package)
            .expect("the call names a published package");
        let args: Vec<CVal> = call.args.iter().map(ref_arg).collect();
        let mut instance = RefComponentInstance::instantiate(component, SessionHost(session))
            .map_err(|(_, error)| error)
            .expect("instantiate");
        instance.set_fuel_limit(call.fuel_budget.min(FUEL));
        let outcome = instance.invoke(call.export, &args).expect("invoke");
        let fuel = instance.fuel_consumed();
        let exhausted = matches!(outcome, Err(ExecError::Trap(RefTrap::OutOfFuel)));
        let result = match outcome {
            Ok(values) => lifted(&values),
            Err(error) => Invoked::Aborted(error.abort_reason()),
        };
        InvokeResult {
            session: instance.into_host().0,
            fuel,
            result,
            exhausted,
        }
    }
}

/// The blessed engine's verdict as the kernel's.
fn invoked(outcome: Result<Returned>) -> Invoked {
    match outcome {
        Ok(Returned::Values(bytes)) => Invoked::Returned(bytes),
        Ok(Returned::Declined(code)) => Invoked::Declined(code),
        Err(error) => Invoked::Aborted(classify(&error)),
    }
}

/// The reference interpreter's lifted results as the kernel's verdict.
fn lifted(values: &[CVal]) -> Invoked {
    match values {
        [] => Invoked::Returned(None),
        [CVal::Bytes(bytes)] => Invoked::Returned(Some(bytes.clone())),
        [CVal::Declined(code)] => Invoked::Declined(*code),
        _ => Invoked::Aborted(AbortReason::BadReturnShape),
    }
}

const fn host_kind(kind: CellKind) -> HostCellKind {
    match kind {
        CellKind::Read => HostCellKind::Read,
        CellKind::Locked => HostCellKind::Locked,
        CellKind::Write => HostCellKind::Write,
        CellKind::Delta => HostCellKind::Delta,
        CellKind::Reserve => HostCellKind::Reserve,
        CellKind::RangeRead => HostCellKind::RangeRead,
        CellKind::RangeWrite => HostCellKind::RangeWrite,
    }
}

const fn ref_kind(kind: CellKind) -> ResourceKind {
    match kind {
        CellKind::Read => ResourceKind::ReadCell,
        CellKind::Locked => ResourceKind::LockedCell,
        CellKind::Write => ResourceKind::WriteCell,
        CellKind::Delta => ResourceKind::DeltaCell,
        CellKind::Reserve => ResourceKind::ReserveCell,
        CellKind::RangeRead => ResourceKind::RangeRead,
        CellKind::RangeWrite => ResourceKind::RangeWrite,
    }
}

const fn host_arg<'a>(arg: &GuestArg<'a>) -> HostArg<'a> {
    match arg {
        GuestArg::Handle { rep, kind } => HostArg::Handle {
            rep: *rep,
            kind: host_kind(*kind),
        },
        GuestArg::U64(scalar) => HostArg::U64(*scalar),
        GuestArg::Bytes(bytes) => HostArg::Bytes(bytes),
    }
}

fn ref_arg(arg: &GuestArg<'_>) -> CVal {
    match arg {
        GuestArg::Handle { rep, kind } => CVal::Borrow(*rep, ref_kind(*kind)),
        GuestArg::U64(scalar) => CVal::U64(*scalar),
        GuestArg::Bytes(bytes) => CVal::Bytes(bytes.to_vec()),
    }
}

/// The record the pool's instantiation writes for the unit it issues.
const UNIT_RECORD: ResourceRecord = ResourceRecord {
    kind: Fungibility::Fungible { divisibility: 18 },
};

fn seeded_store(xrd: u128, units: u128) -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(
            resource_record_key(&TestHasher, pool(), unit()),
            UNIT_RECORD.to_cell().unwrap(),
        )
        .unwrap();
    store
        .write(vault(ALICE, XRD), encode_amount(xrd).to_vec())
        .unwrap();
    if units > 0 {
        store
            .write(vault(ALICE, unit()), encode_amount(units).to_vec())
            .unwrap();
    }
    store.clear_log();
    store
}

fn cells(end: &MemoryStore) -> BTreeMap<SubstateKey, Vec<u8>> {
    end.cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

fn amount_of(end: &MemoryStore, key: SubstateKey) -> u128 {
    cells(end)
        .get(&key)
        .map_or(0, |cell| decode_amount(cell).unwrap())
}

/// Execute on both runtimes over both packages and assert identical
/// receipts and end state; returns the blessed outcome.
/// Execute the batch on both runtimes and assert byte-identical receipts
/// and end state; returns the blessed outcome and its collapsed end state.
fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> Result<(BatchOutcome, MemoryStore)> {
    let engine = blessed_engine()?;
    let mut blessed = BlessedPackages {
        components: BTreeMap::new(),
        engine,
    };
    let mut reference = RefPackages {
        components: BTreeMap::new(),
    };
    for (package, bytes) in [
        (account_pkg(), ACCOUNT_COMPONENT),
        (staking_pkg(), STAKING_COMPONENT),
    ] {
        validate_component(bytes).context("profile validation")?;
        blessed
            .components
            .insert(package, Component::new(&blessed.engine, bytes)?);
        reference
            .components
            .insert(package, RefComponent::decode(bytes)?);
    }

    let blessed_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk { backend: &blessed },
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();
    let ref_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk {
            backend: &reference,
        },
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    // Whole receipts, abort classes included: the vocabulary is closed,
    // so a failure path the two runtimes classify differently is a
    // divergence rather than a wording difference to look past.
    assert_eq!(
        blessed_outcome.receipts, ref_outcome.receipts,
        "lanes diverged"
    );
    let end = blessed_outcome.store.collapse_onto(store.clone());
    assert_eq!(
        cells(&end),
        cells(&ref_outcome.store.collapse_onto(store.clone())),
        "state diverged"
    );
    Ok((blessed_outcome, end))
}

#[test]
fn a_delegation_lands_in_the_pool_and_returns_units() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(stake_graph(100)), ALICE)?;

    let (outcome, end) = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry))?;
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
        .find(|event| event.emitter == pool())
        .expect("the pool emitted its event");
    assert_eq!(staked.event_type, 0);
    assert_eq!(staked.payload, encode_amount(100));
    Ok(())
}

#[test]
fn returned_units_are_consumed_and_recorded_as_unbonding() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(unstake_graph(40)), ALICE)?;

    let (outcome, end) = run_both(&seeded_store(0, 100), std::slice::from_ref(&entry))?;
    let receipt = &outcome.receipts[&entry.tx];
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));

    assert_eq!(amount_of(&end, vault(ALICE, unit())), 60);
    assert_eq!(amount_of(&end, unbonding(pool(), XRD)), 40);
    // Nothing came back: the release leg is a later method, so the units
    // are gone and the delegator holds no claim on the pool's vault yet.
    assert_eq!(amount_of(&end, vault(ALICE, XRD)), 0);
    assert_eq!(amount_of(&end, vault(pool(), XRD)), 0);

    let unstaked = receipt
        .events
        .iter()
        .find(|event| event.emitter == pool())
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
    let (outcome, _) = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry))?;

    let events = &outcome.receipts[&entry.tx].events;
    let from_pool: Vec<_> = events.iter().filter(|e| e.emitter == pool()).collect();
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
    let from_pool: Vec<_> = events.iter().filter(|e| e.emitter == pool()).collect();
    assert_eq!(from_pool.len(), 1, "the pool spoke once");
    (from_pool[0].event_type, from_pool[0].payload.clone())
}

#[test]
fn a_registration_records_the_validator_and_reports_it() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(register_graph(VALIDATOR)), OPERATOR)?;
    let (outcome, end) = run_both(&operator_store(), std::slice::from_ref(&entry))?;
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));

    // The pool keeps the key it registered — the whole of its claim on
    // this validator, and what makes a second registration refusable.
    assert_eq!(
        cells(&end).get(&validator_leaf(pool(), VALIDATOR)),
        Some(&PUBKEY.to_vec()),
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
    store.write(validator_leaf(pool(), VALIDATOR), PUBKEY.to_vec())?;
    store.clear_log();

    let (outcome, _) = run_both(&store, std::slice::from_ref(&entry))?;
    assert!(
        !matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a validator id this pool already took on is spent",
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
        let (outcome, _) = run_both(&operator_store(), std::slice::from_ref(&entry))?;
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
    store.write(validator_leaf(pool(), VALIDATOR), PUBKEY.to_vec())?;
    store.clear_log();

    for (method, event_type) in [("deactivate-validator", 3), ("unjail", 4)] {
        let graph = operator_graph(method, VALIDATOR);
        let entry = batch_entry(&world, &single_intent(graph), OPERATOR)?;
        let (outcome, end) = run_both(&store, std::slice::from_ref(&entry))?;
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
            cells(&end).get(&validator_leaf(pool(), VALIDATOR)),
            Some(&PUBKEY.to_vec()),
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
    let (outcome, end) = run_both(&operator_store(), &[first.clone(), second.clone()])?;

    for entry in [&first, &second] {
        assert!(matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ));
    }
    let cells = cells(&end);
    assert_eq!(
        cells.get(&validator_leaf(pool(), VALIDATOR)),
        Some(&PUBKEY.to_vec()),
    );
    assert_eq!(
        cells.get(&validator_leaf(pool(), VALIDATOR + 1)),
        Some(&PUBKEY.to_vec()),
    );
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
        let operator = account::present_badge(b, OPERATOR, badge())?;
        staking::cast_param_vote(
            b,
            operator,
            pool(),
            SPLIT_BYTES,
            IMPOUND_EPOCHS,
            ACTIVATE_AT,
        )
    })
}

#[test]
fn a_cast_vote_is_held_on_the_pools_own_leaf_and_reported() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(cast_graph()), OPERATOR)?;
    let (outcome, end) = run_both(&operator_store(), std::slice::from_ref(&entry))?;
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
    store.write(vote_leaf(pool()), cast_payload())?;
    store.clear_log();

    let cleared = graph(|b| {
        let operator = account::present_badge(b, OPERATOR, badge())?;
        staking::clear_param_vote(b, operator, pool())
    });
    let entry = batch_entry(&world, &single_intent(cleared), OPERATOR)?;
    let (outcome, end) = run_both(&store, std::slice::from_ref(&entry))?;
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
    store.write(vote_leaf(pool()), vec![0xAA; 24])?;
    store.clear_log();

    let entry = batch_entry(&world, &single_intent(cast_graph()), OPERATOR)?;
    let (_, end) = run_both(&store, std::slice::from_ref(&entry))?;
    assert_eq!(cells(&end).get(&vote_leaf(pool())), Some(&cast_payload()));
    Ok(())
}
