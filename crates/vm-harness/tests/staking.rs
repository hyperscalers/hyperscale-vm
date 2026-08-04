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

use hyperscale_vm_effects::stdlib::{UNBONDING, VAULT, account_metadata, staking_metadata};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EnvelopeTree, GraphArg, GraphNode, Hasher, InstanceMeta,
    InstanceRegistry, IntentDecl, ManifestGraph, MetadataCache, PackageHash, PrefixShardResolver,
    SubstateKey, TestHasher, Value, admit_tree, child_key, route_tree,
};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, CellKind, EnvInputs, ExecutionMode, GuestArg, GuestBackend, GuestCall,
    InvokeResult, KernelSession, Locality, ManifestWalk, MemoryStore, Outcome, SubstateStore,
    TxHash, decode_amount, encode_amount, execute_batch,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    CellKind as HostCellKind, HostArg, add_kernel_to_linker, blessed_engine, call_export,
    validate_component,
};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, STAKING_COMPONENT};
use wasmtime::component::{Component, Linker};
use wasmtime::error::{Context, ensure};
use wasmtime::{Engine, Result, Store};

const ALICE: Address = Address([0x10; 16]);
/// The pool instance: an address like any other, distinguished only by the
/// package its registry entry names.
const POOL: Address = Address([0x50; 16]);
/// The resource a delegation is denominated in.
const XRD: Address = Address([0xE1; 16]);
/// The resource this pool issues against delegations.
const UNIT: Address = Address([0xE2; 16]);
const FUEL: u64 = 1_000_000_000;

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
/// creation-fixed configuration — the resource it stakes and the one it
/// issues. Nothing configures which pool it is; the emitter answers that.
fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(account_pkg(), account_metadata());
    cache.publish(staking_pkg(), staking_metadata());
    let mut instances = InstanceRegistry::new();
    instances.register(
        ALICE,
        InstanceMeta {
            package: account_pkg(),
            config: vec![],
        },
    );
    instances.register(
        POOL,
        InstanceMeta {
            package: staking_pkg(),
            config: vec![Value::Address(XRD), Value::Address(UNIT)],
        },
    );
    (cache, instances)
}

fn vault(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn unbonding(pool: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        pool,
        UNBONDING,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn withdraw(target: Address, resource: Address, amount: u128) -> GraphNode {
    GraphNode {
        target,
        method: "withdraw".into(),
        args: vec![
            GraphArg::Literal(Value::Address(resource)),
            GraphArg::Literal(Value::U128(amount)),
        ],
    }
}

fn from_edge(producer: u32, resource: Address) -> GraphArg {
    GraphArg::Edge {
        edge: EdgeRef {
            producer,
            output: 0,
        },
        constraints: vec![Constraint::ResourceIs(resource)],
    }
}

/// `alice.withdraw(XRD) -> pool.stake -> alice.deposit(units)`: the
/// delegation goes in and the position comes back as an ordinary balance.
fn stake_graph(amount: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            withdraw(ALICE, XRD, amount),
            GraphNode {
                target: POOL,
                method: "stake".into(),
                args: vec![from_edge(0, XRD)],
            },
            GraphNode {
                target: ALICE,
                method: "deposit".into(),
                args: vec![from_edge(1, UNIT)],
            },
        ],
    }
}

/// `alice.withdraw(UNIT) -> pool.unstake`: the units are consumed and the
/// pool's unbonding total grows. Nothing comes back — the release leg is
/// not built.
fn unstake_graph(amount: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            withdraw(ALICE, UNIT, amount),
            GraphNode {
                target: POOL,
                method: "unstake".into(),
                args: vec![from_edge(0, UNIT)],
            },
        ],
    }
}

const fn single_intent(graph: ManifestGraph) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    }
}

/// Admit and route one envelope into its batch entry.
fn batch_entry(world: &(MetadataCache, InstanceRegistry), tree: &EnvelopeTree) -> Result<BatchTx> {
    let (cache, instances) = world;
    let identity = tree.hash(&TestHasher);
    let admitted =
        admit_tree(tree, identity, cache, instances, &TestHasher).context("admission")?;
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
        store.set_fuel(FUEL).expect("fuel");
        let instance = linker
            .instantiate(&mut store, component)
            .expect("instantiate");
        let args: Vec<HostArg<'_>> = call.args.iter().map(host_arg).collect();
        let result = call_export(&mut store, &instance, call.export, &args, call.returns)
            .map_err(|trap| format!("{trap:#}"));
        let fuel = FUEL - store.get_fuel().expect("fuel");
        InvokeResult {
            session: store.into_data().0,
            fuel,
            result,
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
            .expect("instantiate");
        let outcome = instance.invoke(call.export, &args).expect("invoke");
        let fuel = instance.fuel_consumed();
        let result = match outcome {
            Ok(values) => match (call.returns, values.as_slice()) {
                (false, []) => Ok(None),
                (true, [CVal::Bytes(bytes)]) => Ok(Some(bytes.clone())),
                other => Err(format!("unexpected result shape {other:?}")),
            },
            Err(trap) => Err(format!("{trap:?}")),
        };
        InvokeResult {
            session: instance.into_host().0,
            fuel,
            result,
        }
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

fn seeded_store(xrd: u128, units: u128) -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, XRD), encode_amount(xrd).to_vec())
        .unwrap();
    if units > 0 {
        store
            .write(vault(ALICE, UNIT), encode_amount(units).to_vec())
            .unwrap();
    }
    store.clear_log();
    store
}

fn cells(outcome: &BatchOutcome) -> BTreeMap<SubstateKey, Vec<u8>> {
    outcome
        .store
        .clone()
        .collapse()
        .cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

fn amount_of(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    cells(outcome)
        .get(&key)
        .map_or(0, |cell| decode_amount(cell).unwrap())
}

/// Execute on both runtimes over both packages and assert byte-identical
/// receipts and end state; returns the blessed outcome.
fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> Result<BatchOutcome> {
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
    assert_eq!(
        blessed_outcome.receipts, ref_outcome.receipts,
        "lanes diverged"
    );
    assert_eq!(
        cells(&blessed_outcome),
        cells(&ref_outcome),
        "state diverged"
    );
    Ok(blessed_outcome)
}

#[test]
fn a_delegation_lands_in_the_pool_and_returns_units() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(stake_graph(100)))?;

    let outcome = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry))?;
    let receipt = &outcome.receipts[&entry.tx];
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));

    // The delegation left the delegator and reached the pool.
    assert_eq!(amount_of(&outcome, vault(ALICE, XRD)), 50);
    assert_eq!(amount_of(&outcome, vault(POOL, XRD)), 100);
    // The position came back as an ordinary balance, at par.
    assert_eq!(amount_of(&outcome, vault(ALICE, UNIT)), 100);

    // What the beacon's witness lift consumes, pinned at the boundary that
    // produces it: the pool's own identifier and the staked amount.
    let staked = receipt
        .events
        .iter()
        .find(|event| event.emitter == POOL)
        .expect("the pool emitted its event");
    assert_eq!(staked.event_type, 0);
    assert_eq!(staked.payload, encode_amount(100));
    Ok(())
}

#[test]
fn returned_units_are_consumed_and_recorded_as_unbonding() -> Result<()> {
    let world = world();
    let entry = batch_entry(&world, &single_intent(unstake_graph(40)))?;

    let outcome = run_both(&seeded_store(0, 100), std::slice::from_ref(&entry))?;
    let receipt = &outcome.receipts[&entry.tx];
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));

    assert_eq!(amount_of(&outcome, vault(ALICE, UNIT)), 60);
    assert_eq!(amount_of(&outcome, unbonding(POOL, XRD)), 40);
    // Nothing came back: the release leg is a later method, so the units
    // are gone and the delegator holds no claim on the pool's vault yet.
    assert_eq!(amount_of(&outcome, vault(ALICE, XRD)), 0);
    assert_eq!(amount_of(&outcome, vault(POOL, XRD)), 0);

    let unstaked = receipt
        .events
        .iter()
        .find(|event| event.emitter == POOL)
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
    let entry = batch_entry(&world, &single_intent(stake_graph(10)))?;
    let outcome = run_both(&seeded_store(150, 0), std::slice::from_ref(&entry))?;

    let events = &outcome.receipts[&entry.tx].events;
    let from_pool: Vec<_> = events.iter().filter(|e| e.emitter == POOL).collect();
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
