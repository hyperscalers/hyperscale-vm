//! The pattern corpus: transfer, AMM swap, and order book end to end —
//! manifest graph → admission → routing → capability materialization →
//! guest execution → receipt — on both runtimes, with the walkthrough's
//! predicted effect profiles and provision shapes asserted exactly.
//!
//! The guests are the real pinned-toolchain components; the driver walks
//! the admitted graph node by node, threading bucket cells along the
//! edges, with one kernel session covering the transaction and the
//! trace-subset oracle standing at every receipt.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::stdlib::{
    ASKS, CLAIMS, CONFIG, FILL_CAP, VAULT, account_metadata, amm_metadata, book_metadata,
};
use hyperscale_vm_effects::{
    AbiParam, Address, Clause, ComponentAddr, Constraint, Effect, EffectSet, EffectTarget, Expr,
    Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache, MethodSignature,
    Mode, ModeExpr, PackageHash, PackageMetadata, ParamType, PrefixShardResolver, PrincipalAddr,
    ResourceAddr, RoleId, Routing, ShardId, ShardResolver, SubstateKey, TargetExpr, TestHasher,
    Value, admit, child_key, fresh_id, route,
};
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchTx, CellKind, EnvInputs, Event, GuestArg, GuestBackend, GuestCall, GuestRunner,
    InvokeResult, KernelSession, ManifestWalk, MemoryStore, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, decode_amount, encode_amount,
};
use hyperscale_vm_manifest_builder::GraphBuilder;
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, ResourceKind, Trap as RefTrap,
};
use hyperscale_vm_runtime::{
    CellKind as HostCellKind, HostArg, add_kernel_to_linker, blessed_engine, call_export,
    validate_component,
};
use wasmtime::component::{Component, Linker};
use wasmtime::error::{Context, ensure};
use wasmtime::{Engine, Result, Store};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const MAKER: PrincipalAddr = PrincipalAddr::new([0x50; 31]);
const TAKER: PrincipalAddr = PrincipalAddr::new([0x60; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const BASE: ResourceAddr = ResourceAddr::new([0xE3; 31]);
const QUOTE: ResourceAddr = ResourceAddr::new([0xE4; 31]);

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 5_000,
        randomness: [2; 32],
    }
}

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

fn claims(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        CLAIMS,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

fn config_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("book"), book_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, pool_meta());
    instances.create(&TestHasher, book_meta());
    (cache, instances)
}

fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        config: vec![
            Value::Address(RES_X.address()),
            Value::Address(RES_Y.address()),
        ],
        salt: Hash32([2; 32]),
    }
}

/// The pool instance, at the address its record derives.
fn pool() -> ComponentAddr {
    pool_meta().address(&TestHasher)
}

fn book_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("book"),
        config: vec![
            Value::Address(BASE.address()),
            Value::Address(QUOTE.address()),
        ],
        salt: Hash32([3; 32]),
    }
}

/// The order book instance.
fn book() -> ComponentAddr {
    book_meta().address(&TestHasher)
}

fn mirror_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("mirror"),
        config: vec![],
        salt: Hash32([4; 32]),
    }
}

/// Which guest each published package runs.
///
/// `mirror` is the same account code under a second content address, so
/// the corpus can publish a package the authored stdlib table knows
/// nothing about and call it through the same walk.
const PACKAGES: &[(&str, &str)] = &[
    ("account", "account"),
    ("amm", "amm"),
    ("book", "book"),
    ("mirror", "account"),
];

/// Both runtimes' compiled guests, resolved by content address — which
/// is how an embedder finds a package's code, an instance's address
/// being no part of it.
struct Engines {
    engine: Engine,
    blessed: BTreeMap<&'static str, Component>,
    reference: BTreeMap<&'static str, RefComponent>,
    guests: BTreeMap<PackageHash, &'static str>,
}

impl Engines {
    fn build() -> Result<Self> {
        let engine = blessed_engine()?;
        let mut blessed = BTreeMap::new();
        let mut reference = BTreeMap::new();
        for name in ["account", "amm", "book"] {
            let bytes = build_guest(name)?;
            validate_component(&bytes).with_context(|| format!("profile validation of {name}"))?;
            blessed.insert(name, Component::new(&engine, &bytes)?);
            reference.insert(name, RefComponent::decode(&bytes)?);
        }
        let guests = PACKAGES
            .iter()
            .map(|(package, guest)| (pkg(package), *guest))
            .collect();
        Ok(Self {
            engine,
            blessed,
            reference,
            guests,
        })
    }

    fn guest_for(&self, package: PackageHash) -> &'static str {
        self.guests[&package]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Blessed,
    Reference,
}

/// The blessed engine behind the walk: one instantiation per guest call,
/// the export invoked dynamically from the arguments the kernel built.
struct BlessedBackend<'a> {
    engines: &'a Engines,
}

impl GuestBackend for BlessedBackend<'_> {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let mut linker = Linker::<SessionHost>::new(&self.engines.engine);
        add_kernel_to_linker(&mut linker).expect("wiring");
        let mut store = Store::new(&self.engines.engine, SessionHost(session));
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let component = &self.engines.blessed[self.engines.guest_for(call.package)];
        let instance = linker
            .instantiate(&mut store, component)
            .expect("instantiate");
        let args: Vec<HostArg<'_>> = call.args.iter().map(host_arg).collect();
        let result = call_export(&mut store, &instance, call.export, &args, call.returns)
            .map_err(|trap| format!("{trap:#}"));
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        let exhausted = store.get_fuel().expect("fuel") == 0 && result.is_err();
        InvokeResult {
            session: store.into_data().0,
            fuel,
            result,
            exhausted,
        }
    }
}

/// The reference interpreter behind the same walk.
struct ReferenceBackend<'a> {
    engines: &'a Engines,
}

impl GuestBackend for ReferenceBackend<'_> {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let args: Vec<CVal> = call.args.iter().map(ref_arg).collect();
        let component = &self.engines.reference[self.engines.guest_for(call.package)];
        let mut instance = RefComponentInstance::instantiate(component, SessionHost(session))
            .expect("instantiate");
        instance.set_fuel_limit(call.fuel_budget.min(FUEL));
        let outcome = instance.invoke(call.export, &args).expect("invoke");
        let fuel = instance.fuel_consumed();
        let exhausted = matches!(outcome, Err(ExecError::Trap(RefTrap::OutOfFuel)));
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
            exhausted,
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

/// How one transaction ended on a lane.
#[derive(Debug, PartialEq, Eq)]
enum TxResult {
    Completed(Receipt),
    /// The guest trapped. Compared as the bare fact: the reason is the
    /// engine's own text, and the two runtimes word theirs differently.
    Trapped,
    /// The kernel refused, before or around the call. Its verdicts carry
    /// no engine text, so the lanes are compared whole.
    Refused(Outcome),
}

/// Execute one admitted manifest through the kernel's own walk: routing
/// lowers each node to the invocation its package's ABI binding
/// describes, the walk performs them in order, and the session finishes
/// into a receipt with the trace-subset oracle standing over it.
///
/// Nothing here names a method or an export. Everything a call needs is
/// either signed manifest content or content-addressed package metadata,
/// which is what makes a package published at runtime callable by the
/// same code path the genesis packages take.
fn execute_manifest(
    lane: Lane,
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: MemoryStore,
    graph: &ManifestGraph,
    tx: TxHash,
) -> Result<(TxResult, MemoryStore)> {
    let (cache, instances) = world;
    let admitted = admit(graph, cache, instances, &TestHasher).context("admission")?;
    let routing = route(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )
    .context("routing")?;
    // The null resolver puts every effect on one shard, so the whole
    // declaration is the sole entry — taken as that rather than by naming
    // an id the resolver is free to choose.
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().context("declaration")?;
    let entry =
        BatchTx::new(tx, declaration, env().clock_ms, env().randomness).with_calls(routing.calls);

    let before = store.clone();
    let session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &entry.declared,
        &entry.ordered,
        tx,
        env(),
        test_hash,
    )
    .expect("corpus manifests are feasible");

    let blessed = BlessedBackend { engines };
    let reference = ReferenceBackend { engines };
    let run = match lane {
        Lane::Blessed => ManifestWalk { backend: &blessed }.run(&entry, session),
        Lane::Reference => ManifestWalk {
            backend: &reference,
        }
        .run(&entry, session),
    };
    match run.outcome {
        Outcome::Completed { .. } => {
            let (receipt, threaded) = run
                .session
                .finish(Outcome::Completed { value: None }, run.fuel)
                .expect("the oracle stands on every corpus receipt");
            Ok((TxResult::Completed(receipt), threaded.collapse()))
        }
        Outcome::UserError { .. } => Ok((TxResult::Trapped, before)),
        refused => Ok((TxResult::Refused(refused), before)),
    }
}

const fn point(key: SubstateKey, mode: Mode) -> Effect {
    Effect {
        target: EffectTarget::Point(key),
        mode,
    }
}

fn set(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    set
}

/// Where the sharded routing above puts an address — asked rather than
/// restated, so a change to the resolver cannot leave this behind.
fn shard_of(address: impl Into<Address>) -> ShardId {
    PrefixShardResolver { bits: 8 }.shard_of(address.into())
}

fn sharded_routing(world: &(MetadataCache, InstanceRegistry), graph: &ManifestGraph) -> Routing {
    let (cache, instances) = world;
    let admitted = admit(graph, cache, instances, &TestHasher).expect("admits");
    let first = route(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .expect("routes");
    let second = route(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .expect("routes");
    assert_eq!(first, second, "route is a function over the corpus");
    first
}

fn run_both(
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
) -> (Vec<TxResult>, MemoryStore) {
    let mut lanes = Vec::new();
    for lane in [Lane::Blessed, Lane::Reference] {
        let mut results = Vec::new();
        let mut threaded = store.clone();
        for (graph, tx) in transactions {
            let (result, next) =
                execute_manifest(lane, engines, world, threaded, graph, *tx).expect("driver");
            results.push(result);
            threaded = next;
        }
        lanes.push((results, threaded));
    }
    let (reference, ref_store) = lanes.pop().unwrap();
    let (blessed, blessed_store) = lanes.pop().unwrap();
    assert_eq!(blessed, reference, "lanes diverged");
    let cells = |store: &MemoryStore| -> BTreeMap<SubstateKey, Vec<u8>> {
        store.cells().map(|(k, v)| (k, v.to_vec())).collect()
    };
    assert_eq!(cells(&blessed_store), cells(&ref_store), "state diverged");
    (blessed, blessed_store)
}

fn amount_of(store: &mut MemoryStore, key: SubstateKey) -> u128 {
    store
        .read(key)
        .unwrap()
        .map_or(0, |cell| decode_amount(&cell).unwrap())
}

fn transfer_graph() -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (RES_X, 100u128));
    let [] = b.call(BOB, "deposit", (funds.resource_is(RES_X),));
    b.build().expect("every output is consumed")
}

/// A package the authored stdlib table does not describe: the same
/// account code under its own content address, with metadata written
/// here and published at runtime.
///
/// `deposit` declares its two delta clauses in the opposite order to the
/// stdlib account's and binds the ABI handle to the second one. Nothing
/// about the resulting call can come from a table of known method names,
/// and nothing can come from a convention that a method's first clause is
/// its first handle: if either were true the credit would land on the
/// claims cell instead of the vault.
fn mirror_metadata() -> PackageMetadata {
    let self_child = |role: RoleId, material: Vec<Expr>| Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        role,
        material,
    };
    let resource_of_arg0 = || Expr::ResourceOf(Box::new(Expr::Arg(0)));
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "deposit".into(),
        MethodSignature {
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(1), AbiParam::Bucket(0)],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(CLAIMS, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                },
            ],
            ..MethodSignature::default()
        },
    );
    metadata.events = vec!["withdrawn".into(), "deposited".into()];
    metadata
}

#[test]
fn a_package_published_at_runtime_is_callable_through_the_same_walk() -> Result<()> {
    let (mut cache, mut instances) = world();
    cache.publish(pkg("mirror"), mirror_metadata());
    let dana = instances.create(&TestHasher, mirror_meta());
    let world = (cache, instances);

    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    let graph = {
        let mut b = GraphBuilder::new();
        let [funds] = b.call(ALICE, "withdraw", (RES_X, 100u128));
        let [] = b.call(dana, "deposit", (funds.resource_is(RES_X),));
        b.build().expect("every output is consumed")
    };
    let (results, _) = run_both(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0D; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the published package must complete");
    };
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(dana, RES_X))
            .map(|movement| movement.credit),
        Some(100),
        "the bound clause's cell takes the credit"
    );
    assert!(
        receipt.delta.movements.get(&claims(dana, RES_X)).is_none(),
        "the unbound clause is declared and untouched"
    );
    Ok(())
}

/// A transfer whose recipient signs a bound the sender's withdrawal
/// cannot meet.
fn bounded_transfer_graph(constraint: Constraint) -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (RES_X, 100u128));
    let funds = funds.resource_is(RES_X).constrain(constraint);
    let [] = b.call(BOB, "deposit", (funds,));
    b.build().expect("every output is consumed")
}

#[test]
fn a_missed_edge_bound_aborts_identically_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(500).to_vec())
        .unwrap();
    store.clear_log();

    // The withdrawal is feasible and the guest is honest — it returns
    // exactly the 100 it reserved. What fails is the manifest's own
    // guarantee, asserted independently of the callee, so neither the
    // producer's code nor the consumer's had to check anything.
    for (constraint, name) in [
        (Constraint::MinAmount(150), "under the floor"),
        (Constraint::MaxAmount(50), "over the ceiling"),
    ] {
        let graph = bounded_transfer_graph(constraint);
        let (results, after) = run_both(
            &engines,
            &world,
            &store,
            &[(&graph, TxHash(Hash32([0x0E; 32])))],
        );
        assert_eq!(
            results[0],
            TxResult::Refused(Outcome::ConstraintUnmet {
                node: 1,
                param: 0,
                amount: 100,
            }),
            "{name}"
        );
        // The abort is the whole of it: nothing the sender declared
        // applied, so the reservation never settled.
        assert_eq!(
            after
                .cells()
                .map(|(key, value)| (key, value.to_vec()))
                .collect::<BTreeMap<_, _>>(),
            store
                .cells()
                .map(|(key, value)| (key, value.to_vec()))
                .collect::<BTreeMap<_, _>>(),
            "{name}"
        );
    }

    // The same manifest inside the bound completes, so the refusal is
    // the bound and not the shape.
    let graph = bounded_transfer_graph(Constraint::MinAmount(100));
    let (results, _) = run_both(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0F; 32])))],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    Ok(())
}

#[test]
fn transfer_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &transfer_graph());

    // The walkthrough's profile: one reservation at the sender, the vault
    // and claims deltas at the recipient — the balance cells and nothing
    // else.
    let expected: BTreeMap<ShardId, EffectSet> = BTreeMap::from([
        (
            shard_of(ALICE),
            set(&[point(vault(ALICE, RES_X), Mode::Reserve { amount: 100 })]),
        ),
        (
            shard_of(BOB),
            set(&[
                point(vault(BOB, RES_X), Mode::Delta),
                point(claims(BOB, RES_X), Mode::Delta),
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);

    // The acceptance test, executable: a commutative-only transfer
    // provisions nothing at all — on either side.
    for set in routing.per_shard.values() {
        assert!(set.provision_targets().is_empty());
    }
}

#[test]
fn transfer_executes_end_to_end_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    let graph = transfer_graph();
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x01; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("transfer must complete");
    };
    assert_eq!(receipt.delta.settles.get(&vault(ALICE, RES_X)), Some(&100));
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(BOB, RES_X))
            .unwrap()
            .credit,
        100
    );
    assert!(receipt.delta.cells.is_empty());
    // Both nodes emitted, and each event carries the address of the node
    // that ran rather than anything the guest could have named — the two
    // legs of a transfer live on different shards, so this is what decides
    // which receipt each event lands on.
    assert_eq!(
        receipt.events,
        vec![
            Event {
                emitter: ALICE.address(),
                event_type: 0,
                payload: encode_amount(100).to_vec(),
            },
            Event {
                emitter: BOB.address(),
                event_type: 1,
                payload: encode_amount(100).to_vec(),
            },
        ],
    );
    // Nothing on the execution path resolves an index, so the guest's
    // constants and the package's table are two halves of one contract
    // that only a test holds together.
    let table = account_metadata().events;
    assert_eq!(table, vec!["withdrawn", "deposited"]);
    for event in &receipt.events {
        assert!(
            table.get(event.event_type as usize).is_some(),
            "event type {} resolves in its emitter's package",
            event.event_type,
        );
    }
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 100);
    Ok(())
}

fn swap_graph(min_out: u128) -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (RES_X, 500u128));
    let [out] = b.call(pool(), "swap", (funds, min_out));
    let [] = b.call(ALICE, "deposit", (out.resource_is(RES_Y),));
    b.build().expect("every output is consumed")
}

fn swap_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(600).to_vec())
        .unwrap();
    store
        .write(vault(pool(), RES_X), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(vault(pool(), RES_Y), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(config_leaf(pool()), 30u16.to_le_bytes().to_vec())
        .unwrap();
    store.lock(config_leaf(pool())).unwrap();
    store.clear_log();
    store
}

#[test]
fn swap_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &swap_graph(300));

    let pool_set = &routing.per_shard[&shard_of(pool())];
    assert_eq!(
        *pool_set,
        set(&[
            point(config_leaf(pool()), Mode::Locked,),
            point(vault(pool(), RES_X), Mode::Write),
            point(vault(pool(), RES_Y), Mode::Write),
        ])
    );
    // The pool-shard provision carries the two balance cells and nothing
    // else: the reserves are read-modify-writes, the locked config is
    // verified-once and free.
    assert_eq!(
        pool_set.provision_targets(),
        [
            EffectTarget::Point(vault(pool(), RES_X)),
            EffectTarget::Point(vault(pool(), RES_Y)),
        ]
        .into_iter()
        .collect()
    );
    // The user's commutative side provisions nothing.
    assert!(
        routing.per_shard[&shard_of(ALICE)]
            .provision_targets()
            .is_empty()
    );
}

#[test]
fn swap_executes_with_real_pool_math_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let graph = swap_graph(300);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x02; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("swap must complete");
    };

    // The constant-product math, computed independently: 30 bps fee on
    // 500 in gives 498 effective; out = 1000 * 498 / 1498 = 332.
    assert_eq!(
        receipt.delta.cells.get(&vault(pool(), RES_X)),
        Some(&Some(encode_amount(1_500).to_vec()))
    );
    assert_eq!(
        receipt.delta.cells.get(&vault(pool(), RES_Y)),
        Some(&Some(encode_amount(668).to_vec()))
    );
    assert_eq!(receipt.delta.settles.get(&vault(ALICE, RES_X)), Some(&500));
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(ALICE, RES_Y))
            .unwrap()
            .credit,
        332
    );
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_Y)), 332);
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 100);
    Ok(())
}

#[test]
fn a_violated_output_floor_traps_identically() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    // 332 out cannot cover a 400 floor: the guest's assert is a
    // deterministic user-error trap on both runtimes, and no state moves.
    let graph = swap_graph(400);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x03; 32])))],
    );
    assert_eq!(results[0], TxResult::Trapped);
    assert_eq!(amount_of(&mut final_store, vault(pool(), RES_X)), 1_000);
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 600);
    Ok(())
}

fn place_graph() -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(MAKER, "withdraw", (BASE, 50u128));
    let [] = b.call(book(), "place-ask", (3u64, funds));
    b.build().expect("every output is consumed")
}

fn fill_graph() -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [payment] = b.call(TAKER, "withdraw", (QUOTE, 100u128));
    let [base, refund] = b.call(book(), "fill-asks", (3u64, 5u64, payment));
    let [] = b.call(TAKER, "deposit", (base.resource_is(BASE),));
    let [] = b.call(TAKER, "deposit", (refund.resource_is(QUOTE),));
    b.build().expect("every output is consumed")
}

#[test]
fn fill_provisions_only_the_interval() {
    let world = world();
    let routing = sharded_routing(&world, &fill_graph());
    let book_set = &routing.per_shard[&shard_of(book())];
    // The write interval is the only provisioned target: the escrow legs
    // are deltas and carry nothing.
    assert_eq!(
        book_set.provision_targets(),
        std::iter::once(EffectTarget::Range {
            owner: book().into(),
            collection: ASKS,
            lo: 3u128 << 64,
            hi: (5u128 << 64) | u128::from(u64::MAX),
            cap: FILL_CAP,
        })
        .collect()
    );
}

#[test]
fn the_order_book_matches_by_price_time_priority_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(MAKER, BASE), encode_amount(60).to_vec())
        .unwrap();
    store
        .write(vault(TAKER, QUOTE), encode_amount(150).to_vec())
        .unwrap();
    // A resting ask at price 5 from an earlier session, escrow included.
    store
        .entry_write(
            book().address(),
            ASKS,
            (5u128 << 64) | 7,
            encode_amount(10).to_vec(),
        )
        .unwrap();
    store
        .write(vault(book(), BASE), encode_amount(10).to_vec())
        .unwrap();
    store.clear_log();

    let place = place_graph();
    let fill = fill_graph();
    let (results, mut final_store) = run_both(
        &engines,
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
    let admitted = admit(&place, &world.0, &world.1, &TestHasher).unwrap();
    let seq = fresh_id(&TestHasher, admitted.identity(), 1, 0, 0);
    let placed_order = (3u128 << 64) | u128::from(seq);
    assert_eq!(
        place_receipt
            .delta
            .entries
            .get(&(book().address(), ASKS, placed_order)),
        Some(&Some(encode_amount(50).to_vec()))
    );

    // The fill: budget 100 at price 3 buys 33 (cost 99), leaving change 1;
    // the price-5 ask is untouched. Partial fill rewrote the entry.
    assert_eq!(
        fill_receipt
            .delta
            .entries
            .get(&(book().address(), ASKS, placed_order)),
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

    assert_eq!(amount_of(&mut final_store, vault(TAKER, BASE)), 33);
    assert_eq!(amount_of(&mut final_store, vault(TAKER, QUOTE)), 51);
    assert_eq!(amount_of(&mut final_store, vault(book(), BASE)), 27);
    assert_eq!(amount_of(&mut final_store, vault(book(), QUOTE)), 99);
    assert_eq!(amount_of(&mut final_store, vault(MAKER, BASE)), 10);
    let entries: BTreeMap<_, _> = final_store
        .collection_entries()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    assert_eq!(
        entries.get(&(book().address(), ASKS, placed_order)),
        Some(&encode_amount(17).to_vec())
    );
    assert_eq!(
        entries.get(&(book().address(), ASKS, (5u128 << 64) | 7)),
        Some(&encode_amount(10).to_vec())
    );
    Ok(())
}

#[test]
fn every_guest_builds_against_the_canonical_world() -> Result<()> {
    let canonical = std::fs::read(repo_root().join("crates/runtime/wit/kernel.wit"))?;
    for guest in ["transfer", "account", "amm", "book"] {
        let copy =
            std::fs::read(repo_root().join(format!("guests/{guest}/wit/deps/kernel/kernel.wit")))?;
        assert_eq!(canonical, copy, "{guest} kernel.wit drifted");
    }
    Ok(())
}
