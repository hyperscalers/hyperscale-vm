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
    ASKS, AUTH, CLAIMS, CONFIG, DRAIN_CAP, FILL_CAP, NAMES, VAULT, account_metadata, amm_metadata,
    book_metadata, registry_metadata,
};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, Address, AuthBase, AuthCell, Clause, CollectionId, ComponentAddr,
    Constraint, Effect, EffectSet, EffectTarget, Expr, Hash32, Hasher, InstanceMeta,
    InstanceRegistry, ManifestGraph, MetadataCache, MethodSignature, Mode, ModeExpr, PackageHash,
    PackageMetadata, ParamType, PrefixShardResolver, PrincipalAddr, Proposal, ResourceAddr, RoleId,
    RoleSet, Routing, Rule, ShardId, ShardResolver, SubstateKey, TargetExpr, TestHasher, Value,
    admit, child_key, collection_id, fresh_id, order_key, route,
};
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchTx, CellKind, EnvInputs, Event, GuestArg, GuestBackend, GuestCall, GuestRunner,
    InvokeResult, KernelSession, ManifestWalk, MemoryStore, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, decode_amount, encode_amount,
};
use hyperscale_vm_manifest_builder::native::{account, amm, book, registry};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
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

/// The book's asks collection, as the stdlib's declarations derive it.
fn asks() -> CollectionId {
    collection_id(&TestHasher, book(), ASKS, &[])
}

/// An account's stored-authority cell — what its sign-in reads.
fn auth(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, AUTH, &[])
}

/// One identity as all three roles, under the corpus delay.
fn uniform_base(identity: Address) -> AuthBase {
    AuthBase {
        recovery_delay_ms: DAY_MS,
        roles: RoleSet::uniform(Rule::Require(identity)),
    }
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("book"), book_metadata());
    cache.publish(pkg("registry"), registry_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, pool_meta());
    instances.create(&TestHasher, book_meta());
    instances.create(&TestHasher, registry_meta());
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

fn registry_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("registry"),
        config: vec![],
        salt: Hash32([5; 32]),
    }
}

/// The name registry instance.
fn registry_addr() -> ComponentAddr {
    registry_meta().address(&TestHasher)
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
    ("registry", "registry"),
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
        for name in ["account", "amm", "book", "registry"] {
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

/// Whose signature a corpus graph rides.
///
/// An intent carries one signature, so every guarded or authorizing node
/// in one names the same account — which is a property of these fixtures
/// rather than of manifests generally, and worth asserting where it is
/// relied on. A node presenting a minted proof still names its target
/// here: the proof's producer targets the same account, so the union is
/// unchanged.
fn composer(world: &(MetadataCache, InstanceRegistry), graph: &ManifestGraph) -> PrincipalAddr {
    let (cache, instances) = world;
    let mut signer = None;
    for node in &graph.nodes {
        let guarded = instances
            .get(node.target)
            .and_then(|meta| cache.get(meta.package))
            .and_then(|package| package.methods.get(&node.method))
            .is_some_and(|signature| {
                matches!(
                    signature.accessibility,
                    Accessibility::Guarded(_)
                        | Accessibility::Authorizing
                        | Accessibility::RoleGated(_)
                )
            });
        if !guarded {
            continue;
        }
        let principal = PrincipalAddr::try_from(node.target.address())
            .expect("a guarded corpus node targets an account");
        assert!(
            signer.is_none_or(|seen| seen == principal),
            "one intent, one signature: this graph needs two"
        );
        signer = Some(principal);
    }
    signer.unwrap_or(ALICE)
}

/// What one corpus transaction runs under: its hash, its intent signer,
/// and the transaction clock its block would have committed.
#[derive(Clone, Copy)]
struct Signing {
    tx: TxHash,
    signer: PrincipalAddr,
    clock_ms: u64,
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
    under: Signing,
) -> Result<(TxResult, MemoryStore)> {
    let Signing {
        tx,
        signer,
        clock_ms,
    } = under;
    let (cache, instances) = world;
    let admitted = admit(graph, signer, cache, instances, &TestHasher).context("admission")?;
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
    let entry = BatchTx::new(tx, declaration, clock_ms, env().randomness).with_calls(routing.calls);

    let before = store.clone();
    let session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &entry.declared,
        &entry.ordered,
        tx,
        EnvInputs {
            clock_ms,
            randomness: env().randomness,
        },
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
    let admitted =
        admit(graph, composer(world, graph), cache, instances, &TestHasher).expect("admits");
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
    run_both_signed(engines, world, store, transactions, None)
}

/// As [`run_both`], with one signature riding every graph — how a test
/// puts the wrong signer behind an authorization.
fn run_both_signed(
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
    signer: Option<PrincipalAddr>,
) -> (Vec<TxResult>, MemoryStore) {
    run_both_at(engines, world, store, transactions, signer, env().clock_ms)
}

/// As [`run_both_signed`], at an explicit transaction clock — how the
/// recovery tests move weighted time between transactions.
fn run_both_at(
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
    signer: Option<PrincipalAddr>,
    clock_ms: u64,
) -> (Vec<TxResult>, MemoryStore) {
    let mut lanes = Vec::new();
    for lane in [Lane::Blessed, Lane::Reference] {
        let mut results = Vec::new();
        let mut threaded = store.clone();
        for (graph, tx) in transactions {
            let under = Signing {
                tx: *tx,
                signer: signer.unwrap_or_else(|| composer(world, graph)),
                clock_ms,
            };
            let (result, next) =
                execute_manifest(lane, engines, world, threaded, graph, under).expect("driver");
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
    let entries = |store: &MemoryStore| -> BTreeMap<(Address, CollectionId, u128), Vec<u8>> {
        store
            .collection_entries()
            .map(|(k, v)| (k, v.to_vec()))
            .collect()
    };
    assert_eq!(
        entries(&blessed_store),
        entries(&ref_store),
        "entries diverged"
    );
    (blessed, blessed_store)
}

fn amount_of(store: &mut MemoryStore, key: SubstateKey) -> u128 {
    store
        .read(key)
        .unwrap()
        .map_or(0, |cell| decode_amount(&cell).unwrap())
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

fn transfer_graph() -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    })
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
        // Not a wrapper call: `dana` runs the mirror package, so its
        // deposit is the one this test published rather than the account's.
        let (cache, instances) = &world;
        let mut b = TypedBuilder::new(cache, instances, &TestHasher);
        let alice = account::authorize(&mut b, ALICE).unwrap();
        let funds = account::withdraw(&mut b, alice, RES_X, 100).unwrap();
        b.call(dana, "deposit", (funds,)).unwrap().none().unwrap();
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
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
        account::deposit(b, BOB, funds.constrain(constraint))
    })
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
                node: 2,
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

    // The walkthrough's profile: the sign-in's rule-cell read and one
    // reservation at the sender, the vault and claims deltas at the
    // recipient.
    let expected: BTreeMap<ShardId, EffectSet> = BTreeMap::from([
        (
            shard_of(ALICE),
            set(&[
                point(auth(ALICE), Mode::Read),
                point(vault(ALICE, RES_X), Mode::Reserve { amount: 100 }),
            ]),
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

    // The acceptance test, executable: the balance movement stays
    // commutative on both sides, and what provisions is exactly the
    // sender's rule cell — absent for a virtual account, and the read
    // is what carries that absence to the counterpart.
    assert_eq!(
        routing.per_shard[&shard_of(ALICE)].provision_targets(),
        std::iter::once(EffectTarget::Point(auth(ALICE))).collect()
    );
    assert!(
        routing.per_shard[&shard_of(BOB)]
            .provision_targets()
            .is_empty()
    );
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

/// The same transfer, signed in rather than signed per call: authorize
/// mints Alice's identity and the withdrawal presents that proof instead
/// of the intent's signature.
fn authorized_transfer_graph() -> ManifestGraph {
    graph(|b| {
        let proof = account::authorize(b, ALICE)?;
        let funds = b
            .call_as(proof, ALICE, "withdraw", (RES_X, 100u128))?
            .one()?;
        account::deposit(b, BOB, funds)
    })
}

#[test]
fn a_transfer_on_a_minted_proof_settles_like_one_on_the_signature() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    let graph = authorized_transfer_graph();
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0A; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the authorized transfer must complete");
    };
    // The proof changes where the withdrawal's authority came from and
    // nothing about what it did.
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
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 100);
    Ok(())
}

#[test]
fn a_refused_authorization_takes_its_consumers_with_it() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    // Bob's signature behind Alice's sign-in: admission passes — the
    // evidence is present, and whether it satisfies the target is the
    // target's question — and the authorizing node's own gate refuses at
    // execution, taking the whole transaction with it. This is what
    // makes the minted proof sound with nothing checking it later: the
    // withdrawal that would have spent on it never runs.
    let graph = authorized_transfer_graph();
    let (results, mut final_store) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x0B; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })]
    );
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 0);
    Ok(())
}

/// The recovery delay every corpus cell stores: one day of weighted
/// time, against a test clock that starts at [`env`]'s 5000 ms.
const DAY_MS: u64 = 86_400_000;

/// Sign in and hand the account to Bob's rule, uniformly.
fn securify_graph(rule: Rule) -> ManifestGraph {
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
fn securify_retires_the_old_key_and_installs_the_rule() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    // Alice's last act under the virtual rule: signing in for its
    // retirement. Everything she stores from here is governed by Bob.
    let securify = securify_graph(Rule::Require(BOB.address()));
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&securify, TxHash(Hash32([0x51; 32])))],
    );
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
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&transfer, TxHash(Hash32([0x52; 32])))],
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::Unauthorized { node: 0 })],
        "the retired key must not open the account"
    );

    // Bob's signature carries Bob's identity, the stored rule admits
    // it, and the minted proof opens Alice's guarded methods.
    let (results, mut store) = run_both_signed(
        &engines,
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
    assert_eq!(amount_of(&mut store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&mut store, vault(BOB, RES_X)), 100);

    // Nothing re-securifies: the guest's one-way door traps, whoever
    // holds the current rule.
    let again = securify_graph(Rule::Require(BOB.address()));
    let (results, _) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&again, TxHash(Hash32([0x54; 32])))],
        Some(BOB),
    );
    assert_eq!(
        results,
        vec![TxResult::Trapped],
        "securifying a securified account is the guest's own refusal"
    );
    Ok(())
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
    store.clear_log();
    store
}

/// Two stored rules deep, on both runtimes: Bob's signature opens
/// Alice's sign-in, and the proof it mints opens the maker's — an entry
/// no signature reaches directly, since the maker's rule names an
/// account rather than a key the intent could carry.
#[test]
fn a_chained_sign_in_acts_two_rules_deep() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
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
        &engines,
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
    let (results, mut store) = run_both_signed(
        &engines,
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
    assert_eq!(amount_of(&mut store, vault(MAKER, RES_X)), 50);
    assert_eq!(amount_of(&mut store, vault(BOB, RES_X)), 100);
    Ok(())
}

/// A minted proof opens only its own account: presented at another's
/// guarded method it refuses at that node's gate, however valid the
/// sign-in that minted it.
#[test]
fn a_proof_opens_only_the_account_that_minted_it() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(BOB, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

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
        &engines,
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
    Ok(())
}

/// The split-role setup every recovery test starts from: Alice holds
/// primary, Bob recovery, the maker confirmation, and the corpus delay
/// separates a proposal from its maturity.
const fn split_roles() -> RoleSet {
    RoleSet {
        primary: Rule::Require(ALICE.address()),
        recovery: Rule::Require(BOB.address()),
        confirmation: Rule::Require(MAKER.address()),
    }
}

const fn split_base() -> AuthBase {
    AuthBase {
        recovery_delay_ms: DAY_MS,
        roles: split_roles(),
    }
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
    store.clear_log();
    store
}

fn propose_graph() -> ManifestGraph {
    graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(Rule::Require(BOB.address())),
            DAY_MS,
        )
    })
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
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    signer: PrincipalAddr,
    clock_ms: u64,
    admits: bool,
    tag: u8,
) {
    let transfer = authorized_transfer_graph();
    let (results, _) = run_both_at(
        engines,
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
fn a_proposal_governs_from_its_instant_with_nothing_applying_it() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = recovered_store();
    let t0 = env().clock_ms;

    // The primary cannot propose and the recovery key cannot spend:
    // each role opens its own gate and no other.
    let (results, _) = run_both_signed(
        &engines,
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
        &engines,
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
    assert_acts(&engines, &world, &store, ALICE, before, true, 0x62);
    assert_acts(&engines, &world, &store, BOB, before, false, 0x63);
    assert_acts(&engines, &world, &store, BOB, at, true, 0x64);
    assert_acts(&engines, &world, &store, ALICE, at, false, 0x65);

    // A later cancel by the new primary compacts the matured proposal
    // into the base — it cannot cancel what already governs — and the
    // old primary stays retired.
    let (results, store) = run_both_at(
        &engines,
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
    assert_acts(&engines, &world, &store, ALICE, at, false, 0x67);
    Ok(())
}

/// Primary cancels an unmatured proposal, and every later verdict —
/// however far past the would-be maturity — is under the old roles, as
/// if nothing had been proposed.
#[test]
fn primary_cancels_an_unmatured_proposal() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x68; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));
    let (results, store) = run_both_signed(
        &engines,
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
    assert_acts(&engines, &world, &store, ALICE, long_after, true, 0x6A);
    assert_acts(&engines, &world, &store, BOB, long_after, false, 0x6B);

    // With nothing pending, confirm is the guest's own refusal.
    let (results, _) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&confirm_graph(), TxHash(Hash32([0x6C; 32])))],
        Some(MAKER),
    );
    assert_eq!(results, vec![TxResult::Trapped]);
    Ok(())
}

/// Confirmation enacts a proposal early: the new roles govern from the
/// confirm, a day before the instant would have arrived on its own.
#[test]
fn confirmation_enacts_a_proposal_early() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&propose_graph(), TxHash(Hash32([0x6D; 32])))],
        Some(BOB),
    );
    assert!(matches!(&results[0], TxResult::Completed(_)));

    // The recovery key cannot confirm its own proposal.
    let (results, _) = run_both_signed(
        &engines,
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
        &engines,
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
    assert_acts(&engines, &world, &store, BOB, t0, true, 0x70);
    assert_acts(&engines, &world, &store, ALICE, t0, false, 0x71);
    Ok(())
}

/// A second propose replaces an unmatured proposal — its timer restarts
/// from the replacing clock — and an unsecurified account has nothing
/// to propose against.
#[test]
fn propose_replaces_a_pending_proposal_and_needs_a_cell() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = recovered_store();
    let t0 = env().clock_ms;

    let (results, store) = run_both_signed(
        &engines,
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
            RoleSet::uniform(Rule::Require(MAKER.address())),
            DAY_MS,
        )
    });
    let (results, _) = run_both_at(
        &engines,
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

    // A virtual account has no cell: propose is the guest's own trap,
    // judged after the virtual rule signed the caller in.
    let mut virtual_store = MemoryStore::new();
    virtual_store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    virtual_store.clear_log();
    let own_propose = graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(Rule::Require(BOB.address())),
            DAY_MS,
        )
    });
    let (results, _) = run_both_signed(
        &engines,
        &world,
        &virtual_store,
        &[(&own_propose, TxHash(Hash32([0x74; 32])))],
        Some(ALICE),
    );
    assert_eq!(results, vec![TxResult::Trapped]);
    Ok(())
}

fn swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 500)?;
        let out = amm::swap(b, pool(), funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
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
    // The user's side provisions exactly the sign-in's rule cell; her
    // balance movement stays commutative.
    assert_eq!(
        routing.per_shard[&shard_of(ALICE)].provision_targets(),
        std::iter::once(EffectTarget::Point(auth(ALICE))).collect()
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
    graph(|b| {
        let maker = account::authorize(b, MAKER)?;
        let funds = account::withdraw(b, maker, BASE, 50)?;
        book::place_ask(b, book(), 3, funds)
    })
}

fn fill_graph() -> ManifestGraph {
    graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = account::withdraw(b, taker, QUOTE, 100)?;
        let [bought, refund] = book::fill_asks(b, book(), 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    })
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
            collection: asks(),
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
            asks(),
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
    let admitted = admit(&place, MAKER, &world.0, &world.1, &TestHasher).unwrap();
    let seq = fresh_id(&TestHasher, admitted.identity(), 2, 0, 0);
    let placed_order = (3u128 << 64) | u128::from(seq);
    assert_eq!(
        place_receipt
            .delta
            .entries
            .get(&(book().address(), asks(), placed_order)),
        Some(&Some(encode_amount(50).to_vec()))
    );

    // The fill: budget 100 at price 3 buys 33 (cost 99), leaving change 1;
    // the price-5 ask is untouched. Partial fill rewrote the entry.
    assert_eq!(
        fill_receipt
            .delta
            .entries
            .get(&(book().address(), asks(), placed_order)),
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
        entries.get(&(book().address(), asks(), placed_order)),
        Some(&encode_amount(17).to_vec())
    );
    assert_eq!(
        entries.get(&(book().address(), asks(), (5u128 << 64) | 7)),
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

/// The unordered collection end to end on both runtimes: bindings land at
/// their hashed orders, a rebind overwrites in place, a mismatched check
/// traps and rolls back, and one drain crank clears the tail.
#[test]
fn the_registry_binds_checks_and_drains_hashed_entries() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = MemoryStore::new();

    let bind = |name: u64, value: u128| graph(|b| registry::bind(b, registry_addr(), name, value));
    let check =
        |name: u64, expected: u128| graph(|b| registry::check(b, registry_addr(), name, expected));

    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[
            (&bind(7, 700), TxHash(Hash32([0x51; 32]))),
            (&bind(9, 900), TxHash(Hash32([0x52; 32]))),
            (&bind(7, 701), TxHash(Hash32([0x53; 32]))),
            (&check(7, 701), TxHash(Hash32([0x54; 32]))),
            (&check(9, 901), TxHash(Hash32([0x55; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    assert!(
        matches!(results[2], TxResult::Completed(_)),
        "a rebind lands"
    );
    assert!(
        matches!(results[3], TxResult::Completed(_)),
        "a true check passes"
    );
    assert_eq!(results[4], TxResult::Trapped, "a false check traps");

    // Exactly two bindings, each at the order its name hashes to, holding
    // the last value bound — the rebind overwrote in place.
    let names = collection_id(&TestHasher, registry_addr(), NAMES, &[]);
    let order_of = |name: u64| {
        order_key(
            &TestHasher,
            registry_addr(),
            NAMES,
            &[Value::U64(name).canonical_bytes()],
        )
    };
    let entries: BTreeMap<u128, Vec<u8>> = store
        .collection_entries()
        .filter(|((owner, collection, _), _)| {
            (*owner, *collection) == (registry_addr().into(), names)
        })
        .map(|((.., order), value)| (order, value.to_vec()))
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[&order_of(7)], 701u128.to_le_bytes().to_vec());
    assert_eq!(entries[&order_of(9)], 900u128.to_le_bytes().to_vec());

    // One crank from the bottom of the hash order clears everything —
    // two entries against a cap of eight.
    assert!(u32::try_from(entries.len()).unwrap() <= DRAIN_CAP);
    let drain = graph(|b| registry::drain(b, registry_addr(), 0));
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&drain, TxHash(Hash32([0x56; 32])))],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        store.collection_entries().count(),
        0,
        "the drain left nothing"
    );
    Ok(())
}
