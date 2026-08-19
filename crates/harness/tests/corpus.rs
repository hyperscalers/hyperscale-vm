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

use hyperscale_vm_effects::vocabulary::{AUTH, CLAIMS, CONFIG, VAULT};
use hyperscale_vm_effects::{
    AbiParam, Address, AdmissionError, AuthBase, AuthCell, Clause, CollectionId, ComponentAddr,
    Constraint, Effect, EffectSet, EffectTarget, EntryKey, EvidenceRef, Expr, Hash32, Hasher,
    InstanceMeta, InstanceRegistry, MAX_STAGED_DEPTH, ManifestGraph, MetadataCache,
    MethodSignature, Mode, ModeExpr, PackageHash, PackageMetadata, ParamType, PrefixShardResolver,
    Presence, Presented, PrincipalAddr, Proposal, ResourceAddr, Role, RoleSet, Routing, ShardId,
    ShardResolver, SlotId, StoredRule, Strategy, SubstateKey, TargetExpr, TestHasher, Totality,
    Value, admit, child_key, collection_id, fresh_id, holdings_collection, instance_data_key,
    order_key, resource_address, route,
};
use hyperscale_vm_fixtures::{amm, book, lottery, nf, registry, shares};
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_kernel::{
    AbortReason, BatchTx, EnvInputs, Event, GuestBackend, GuestCall, GuestRunner, InvokeResult,
    Invoked, KernelSession, ManifestWalk, MemoryStore, Outcome, OverlayStore, Receipt, RunResult,
    Substates, TxHash, decode_amount, encode_amount, multiply_held_ids,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_ref::{CVal, ExecError, RefComponent, RefComponentInstance, Trap as RefTrap};
use hyperscale_vm_runtime::{
    Returned, add_kernel_to_linker, blessed_engine, call_export, check_method, classify, exhausted,
    validate_component,
};
use hyperscale_vm_sdk::hbor::from_slice;
use hyperscale_vm_stdlib::account;
use wasmtime::component::{Component, Linker};
use wasmtime::error::{Context, ensure};
use wasmtime::{Engine, Result, Store};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const MAKER: PrincipalAddr = PrincipalAddr::new([0x50; 31]);
const TAKER: PrincipalAddr = PrincipalAddr::new([0x60; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const RES_Z: ResourceAddr = ResourceAddr::new([0xE5; 31]);
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
    collection_id(&TestHasher, book(), book::ASKS, &[])
}

/// An account's stored-authority cell — what its sign-in reads.
fn auth(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, AUTH, &[])
}

/// One identity as all three roles, under the corpus delay.
fn uniform_base(identity: Address) -> AuthBase {
    AuthBase::new(
        DAY_MS,
        &RoleSet::uniform(StoredRule::Require(identity.into())),
    )
    .expect("a rule within the vocabulary caps")
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account::metadata());
    cache.publish(pkg("amm"), amm::metadata());
    cache.publish(pkg("book"), book::metadata());
    cache.publish(pkg("registry"), registry::metadata());
    cache.publish(pkg("nf"), nf::metadata());
    cache.publish(pkg("lottery"), lottery::metadata());
    cache.publish(pkg("shares"), shares::metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, pool_meta());
    instances.create(&TestHasher, book_meta());
    instances.create(&TestHasher, registry_meta());
    instances.create(&TestHasher, nf_issuer_meta());
    instances.create(&TestHasher, nf_holder_meta(7));
    instances.create(&TestHasher, nf_holder_meta(8));
    instances.create(&TestHasher, gated_meta(nf_resource().address(), 9));
    instances.create(&TestHasher, gated_meta(RES_X.address(), 10));
    instances.create(&TestHasher, lottery_meta());
    instances.create(&TestHasher, shares_meta());
    (cache, instances)
}

fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        // The pair, then the fee: the guest reads the fee as an
        // evaluated slot, so it is configuration rather than a shape
        // spliced into the locked leaf. Thirty basis points, at the scale
        // the bounded type holds — the range was checked when the value
        // was made, and the cell carries what it made.
        config: vec![
            Value::Address(RES_X.address()),
            Value::Address(RES_Y.address()),
            Value::U128(30 * (1_000_000_000_000_000_000 / 10_000)),
        ],
        salt: Hash32([2; 32]),
    }
}

/// The pool instance, at the address its record derives.
fn pool() -> amm::Amm {
    amm::Amm::at(pool_meta().address(&TestHasher))
}

/// The share vault, over the asset it prices shares against.
fn shares_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("shares"),
        config: vec![Value::Address(RES_X.address())],
        salt: Hash32([11; 32]),
    }
}

/// The share vault instance.
fn shares_vault() -> shares::Shares {
    shares::Shares::at(shares_meta().address(&TestHasher))
}

/// The share the vault issues against deposits.
fn shares_unit() -> ResourceAddr {
    resource_address(&TestHasher, Address::from(shares_vault()), &[])
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
fn book() -> book::Book {
    book::Book::at(book_meta().address(&TestHasher))
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

fn nf_issuer_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![],
        salt: Hash32([6; 32]),
    }
}

/// The non-fungible issuer instance.
fn nf_issuer() -> ComponentAddr {
    nf_issuer_meta().address(&TestHasher)
}

/// The resource the issuer mints: its own provenance, empty material.
fn nf_resource() -> ResourceAddr {
    resource_address(&TestHasher, nf_issuer().address(), &[])
}

fn nf_holder_meta(salt: u8) -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![],
        salt: Hash32([salt; 32]),
    }
}

/// A non-fungible holder instance.
fn nf_holder(salt: u8) -> ComponentAddr {
    nf_holder_meta(salt).address(&TestHasher)
}

/// A badge-gated instance: its one config slot names the badge resource
/// its operator surface opens for.
fn gated_meta(badge: Address, salt: u8) -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![Value::Address(badge)],
        salt: Hash32([salt; 32]),
    }
}

/// The instance gated on `badge`.
fn gated_by(badge: Address, salt: u8) -> ComponentAddr {
    gated_meta(badge, salt).address(&TestHasher)
}

fn lottery_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("lottery"),
        config: vec![],
        salt: Hash32([11; 32]),
    }
}

/// The lottery instance.
fn lottery_addr() -> lottery::Lottery {
    lottery::Lottery::at(lottery_meta().address(&TestHasher))
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
    ("nf", "nf"),
    ("lottery", "lottery"),
    ("shares", "shares"),
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
        for name in [
            "account", "amm", "book", "registry", "nf", "lottery", "shares",
        ] {
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
        let mut linker = Linker::<KernelSession>::new(&self.engines.engine);
        add_kernel_to_linker(&mut linker).expect("wiring");
        let mut store = Store::new(&self.engines.engine, session);
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let component = &self.engines.blessed[self.engines.guest_for(call.package)];
        let instance = linker
            .instantiate(&mut store, component)
            .expect("instantiate");
        let outcome = call_export(&mut store, &instance, call.export, call.args);
        let exhausted = outcome.as_ref().err().is_some_and(exhausted);
        let result = invoked(outcome);
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        InvokeResult {
            session: store.into_data(),
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
        let args: Vec<CVal> = call.args.iter().map(CVal::from).collect();
        let component = &self.engines.reference[self.engines.guest_for(call.package)];
        let mut instance = RefComponentInstance::instantiate(component, session)
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
            session: instance.into_host(),
            fuel,
            result,
            exhausted,
        }
    }
}

/// The blessed engine's verdict as the kernel's.
fn invoked(outcome: Result<Returned>) -> Invoked {
    match outcome {
        Ok(Returned::Edges(reps)) => Invoked::Produced(reps),
        Ok(Returned::Declined(code)) => Invoked::Declined(code),
        Err(error) => Invoked::Aborted(classify(&error)),
    }
}

/// The reference interpreter's lifted results as the kernel's verdict.
fn lifted(values: &[CVal]) -> Invoked {
    match values {
        [] => Invoked::Produced(Vec::new()),
        // Every value is an edge, or the shape is one the convention
        // does not fix.
        edges if !edges.is_empty() && edges.iter().all(|v| matches!(v, CVal::Own(_))) => {
            Invoked::Produced(
                edges
                    .iter()
                    .map(|v| match v {
                        CVal::Own(rep) => *rep,
                        _ => unreachable!("every value is an owned edge"),
                    })
                    .collect(),
            )
        }
        [CVal::Declined(code)] => Invoked::Declined(*code),
        _ => Invoked::Aborted(AbortReason::BadReturnShape),
    }
}

/// How one transaction ended on a lane.
#[derive(Debug, PartialEq, Eq)]
enum TxResult {
    Completed(Receipt),
    /// The guest trapped, with the class both runtimes classified it as.
    /// Compared whole: the vocabulary is closed, so the two lanes
    /// disagreeing here is a divergence rather than a wording difference.
    Trapped(AbortReason),
    /// The package declined on its own terms, with an index into its
    /// error table. Not a defect and not the kernel's refusal: the guest
    /// ran to completion and said no.
    Declined(u32),
    /// The kernel refused, before or around the call.
    Refused(Outcome),
}

/// Whose signature a corpus graph rides.
///
/// An intent carries one signature, so every node presenting it names
/// the same account — which is a property of these fixtures rather than
/// of manifests generally, and worth asserting where it is relied on.
/// Nodes presenting minted proofs contribute nothing: their proofs chain
/// back to a signature-presenting node of the same graph.
fn composer(graph: &ManifestGraph) -> PrincipalAddr {
    let mut signer = None;
    for node in &graph.nodes {
        if !node.evidence.contains(&EvidenceRef::IntentSignature) {
            continue;
        }
        let principal = PrincipalAddr::try_from(node.target.address())
            .expect("a signing corpus node targets an account");
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
    // A presence requirement and a reservation are both judged here,
    // before any body runs, so a refusal at this seam is an outcome the
    // lane reports rather than a harness failure. Mapped through the
    // executor's own conversion, so what a corpus test sees is what a
    // block would record.
    let session = match KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &entry.declaration,
        tx,
        EnvInputs {
            clock_ms,
            randomness: env().randomness,
        },
        test_hash,
    ) {
        Ok(session) => session,
        Err(defect) => {
            return Ok(match Outcome::from(defect) {
                Outcome::UserError { reason } => (TxResult::Trapped(reason), before),
                refused => (TxResult::Refused(refused), before),
            });
        }
    };

    let blessed = BlessedBackend { engines };
    let reference = ReferenceBackend { engines };
    let run = match lane {
        Lane::Blessed => ManifestWalk { backend: &blessed }.run(&entry, session),
        Lane::Reference => ManifestWalk {
            backend: &reference,
        }
        .run(&entry, session),
    }
    .expect("every corpus package is registered with both engines");
    match run {
        RunResult::Completed { session, fuel, .. } => {
            let (receipt, threaded) = session
                .finish(None, fuel)
                .expect("the oracle stands on every corpus receipt");
            Ok((TxResult::Completed(receipt), threaded.collapse_onto(before)))
        }
        RunResult::Aborted { outcome, .. } => match outcome {
            Outcome::UserError { reason } => Ok((TxResult::Trapped(reason), before)),
            Outcome::Declined { code, .. } => Ok((TxResult::Declined(code), before)),
            refused => Ok((TxResult::Refused(refused), before)),
        },
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
    let admitted = admit(graph, composer(graph), cache, instances, &TestHasher).expect("admits");
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
                signer: signer.unwrap_or_else(|| composer(graph)),
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
    let entries = |store: &MemoryStore| -> BTreeMap<EntryKey, Vec<u8>> {
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

fn amount_of(store: &MemoryStore, key: SubstateKey) -> u128 {
    store
        .cell(key)
        .map_or(0, |cell| decode_amount(&cell).unwrap())
}

/// Build against this world's metadata, so every call is typed by the
/// signature it names and every edge carries the resource that signature
/// declares — neither of which is written out below.
fn graph(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    graph_in(&world(), write)
}

/// As [`graph`], against a world a test extended: an instance whose
/// configuration names something only a run can produce — an instance id
/// — is registered by the test rather than by the shared fixture.
fn graph_in(
    world: &(MetadataCache, InstanceRegistry),
    write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> ManifestGraph {
    let mut b = TypedBuilder::new(&world.0, &world.1, &TestHasher);
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
    let self_child = |slot: SlotId, material: Vec<Expr>| Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot,
        material,
    };
    let resource_of_arg0 = || Expr::ResourceOf(Box::new(Expr::Arg(0)));
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "deposit".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(1), AbiParam::Bucket(0)],
            effects: vec![
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(self_child(CLAIMS, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(resource_of_arg0())),
                },
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(self_child(VAULT, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(resource_of_arg0())),
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

    let graph = transfer_graph();
    let (results, final_store) = run_both(
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
    let table = account::metadata().events;
    assert_eq!(table, vec!["withdrawn", "deposited"]);
    for event in &receipt.events {
        assert!(
            table.get(event.event_type as usize).is_some(),
            "event type {} resolves in its emitter's package",
            event.event_type,
        );
    }
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 100);
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

    let graph = authorized_transfer_graph();
    let (results, final_store) = run_both(
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
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 100);
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

    // Bob's signature behind Alice's sign-in: admission passes — the
    // evidence is present, and whether it satisfies the target is the
    // target's question — and the authorizing node's own gate refuses at
    // execution, taking the whole transaction with it. This is what
    // makes the minted proof sound with nothing checking it later: the
    // withdrawal that would have spent on it never runs.
    let graph = authorized_transfer_graph();
    let (results, final_store) = run_both_signed(
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
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 0);
    Ok(())
}

/// The recovery delay every corpus cell stores: one day of weighted
/// time, against a test clock that starts at [`env`]'s 5000 ms.
const DAY_MS: u64 = 86_400_000;

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
fn securify_retires_the_old_key_and_installs_the_rule() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();

    // Alice's last act under the virtual rule: signing in for its
    // retirement. Everything she stores from here is governed by Bob.
    let securify = securify_graph(StoredRule::Require(Presented::of_address(BOB.address())));
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
    let (results, store) = run_both_signed(
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
    assert_eq!(amount_of(&store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&store, vault(BOB, RES_X)), 100);

    // Nothing re-securifies, and the refusal is the protocol's rather
    // than the guest's: `securify` declares a write requiring the cell
    // to be absent, so the shard holding it judges the door against
    // committed state and the body never runs.
    let again = securify_graph(StoredRule::Require(Presented::of_address(BOB.address())));
    let (results, _) = run_both_signed(
        &engines,
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
    let (results, store) = run_both_signed(
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
    assert_eq!(amount_of(&store, vault(MAKER, RES_X)), 50);
    assert_eq!(amount_of(&store, vault(BOB, RES_X)), 100);
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

fn propose_graph() -> ManifestGraph {
    graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(StoredRule::Require(Presented::of_address(BOB.address()))),
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
    assert_eq!(results, vec![TxResult::Trapped(AbortReason::Unreachable)]);
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
            RoleSet::uniform(StoredRule::Require(Presented::of_address(MAKER.address()))),
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
        &engines,
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
    Ok(())
}

fn swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

/// The same trade the other way round, paid in the side the pool sold
/// last time.
fn reverse_swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_Y, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

/// The same trade, paid in a resource the pool does not trade at all.
fn untraded_swap_graph() -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_Z, 500)?;
        let out = pool().swap(b, funds, 0)?;
        account::deposit(b, ALICE, out)
    })
}

/// The pool's pair is its configuration's, and a manifest paying in a
/// third resource never becomes a transaction.
///
/// The declared denomination is a conditional over that pair rather than
/// the resource the edge happens to carry, which is what keeps the cycle
/// total: a resource in neither side selects the side it is not, and the
/// mismatch is the refusal. Were it read off the edge instead, a caller
/// could pay in anything, land it in a vault holding none of it, and have
/// the curve quote a share against an empty reserve. Refused at
/// admission, where the verdict is a function of signed content and costs
/// the sender nothing.
#[test]
fn a_swap_paid_in_a_resource_the_pool_does_not_trade_is_refused() {
    let (cache, instances) = world();
    let graph = untraded_swap_graph();
    let refused = admit(&graph, ALICE, &cache, &instances, &TestHasher)
        .expect_err("the pool trades a pair and this manifest pays neither side");

    let AdmissionError::Denomination {
        param,
        expected,
        found,
        ..
    } = refused
    else {
        panic!("the refusal names the denomination: {refused:?}");
    };
    assert_eq!(param, 0, "the payment is the swap's first argument");
    assert_eq!(
        expected,
        RES_Y.address(),
        "a resource that is not x selects the side it is not"
    );
    assert_eq!(found, RES_Z.address());
}

/// The control: both sides of the pair admit against one instance.
#[test]
fn a_swap_paid_in_either_side_of_the_pair_admits() {
    let (cache, instances) = world();
    for graph in [swap_graph(300), reverse_swap_graph(300)] {
        admit(&graph, ALICE, &cache, &instances, &TestHasher)
            .expect("either side of the configured pair is one the declaration asks for");
    }
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
        .write(config_leaf(pool()), pool_meta().config_bytes().unwrap())
        .unwrap();
    store.lock(config_leaf(pool()));
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
            point(
                vault(pool(), RES_X),
                Mode::Write {
                    requires: Presence::Either
                }
            ),
            point(
                vault(pool(), RES_Y),
                Mode::Write {
                    requires: Presence::Either
                }
            ),
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
    let (results, final_store) = run_both(
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
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_Y)), 332);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 100);
    Ok(())
}

/// The other direction, against the same instance and the same reserves.
///
/// One pool, one curve, both ways round — which is the whole of what a
/// conditional key buys here. A second instance would price the same
/// market off half the liquidity, and the two would drift apart on every
/// trade either one took.
#[test]
fn the_pool_trades_both_directions_off_one_instance() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = swap_store();
    store
        .write(vault(ALICE, RES_Y), encode_amount(600).to_vec())
        .unwrap();
    let (results, final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&reverse_swap_graph(300), TxHash(Hash32([0x04; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("swap must complete");
    };

    // The mirror of the forward trade, because the reserves are equal:
    // 500 in less 30 bps is 498 effective, and 1000 * 498 / 1498 is 332.
    assert_eq!(
        receipt.delta.cells.get(&vault(pool(), RES_Y)),
        Some(&Some(encode_amount(1_500).to_vec()))
    );
    assert_eq!(
        receipt.delta.cells.get(&vault(pool(), RES_X)),
        Some(&Some(encode_amount(668).to_vec()))
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 932);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_Y)), 100);
    Ok(())
}

/// The floor is declined, not trapped, and the two lanes reach the same
/// code.
///
/// The distinction is the whole of A1: 332 out cannot cover a 400 floor,
/// which is a race the sender lost between signing and execution rather
/// than a defect it committed. The abort is still whole-transaction —
/// nothing moves, and the manifest does not branch on the arm — but the
/// receipt records what happened instead of a wasm backtrace, and the
/// fee schedule prices it as the lost race.
#[test]
fn a_violated_output_floor_declines_identically() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let graph = swap_graph(400);
    let (results, final_store) = run_both(
        &engines,
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x03; 32])))],
    );
    assert_eq!(results[0], TxResult::Declined(amm::SLIPPAGE_EXCEEDED));
    assert_eq!(
        amm::metadata().errors[amm::SLIPPAGE_EXCEEDED as usize],
        "slippage-exceeded",
        "the code is an index into the table the package published",
    );
    assert_eq!(amount_of(&final_store, vault(pool(), RES_X)), 1_000);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 600);
    Ok(())
}

fn place_graph() -> ManifestGraph {
    graph(|b| {
        let maker = account::authorize(b, MAKER)?;
        let funds = account::withdraw(b, maker, BASE, 50)?;
        book().place_ask(b, 3, funds)
    })
}

fn fill_graph() -> ManifestGraph {
    graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = account::withdraw(b, taker, QUOTE, 100)?;
        let [bought, refund] = book().fill_asks(b, 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    })
}

/// A book means its configured pair, so each side takes the resource its
/// own vault holds and refuses the other before the transaction exists.
///
/// Both directions matter and they fail differently in the world without
/// the check: an ask escrowed in something the book does not sell stands
/// on the ladder at any price a maker likes, and a fill paid in something
/// the book does not price buys real base with it.
#[test]
fn each_side_of_the_book_takes_only_its_own_resource() {
    let (cache, instances) = world();
    let refused = |graph: &ManifestGraph, signer| {
        admit(graph, signer, &cache, &instances, &TestHasher)
            .expect_err("the book declares which side this is")
    };

    // A maker escrowing quote where the book escrows base.
    let wrong_ask = graph(|b| {
        let maker = account::authorize(b, MAKER)?;
        let funds = account::withdraw(b, maker, QUOTE, 50)?;
        book().place_ask(b, 3, funds)
    });
    assert!(
        matches!(
            refused(&wrong_ask, MAKER),
            AdmissionError::Denomination { param: 1, expected, found, .. }
                if expected == BASE.address() && found == QUOTE.address()
        ),
        "an ask escrows the base side"
    );

    // A taker paying base where the book is paid in quote.
    let wrong_fill = graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = account::withdraw(b, taker, BASE, 100)?;
        let [bought, refund] = book().fill_asks(b, 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    });
    assert!(
        matches!(
            refused(&wrong_fill, TAKER),
            AdmissionError::Denomination { param: 2, expected, found, .. }
                if expected == QUOTE.address() && found == BASE.address()
        ),
        "a fill pays the quote side"
    );

    // The controls: each side in the resource it is declared in.
    admit(&place_graph(), MAKER, &cache, &instances, &TestHasher).expect("an ask in base admits");
    admit(&fill_graph(), TAKER, &cache, &instances, &TestHasher).expect("a fill in quote admits");
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
            cap: book::FILL_CAP,
        })
        .collect()
    );
}

/// One catalogue pattern and the star its shape implies.
struct Shape {
    name: &'static str,
    graph: ManifestGraph,
    /// Where each node sits, in node order.
    roles: Vec<Role>,
    /// Every shard change along the longest chain.
    crossings: u32,
    /// Only the crossings something waits on.
    stages: u32,
    strategy: Strategy,
}

/// Every catalogue shape, and the decomposition it implies.
///
/// One table rather than an assertion bolted onto each behavioural test,
/// because what earns its place here is the *contrast* between the rows:
/// the same classifier has to call a transfer a degenerate star, a venue
/// call a one-stage star, a self-governing account nothing at all, and a
/// named-instance move back to replication. A row on its own would say
/// little; the set is the falsifier.
#[test]
fn every_pattern_takes_the_star_its_shape_implies() {
    let world = world();
    let shapes = vec![
        // A core with a leg either side and no venue between them. The
        // one crossing is into the recipient's deposit, which cannot
        // refuse, so nothing waits and no stage is owed.
        Shape {
            name: "transfer",
            graph: transfer_graph(),
            roles: vec![Role::Core, Role::Inbound, Role::Outbound],
            crossings: 1,
            stages: 0,
            strategy: Strategy::LegLocal,
        },
        // The venue star: the withdrawal inbound, the pool a single-shard
        // core, the delivery outbound. Two crossings to reach the venue
        // and return, and only the outbound one is free.
        Shape {
            name: "swap",
            graph: swap_graph(300),
            roles: vec![Role::Core, Role::Inbound, Role::Core, Role::Outbound],
            crossings: 2,
            stages: 1,
            strategy: Strategy::LegLocal,
        },
        // The same star over a range rather than points — an interval's
        // width prices provisioning and never depth — and the first
        // shape with more than one outbound leg, which is what L2's "N
        // outbound legs" was written for: a fill pays out on two edges
        // and the core waits on neither.
        Shape {
            name: "fill",
            graph: fill_graph(),
            roles: vec![
                Role::Core,
                Role::Inbound,
                Role::Core,
                Role::Outbound,
                Role::Outbound,
            ],
            crossings: 2,
            stages: 1,
            strategy: Strategy::LegLocal,
        },
        // An account governing itself reaches no further than itself, so
        // there is no star to take and the two strategies name the same
        // execution.
        Shape {
            name: "propose",
            graph: propose_graph(),
            roles: vec![Role::Core],
            crossings: 0,
            stages: 0,
            strategy: Strategy::Replicated,
        },
    ];

    for shape in shapes {
        let routing = sharded_routing(&world, &shape.graph);
        let name = shape.name;
        assert_eq!(routing.roles, shape.roles, "{name}: star");
        assert_eq!(
            routing.alternation_depth, shape.crossings,
            "{name}: crossings"
        );
        assert_eq!(routing.staged_depth, shape.stages, "{name}: stages");
        assert_eq!(routing.strategy, shape.strategy, "{name}: strategy");
        // The budget is what the verdict is for, so nothing may decompose
        // past it. Read across the table rather than per row: the claim
        // is about the classifier, not about any one shape's depth.
        assert!(
            shape.strategy != Strategy::LegLocal || routing.staged_depth <= MAX_STAGED_DEPTH,
            "{name}: decomposed at {} stages, past a budget of {MAX_STAGED_DEPTH}",
            routing.staged_depth,
        );
    }
}

/// Named instances moving inside a core do not force replication.
///
/// L11 excludes non-fungible value from *staging*, because the supply
/// delta an escrow certificate attests counts amounts and cannot see
/// which id moved. A core is not staged: its participants agree by
/// unanimity rather than by taking each other's attested values, so
/// nothing inside one is exposed to that gap and the exclusion has no
/// business firing.
///
/// Minting an instance and filing it into an account is exactly that
/// shape — neither node is a leg, since a mint declares no reservation
/// and `deposit-nf` cannot carry the total mark while filing each id is
/// a loop — so the two sit on either side of a multi-shard core and the
/// route still decomposes.
///
/// The reachable-today consequence, worth stating: no catalogue pattern
/// can put a named instance across a *leg*, because no non-fungible
/// method is reservation-shaped or total. L11 guards a shape the
/// vocabulary cannot currently express, which is where a unit test
/// belongs and a catalogue case cannot go.
#[test]
fn named_instances_inside_a_core_still_decompose() {
    let world = world();
    let seat = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, minted)
    });
    let routing = sharded_routing(&world, &seat);

    assert!(
        routing.alternation_depth > 0,
        "the fixture has to cross, or the verdict below proves nothing",
    );
    assert!(
        routing.roles.iter().all(|slot| *slot == Role::Core),
        "neither end is a leg: {:?}",
        routing.roles,
    );
    assert_eq!(routing.strategy, Strategy::LegLocal);
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
            Address::from(book()),
            asks(),
            (5u128 << 64) | 7,
            encode_amount(10).to_vec(),
        )
        .unwrap();
    store
        .write(vault(book(), BASE), encode_amount(10).to_vec())
        .unwrap();

    let place = place_graph();
    let fill = fill_graph();
    let (results, final_store) = run_both(
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
    let placed_ask = EntryKey {
        owner: Address::from(book()),
        collection: asks(),
        order: (3u128 << 64) | u128::from(seq),
    };
    assert_eq!(
        place_receipt.delta.entries.get(&placed_ask),
        Some(&Some(encode_amount(50).to_vec()))
    );

    // The fill: budget 100 at price 3 buys 33 (cost 99), leaving change 1;
    // the price-5 ask is untouched. Partial fill rewrote the entry.
    // The quote vault is credited with what was spent: the change comes
    // off the payment before the rest of it goes in, so the movement is
    // the net and neither half is a number the body wrote down.
    assert_eq!(
        fill_receipt.delta.entries.get(&placed_ask),
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
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(book(), QUOTE))
            .unwrap()
            .debit,
        0
    );

    assert_eq!(amount_of(&final_store, vault(TAKER, BASE)), 33);
    assert_eq!(amount_of(&final_store, vault(TAKER, QUOTE)), 51);
    assert_eq!(amount_of(&final_store, vault(book(), BASE)), 27);
    assert_eq!(amount_of(&final_store, vault(book(), QUOTE)), 99);
    assert_eq!(amount_of(&final_store, vault(MAKER, BASE)), 10);
    let entries: BTreeMap<_, _> = final_store
        .collection_entries()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    assert_eq!(entries.get(&placed_ask), Some(&encode_amount(17).to_vec()));
    assert_eq!(
        entries.get(&EntryKey {
            order: (5u128 << 64) | 7,
            ..placed_ask
        }),
        Some(&encode_amount(10).to_vec())
    );
    Ok(())
}

/// The stdlib's own total mark, checked against the code that carries it.
///
/// `account_metadata` declares `deposit` total, and a claim a package
/// makes about itself is worth nothing unless something reads the
/// artifact back. This is that reading: the guest as it deploys, the
/// method as routing names it, and the same walk a publish-time check
/// would run.
///
/// `withdraw` rides along as the contrast, and the two facts behind the
/// mark come apart on it. Its export carries no error arm either, so it
/// is infallible by the same reading — and the checker still refuses it
/// the upgrade, which is the proof that the scan answers per method
/// rather than per package: the two live in one module and only one of
/// them passes.
#[test]
fn the_stdlib_deposit_earns_the_mark_it_claims() -> Result<()> {
    let artifact = build_guest("account")?;

    assert_eq!(
        account::metadata().methods["deposit"].totality,
        Totality::Total,
        "the fixture under test is the claim itself",
    );
    assert_eq!(
        check_method(&artifact, "deposit"),
        Ok(()),
        "the claim has to survive the artifact, or it is not a claim",
    );

    assert_eq!(
        account::metadata().methods["withdraw-nf"].totality,
        Totality::Infallible,
    );
    assert!(
        check_method(&artifact, "withdraw-nf").is_err(),
        "one module, two verdicts — the check is per method",
    );
    Ok(())
}

/// One kernel WIT, and no package holds a copy of it.
///
/// Drift used to be checkable only by comparing eight copies against the
/// canonical file; now there is nothing to compare, because a package
/// resolves `hyperscale:kernel` out of the SDK rather than vendoring it.
/// What is left to assert is that the vendoring did not come back — a
/// package with its own copy would compile against a world nothing holds
/// it to.
#[test]
fn no_guest_vendors_its_own_kernel_world() -> Result<()> {
    let canonical = std::fs::read(repo_root().join("crates/runtime/wit/kernel.wit"))?;
    let vendored = std::fs::read(repo_root().join("crates/sdk/wit/deps/kernel/kernel.wit"))?;
    assert_eq!(canonical, vendored, "the SDK's kernel.wit drifted");

    for guest in std::fs::read_dir(repo_root().join("guests"))? {
        let guest = guest?.path();
        assert!(
            !guest.join("wit/deps").exists(),
            "{} vendors its own dependencies",
            guest.display()
        );
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
    assert_eq!(
        results[4],
        TxResult::Trapped(AbortReason::Unreachable),
        "a false check traps"
    );

    // Exactly two bindings, each at the order its name hashes to, holding
    // the last value bound — the rebind overwrote in place.
    let names = collection_id(&TestHasher, registry_addr(), registry::NAMES, &[]);
    let order_of = |name: u64| {
        order_key(
            &TestHasher,
            registry_addr(),
            registry::NAMES,
            &[Value::U64(name).canonical_bytes()],
        )
    };
    let entries: BTreeMap<u128, Vec<u8>> = store
        .collection_entries()
        .filter(|(key, _)| (key.owner, key.collection) == (registry_addr().into(), names))
        .map(|(key, value)| (key.order, value.to_vec()))
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[&order_of(7)], 701u128.to_le_bytes().to_vec());
    assert_eq!(entries[&order_of(9)], 900u128.to_le_bytes().to_vec());

    // One crank from the bottom of the hash order clears everything —
    // two entries against a cap of eight.
    assert!(u32::try_from(entries.len()).unwrap() <= registry::DRAIN_CAP);
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

#[test]
fn custody_opens_for_the_holder_and_only_the_holder() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
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
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&seat, TxHash(Hash32([0x71; 32])))],
    );
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
        &engines,
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
        &engines,
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
        &engines,
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

    Ok(())
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
fn distinct_instances_of_one_badge_are_distinct_authorities() -> Result<()> {
    let (cache, mut instances) = world();
    let engines = Engines::build()?;
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
        &engines,
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
        &engines,
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
        &engines,
        &world,
        &store,
        &[
            (&operate_resource(ALICE, alices), TxHash(Hash32([0x84; 32]))),
            (&operate_resource(BOB, bobs), TxHash(Hash32([0x85; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert!(matches!(results[1], TxResult::Completed(_)));
    Ok(())
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
fn a_declared_threshold_admits_exactly_its_quorum() -> Result<()> {
    let (cache, mut instances) = world();
    let engines = Engines::build()?;
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
        &engines,
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
        &engines,
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
        &engines,
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
    Ok(())
}

#[test]
fn a_fungible_badge_is_custody_while_the_vault_is_funded() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
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
        &engines,
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
    Ok(())
}

#[test]
fn non_fungibles_mint_transfer_and_burn_end_to_end() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let store = MemoryStore::new();

    let resource = nf_resource();
    let holder_a = nf_holder(7);
    let holder_b = nf_holder(8);
    let a_holdings = holdings_collection(&TestHasher, holder_a, resource);
    let b_holdings = holdings_collection(&TestHasher, holder_b, resource);
    let holdings = [(holder_a.into(), a_holdings), (holder_b.into(), b_holdings)];
    let held = |store: &MemoryStore, collection: CollectionId| -> Vec<u64> {
        store
            .collection_entries()
            .filter(|(key, _)| key.collection == collection)
            .map(|(key, _)| u64::try_from(key.order).unwrap())
            .collect()
    };

    // Two mints in one manifest — distinct nodes, distinct fresh ids —
    // both deposited to A.
    let mint_to_a = graph(|b| {
        let first = nf::mint(b, nf_issuer())?;
        nf::deposit(b, holder_a, first)?;
        let second = nf::mint(b, nf_issuer())?;
        nf::deposit(b, holder_a, second)
    });
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&mint_to_a, TxHash(Hash32([0x61; 32])))],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));

    // Two instances held by A, each with its data cell under the issuer
    // holding the id it was minted with.
    let ids = held(&store, a_holdings);
    assert_eq!(ids.len(), 2, "two mints, two holdings");
    for &id in &ids {
        let data = instance_data_key(&TestHasher, nf_issuer(), resource, id);
        assert_eq!(
            store.cells().find(|(key, _)| *key == data).map(|(_, v)| v),
            Some(id.to_le_bytes().as_slice()),
            "the mint wrote the instance's data cell"
        );
    }
    assert_eq!(multiply_held_ids(&store, &holdings), Vec::<u128>::new());

    // Move the first id to B; a withdrawal of an id nobody holds traps;
    // burn the second id.
    let absent = (0..=u64::MAX).find(|id| !ids.contains(id)).unwrap();
    let transfer = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[ids[0]])?;
        nf::deposit(b, holder_b, moved)
    });
    let unheld = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[absent])?;
        nf::deposit(b, holder_b, moved)
    });
    let burn = graph(|b| {
        let moved = nf::withdraw(b, holder_a, resource, &[ids[1]])?;
        nf::burn(b, nf_issuer(), moved)
    });
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[
            (&transfer, TxHash(Hash32([0x63; 32]))),
            (&unheld, TxHash(Hash32([0x64; 32]))),
            (&burn, TxHash(Hash32([0x65; 32]))),
        ],
    );
    assert!(matches!(results[0], TxResult::Completed(_)));
    assert_eq!(
        results[1],
        // The kernel's own class, not a guest's assertion: taking an
        // instance is where the removal happens, so it is where the
        // refusal belongs.
        TxResult::Trapped(AbortReason::InstanceNotHeld),
        "moving an id you do not hold aborts"
    );
    assert!(matches!(results[2], TxResult::Completed(_)));

    // A holds nothing, B holds exactly the moved id, no id is anywhere
    // twice, and the burned instance's data cell survives unmoved.
    assert_eq!(held(&store, a_holdings), Vec::<u64>::new());
    assert_eq!(held(&store, b_holdings), vec![ids[0]]);
    assert_eq!(multiply_held_ids(&store, &holdings), Vec::<u128>::new());
    let burned = instance_data_key(&TestHasher, nf_issuer(), resource, ids[1]);
    assert!(
        store.cells().any(|(key, _)| key == burned),
        "burn consumes the edge and leaves the data where the mint put it"
    );
    Ok(())
}

/// A mint creates an instance's data cell; it never rewrites one.
///
/// The fresh id is derived from the manifest's identity and the minting
/// node's position, so two mints agreeing on one is not something a
/// sender can arrange — which leaves putting the cell where this mint's
/// own derivation lands as the only way to witness the requirement. What
/// answers is the declared precondition, judged by the shard holding the
/// leaf before any body runs.
#[test]
fn a_mint_onto_an_instance_already_there_is_refused() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;

    let mint = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        nf::deposit(b, nf_holder(7), minted)
    });

    let admitted = admit(&mint, ALICE, &world.0, &world.1, &TestHasher).unwrap();
    let id = fresh_id(&TestHasher, admitted.identity(), 0, 0, 0);
    let data = instance_data_key(&TestHasher, nf_issuer(), nf_resource(), id);

    let mut store = MemoryStore::new();
    store.write(data, id.to_le_bytes().to_vec()).unwrap();

    let (results, _) = run_both_signed(
        &engines,
        &world,
        &store,
        &[(&mint, TxHash(Hash32([0x66; 32])))],
        Some(ALICE),
    );
    assert_eq!(
        results,
        vec![TxResult::Refused(Outcome::PresenceUnmet {
            target: EffectTarget::Point(data),
            required: Presence::Absent,
        })],
        "an instance already there is a refusal, never an overwrite"
    );
    Ok(())
}

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
fn the_draw_settles_on_the_entrant_the_transactions_randomness_picks() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
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
    let draw = graph(|b| lottery_addr().draw(b));

    // The empty round first: nobody has entered, and the draw still
    // settles — recording what it drew and naming no winner.
    let (results, store) = run_both(
        &engines,
        &world,
        &store,
        &[(&draw, TxHash(Hash32([0x60; 32])))],
    );
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
        &engines,
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
    Ok(())
}

/// The share vault seeded so that neither direction divides evenly.
///
/// A thousand assets against seven hundred and seventy-seven shares. The
/// ratio is what makes the test worth running: every step truncates, and
/// which way it truncates is the whole of what the four entry points are
/// for.
fn shares_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(vault(shares_vault(), RES_X), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(supply_leaf(shares_vault()), encode_amount(777).to_vec())
        .unwrap();
    store
        .write(
            config_leaf(shares_vault()),
            shares_meta().config_bytes().unwrap(),
        )
        .unwrap();
    store.lock(config_leaf(shares_vault()));
    store
}

/// The vault's circulating-supply leaf.
fn supply_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, shares::SUPPLY, &[])
}

/// A deposit and a redemption of what it bought, on both runtimes, over a
/// ratio that truncates in both directions.
///
/// Here rather than in the guest's own crate because of what it computes.
/// Every step is a rounding decision over the widest arithmetic the
/// vocabulary has, and a subunit's disagreement between two engines is a
/// fork no test running one of them can see. The arithmetic is computed
/// here rather than read off the body, and `run_both` is what asserts the
/// two engines reached it.
///
/// The invariant underneath is that assets per share never falls: a
/// depositor who immediately redeems gets back less than they put in, and
/// the difference stayed with the pool rather than going anywhere.
#[test]
fn the_share_vault_rounds_toward_the_pool_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;

    // 100 assets into 1000 assets against 777 shares mints
    // floor(100 * 777 / 1000) = 77 shares, not 77.7.
    let deposit = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
        let units = shares_vault().deposit(b, funds)?;
        account::deposit(b, ALICE, units)
    });
    let (results, store) = run_both(
        &engines,
        &world,
        &shares_store(),
        &[(&deposit, TxHash(Hash32([0x40; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the deposit must complete: {:?}", results[0]);
    };
    assert_eq!(
        receipt.supply.minted(shares_unit().address()),
        77,
        "the shares are minted rather than moved, so supply says so"
    );

    // Redeeming all 77 against 1100 assets and 854 shares returns
    // floor(77 * 1100 / 854) = 99 assets, not 99.18 — so the depositor
    // is one subunit down and the pool is one subunit up.
    let redeem = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let units = account::withdraw(b, alice, shares_unit(), 77)?;
        let assets = shares_vault().redeem(b, units)?;
        account::deposit(b, ALICE, assets)
    });
    let (results, end) = run_both(
        &engines,
        &world,
        &store,
        &[(&redeem, TxHash(Hash32([0x41; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the redemption must complete: {:?}", results[0]);
    };
    assert_eq!(
        receipt.supply.burned(shares_unit().address()),
        77,
        "the shares are destroyed rather than parked"
    );

    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 999);
    assert_eq!(amount_of(&end, vault(shares_vault(), RES_X)), 1_001);
    assert_eq!(amount_of(&end, vault(ALICE, shares_unit())), 0);
    Ok(())
}
