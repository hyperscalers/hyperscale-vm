//! The corpus world: packages, instances, stores, graphs, and the
//! dual-lane manifest walk every corpus binary drives.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use hyperscale_vm_effects::vocabulary::{AUTH, CLAIMS, CONFIG};
use hyperscale_vm_effects::{
    AuthBase, EvidenceRef, Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestGraph,
    MetadataCache, PackageHash, PrefixShardResolver, Presented, ResourceKind, RoleTable, Routing,
    ShardId, ShardResolver, StarShape, StoredRule, TestHasher, Value, admit, child_key,
    classify as classify_star, collection_id, resource_address, route,
};
use hyperscale_vm_fixtures::{amm, book, lottery, nf, registry, shares};
use hyperscale_vm_harness::driver::{Lanes, test_hash};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_kernel::{
    BatchTx, EnvInputs, GuestBackend, GuestRunner, KernelSession, ManifestWalk, MemoryStore,
    OverlayStore, Receipt, RunResult,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    AbortReason, Address, CollectionId, ComponentAddr, Effect, EffectSet, EffectTarget, EntryKey,
    Mode, Outcome, PrincipalAddr, ResourceAddr, SubstateKey, TxHash,
};
use wasmtime::Result;
use wasmtime::error::{Context, ensure};

pub const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);

pub const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);

pub const MAKER: PrincipalAddr = PrincipalAddr::new([0x50; 31]);

pub const TAKER: PrincipalAddr = PrincipalAddr::new([0x60; 31]);

pub const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);

pub const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

pub const RES_Z: ResourceAddr = ResourceAddr::new([0xE5; 31]);

pub const BASE: ResourceAddr = ResourceAddr::new([0xE3; 31]);

pub const QUOTE: ResourceAddr = ResourceAddr::new([0xE4; 31]);

pub const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 5_000,
        randomness: [2; 32],
    }
}

pub fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

pub fn claims(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        CLAIMS,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

pub fn config_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
}

/// The book's asks collection, as the stdlib's declarations derive it.
pub fn asks() -> CollectionId {
    collection_id(&TestHasher, book(), book::ASKS, &[])
}

/// An account's stored-authority cell — what its sign-in reads.
pub fn auth(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, AUTH, &[])
}

/// One identity as all three roles, under the corpus delay.
pub fn uniform_base(identity: PrincipalAddr) -> AuthBase {
    AuthBase::new(
        DAY_MS,
        RoleTable::uniform(&StoredRule::Require(Presented::Identity(identity.into())))
            .expect("a rule within the vocabulary caps"),
    )
}

pub fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish_unchecked(pkg("account"), account::metadata());
    cache.publish_unchecked(pkg("amm"), amm::metadata());
    cache.publish_unchecked(pkg("book"), book::metadata());
    cache.publish_unchecked(pkg("registry"), registry::metadata());
    cache.publish_unchecked(pkg("nf"), nf::metadata());
    cache.publish_unchecked(pkg("lottery"), lottery::metadata());
    cache.publish_unchecked(pkg("shares"), shares::metadata());
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

pub fn pool_meta() -> InstanceMeta {
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
pub fn pool() -> amm::Amm {
    amm::Amm::at(pool_meta().address(&TestHasher))
}

/// The share vault, over the asset it prices shares against.
pub fn shares_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("shares"),
        config: vec![Value::Address(RES_X.address())],
        salt: Hash32([11; 32]),
    }
}

/// The share vault instance.
pub fn shares_vault() -> shares::Shares {
    shares::Shares::at(shares_meta().address(&TestHasher))
}

/// The share the vault issues against deposits.
pub fn shares_unit() -> ResourceAddr {
    resource_address(
        &TestHasher,
        Address::from(shares_vault()),
        ResourceKind::Fungible,
        &[],
    )
}

pub fn book_meta() -> InstanceMeta {
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
pub fn book() -> book::Book {
    book::Book::at(book_meta().address(&TestHasher))
}

pub fn registry_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("registry"),
        config: vec![],
        salt: Hash32([5; 32]),
    }
}

/// The name registry instance.
pub fn registry_addr() -> ComponentAddr {
    registry_meta().address(&TestHasher)
}

pub fn nf_issuer_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![],
        salt: Hash32([6; 32]),
    }
}

/// The non-fungible issuer instance.
pub fn nf_issuer() -> ComponentAddr {
    nf_issuer_meta().address(&TestHasher)
}

/// The resource the issuer mints: its own provenance, empty material.
pub fn nf_resource() -> ResourceAddr {
    resource_address(
        &TestHasher,
        nf_issuer().address(),
        ResourceKind::NonFungible,
        &[],
    )
}

pub fn nf_holder_meta(salt: u8) -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![],
        salt: Hash32([salt; 32]),
    }
}

/// A non-fungible holder instance.
pub fn nf_holder(salt: u8) -> ComponentAddr {
    nf_holder_meta(salt).address(&TestHasher)
}

/// A badge-gated instance: its one config slot names the badge resource
/// its operator surface opens for.
pub fn gated_meta(badge: Address, salt: u8) -> InstanceMeta {
    InstanceMeta {
        package: pkg("nf"),
        config: vec![Value::Address(badge)],
        salt: Hash32([salt; 32]),
    }
}

/// The instance gated on `badge`.
pub fn gated_by(badge: Address, salt: u8) -> ComponentAddr {
    gated_meta(badge, salt).address(&TestHasher)
}

pub fn lottery_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("lottery"),
        config: vec![],
        salt: Hash32([11; 32]),
    }
}

/// The lottery instance.
pub fn lottery_addr() -> lottery::Lottery {
    lottery::Lottery::at(lottery_meta().address(&TestHasher))
}

/// Which guest each published package runs.
///
/// `mirror` is the same account code under a second content address, so
/// the corpus can publish a package the authored stdlib table knows
/// nothing about and call it through the same walk.
pub const PACKAGES: &[(&str, &str)] = &[
    ("account", "account"),
    ("amm", "amm"),
    ("book", "book"),
    ("registry", "registry"),
    ("nf", "nf"),
    ("lottery", "lottery"),
    ("shares", "shares"),
    ("mirror", "account"),
];

/// The lanes, seeded once per binary: every guest compiled and decoded,
/// each under the package address a call names it at.
pub static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let mut lanes = Lanes::new();
    let mut built: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    for (package, guest) in PACKAGES {
        let bytes = built
            .entry(guest)
            .or_insert_with(|| build_guest(guest).expect("every corpus guest builds"));
        lanes.seed(pkg(package), bytes);
    }
    lanes
});

/// How one transaction ended on a lane.
#[derive(Debug, PartialEq, Eq)]
pub enum TxResult {
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
pub fn composer(graph: &ManifestGraph) -> PrincipalAddr {
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
pub struct Signing {
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
pub fn execute_manifest(
    backend: &dyn GuestBackend,
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
    let routing = route(&admitted, &PrefixShardResolver { bits: 0 });
    // The null resolver puts every effect on one shard, so the whole
    // declaration is the sole entry — taken as that rather than by naming
    // an id the resolver is free to choose.
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().clone();
    let entry = BatchTx::new(
        tx,
        declaration,
        EnvInputs {
            clock_ms,
            randomness: env().randomness,
        },
    )
    .with_calls(routing.calls);

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

    let run = ManifestWalk { backend }
        .run(&entry, session)
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

pub const fn point(key: SubstateKey, mode: Mode) -> Effect {
    Effect {
        target: EffectTarget::Point(key),
        mode,
    }
}

pub fn set(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    set
}

/// Where the sharded routing above puts an address — asked rather than
/// restated, so a change to the resolver cannot leave this behind.
pub fn shard_of(address: impl Into<Address>) -> ShardId {
    PrefixShardResolver { bits: 8 }.shard_of(address.into())
}

pub fn sharded_routing(
    world: &(MetadataCache, InstanceRegistry),
    graph: &ManifestGraph,
) -> Routing {
    let (cache, instances) = world;
    let admitted = admit(graph, composer(graph), cache, instances, &TestHasher).expect("admits");
    let first = route(&admitted, &PrefixShardResolver { bits: 8 });
    let second = route(&admitted, &PrefixShardResolver { bits: 8 });
    assert_eq!(first, second, "route is a function over the corpus");
    first
}

/// A stable rendering of everything a routing carries, digested so the
/// pin below is one line per pattern rather than pages of debug output.
pub fn routing_fingerprint(routing: &Routing) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (shard, set) in &routing.per_shard {
        let effects: Vec<_> = set.iter().collect();
        let _ = writeln!(out, "shard {shard:?}: {effects:?}");
    }
    let _ = writeln!(out, "calls: {:?}", routing.calls);
    let _ = writeln!(out, "frames: {:?}", routing.frames);
    let declaration = routing.declaration();
    let folded: Vec<_> = declaration.set.iter().collect();
    let _ = writeln!(out, "set: {folded:?}");
    let _ = writeln!(out, "ordered: {:?}", declaration.ordered);
    let digest = TestHasher.hash(b"routing-vector", &[out.as_bytes()]);
    digest.0.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// The star the classifier reads off a graph's admitted form.
pub fn star_of(world: &(MetadataCache, InstanceRegistry), graph: &ManifestGraph) -> StarShape {
    let (cache, instances) = world;
    let admitted = admit(graph, composer(graph), cache, instances, &TestHasher).expect("admits");
    classify_star(
        admitted.manifest(),
        cache,
        instances,
        &PrefixShardResolver { bits: 8 },
    )
}

pub fn run_both(
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
) -> (Vec<TxResult>, MemoryStore) {
    run_both_signed(world, store, transactions, None)
}

/// As [`run_both`], with one signature riding every graph — how a test
/// puts the wrong signer behind an authorization.
pub fn run_both_signed(
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
    signer: Option<PrincipalAddr>,
) -> (Vec<TxResult>, MemoryStore) {
    run_both_at(world, store, transactions, signer, env().clock_ms)
}

/// As [`run_both_signed`], at an explicit transaction clock — how the
/// recovery tests move weighted time between transactions.
pub fn run_both_at(
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
    signer: Option<PrincipalAddr>,
    clock_ms: u64,
) -> (Vec<TxResult>, MemoryStore) {
    let mut lanes = Vec::new();
    for backend in LANES.engine_backends() {
        let mut results = Vec::new();
        let mut threaded = store.clone();
        for (graph, tx) in transactions {
            let under = Signing {
                tx: *tx,
                signer: signer.unwrap_or_else(|| composer(graph)),
                clock_ms,
            };
            let (result, next) =
                execute_manifest(backend, world, threaded, graph, under).expect("driver");
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

/// Build against this world's metadata, so every call is typed by the
/// signature it names and every edge carries the resource that signature
/// declares — neither of which is written out below.
pub fn graph(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    graph_in(&world(), write)
}

/// As [`graph`], against a world a test extended: an instance whose
/// configuration names something only a run can produce — an instance id
/// — is registered by the test rather than by the shared fixture.
pub fn graph_in(
    world: &(MetadataCache, InstanceRegistry),
    write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> ManifestGraph {
    let mut b = TypedBuilder::new(&world.0, &world.1, &TestHasher);
    write(&mut b).expect("every call types against its signature");
    b.build().expect("every output is consumed")
}

pub fn transfer_graph() -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
        account::deposit(b, BOB, funds)
    })
}

/// The same transfer, signed in rather than signed per call: authorize
/// mints Alice's identity and the withdrawal presents that proof instead
/// of the intent's signature.
pub fn authorized_transfer_graph() -> ManifestGraph {
    graph(|b| {
        let proof = account::authorize(b, ALICE)?;
        let funds = b
            .call_as(proof, ALICE, "withdraw", (RES_X, 100u128))?
            .one()?;
        account::deposit(b, BOB, funds)
    })
}

/// The recovery delay every corpus cell stores: one day of weighted
/// time, against a test clock that starts at [`env`]'s 5000 ms.
pub const DAY_MS: u64 = 86_400_000;

pub fn propose_graph() -> ManifestGraph {
    graph(|b| {
        account::propose(
            b,
            ALICE,
            RoleTable::uniform(&StoredRule::Require(Presented::Identity(BOB.into())))
                .expect("a rule within the vocabulary caps"),
            DAY_MS,
        )
    })
}

pub fn swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

pub fn fill_graph() -> ManifestGraph {
    graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = account::withdraw(b, taker, QUOTE, 100)?;
        let [bought, refund] = book().fill_asks(b, 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    })
}
