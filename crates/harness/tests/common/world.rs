//! The corpus world: packages, instances, stores, graphs, and the
//! dual-lane manifest walk every corpus binary drives.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use hyperscale_vm_effects::vocabulary::{AUTH, CONFIG};
use hyperscale_vm_effects::{
    AdmissionError, Admitted, Claim, EnvelopeTree, EvidenceRef, Hash32, Hasher, InstanceMeta,
    ManifestGraph, NodeShape, PACKAGE_SLOT_BASE, PackageHash, PrefixShardResolver, PresentedGrants,
    Records, Routing, RuleBytes, ShardId, ShardResolver, SlotId, StarShape, StoredRule, TestHasher,
    Value, admit_presenting, admit_tree, child_key, classify_roles, collection_id,
    holdings_collection, package_slot, route, route_tree, shape_of, star_at,
};
use hyperscale_vm_fixtures::{amm, book, lottery, nf, registry, security, shares};
use hyperscale_vm_harness::driver::{Lanes, declared_vault, run_lanes, test_hash, vault};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, EnvInputs, GuestBackend, GuestRunner, KernelSession, ManifestWalk,
    MemoryStore, OverlayStore, Receipt, RunResult,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError, graph_records};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account};
use hyperscale_vm_types::{
    AbortReason, Address, CollectionId, ComponentAddr, Effect, EffectSet, EffectTarget, EntryKey,
    Mode, Outcome, PrincipalAddr, ResourceAddr, SEAL_MATURITY_EPOCHS, SeedWindow, SubstateKey,
    TxHash, encode_amount,
};
use wasmtime::Result;
use wasmtime::error::{Context, Error as WasmtimeError, ensure};

pub const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);

pub const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);

pub const MAKER: PrincipalAddr = PrincipalAddr::new([0x50; 31]);

pub const TAKER: PrincipalAddr = PrincipalAddr::new([0x60; 31]);

/// Who keeps the register the restricted share classes are governed by,
/// and whose signature an approval-gated movement asks for.
pub const REGISTRAR: PrincipalAddr = PrincipalAddr::new([0x70; 31]);

pub const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);

pub const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

pub const RES_Z: ResourceAddr = ResourceAddr::new([0xE5; 31]);

pub const BASE: ResourceAddr = ResourceAddr::new([0xE3; 31]);

pub const QUOTE: ResourceAddr = ResourceAddr::new([0xE4; 31]);

/// The epoch every corpus transaction executes in, and therefore the
/// epoch a seal written by one records.
pub const EPOCH: u64 = 10;

/// The seed a round sealed in [`EPOCH`] matures into.
pub const MATURED_SEED: [u8; 32] = [0x5E; 32];

/// The environment the corpus lane runs under: a clock, a draw, and one
/// usable seed — the one a seal written now opens onto.
pub fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 5_000,
        epoch: EPOCH,
        seeds: SeedWindow::new(
            BTreeMap::from([(EPOCH + SEAL_MATURITY_EPOCHS, MATURED_SEED)]),
            Some(EPOCH + SEAL_MATURITY_EPOCHS),
        ),
    }
}

pub fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// The account alone: the world an account-seam test needs, with
/// nothing else published to get in the way of its refusals. A test
/// wanting more publishes beside it.
pub fn account_world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish(pkg("account"), account::metadata())
        .expect("the account publishes");
    chain.instances.serve_principals(pkg("account"));
    chain
}

/// The lanes an account-only test starts from; a test seeds its own
/// packages beside the account's.
pub fn account_lanes() -> Lanes {
    let mut lanes = Lanes::new();
    lanes.seed(pkg("account"), ACCOUNT_COMPONENT);
    lanes.seed_native(pkg("account"), account::invoke);
    lanes
}

/// One admitted, routed batch entry over `world`, under the null
/// resolver's single shard.
pub fn batch_entry(
    world: &Records,
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
    env: EnvInputs,
) -> Result<BatchTx> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, composer, identity, world, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    Ok(
        BatchTx::new(TxHash(identity.0), routing.declaration().clone(), env)
            .with_calls(routing.calls),
    )
}

/// The account's own quarantine vault for a resource — its second
/// declared slot, and a package's cell rather than the protocol's.
pub fn quarantine(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        package_slot(1),
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The flag saying this account sends the resource there instead.
pub fn refused(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        package_slot(0),
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

pub fn config_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
}

/// Seal `meta`'s instance: the committed configuration leaf its
/// instantiation writes, which the fence on every method reads.
pub fn seal(store: &mut MemoryStore, meta: &InstanceMeta) {
    store.write(
        config_leaf(meta.address(&TestHasher)),
        meta.leaf_bytes().expect("an instance's record encodes"),
    );
}

/// The book's asks collection, as the stdlib's declarations derive it.
pub fn asks() -> CollectionId {
    collection_id(&TestHasher, book(), book::ASKS, &[])
}

/// The finely quoted book's ladder.
pub fn fine_asks() -> CollectionId {
    collection_id(&TestHasher, fine_book(), book::ASKS, &[])
}

/// The rule governing an address — what its sign-in reads.
pub fn auth(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, AUTH, &[])
}

/// One of the account's own cells, by its offset in the package band:
/// 0 the rule that may replace the governing one, 1 the rule that may
/// enact a replacement early, 2 the replacement waiting, 3 the delay.
pub fn own_cell(owner: impl Into<Address>, offset: u16) -> SubstateKey {
    child_key(&TestHasher, owner, SlotId(PACKAGE_SLOT_BASE + offset), &[])
}

/// One identity, as the rule a cell stores.
pub fn stored_rule(identity: PrincipalAddr) -> RuleBytes {
    RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(identity)))
        .expect("a rule within the vocabulary caps")
}

pub fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("amm"), amm::metadata());
    chain
        .packages
        .publish_unchecked(pkg("book"), book::metadata());
    chain
        .packages
        .publish_unchecked(pkg("registry"), registry::metadata());
    chain.packages.publish_unchecked(pkg("nf"), nf::metadata());
    chain
        .packages
        .publish_unchecked(pkg("lottery"), lottery::metadata());
    chain
        .packages
        .publish_unchecked(pkg("shares"), shares::metadata());
    chain
        .packages
        .publish_unchecked(pkg("security"), security::metadata());
    chain.instances.serve_principals(pkg("account"));
    for meta in world_instances() {
        chain.instances.create(&TestHasher, meta);
    }
    chain
}

/// Every component the corpus world holds a record for.
pub fn world_instances() -> Vec<InstanceMeta> {
    vec![
        pool_meta(),
        book_meta(),
        fine_book_meta(),
        registry_meta(),
        nf_issuer_meta(),
        nf_holder_meta(7),
        nf_holder_meta(8),
        gated_meta(nf_resource().address(), 9),
        gated_meta(RES_X.address(), 10),
        lottery_meta(),
        shares_meta(),
        issuer_meta(),
        register_pool_meta(),
        approval_pool_meta(),
    ]
}

/// A store where every component the world names is actual.
///
/// What a network's genesis does for the components it is born running:
/// admission fences every call on a component's configuration leaf, so a
/// corpus that calls one starts from a store where the seal is there.
pub fn sealed_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    for meta in world_instances() {
        seal(&mut store, &meta);
    }
    store
}

pub fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        // The pair, then the fee: the guest reads the fee as an
        // evaluated slot, so it is configuration rather than a shape
        // spliced into the record. Thirty basis points, at the scale
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
    shares_vault().issued_unit(&TestHasher)
}

/// A stored rate's slot value: the scaled integer in the width a rate
/// has.
#[must_use]
pub fn scaled_rate(scaled: u128) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&scaled.to_le_bytes());
    Value::U256(bytes)
}

/// One quote subunit per tick, which is the step a book prices in unless
/// it was created finer.
pub const ONE_PER_TICK: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

pub fn book_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("book"),
        config: vec![
            Value::Address(BASE.address()),
            Value::Address(QUOTE.address()),
            scaled_rate(ONE_PER_TICK),
        ],
        salt: Hash32([3; 32]),
    }
}

/// The order book instance.
pub fn book() -> book::Book {
    book::Book::at(book_meta().address(&TestHasher))
}

/// A second book over the same pair, quoting in half a quote subunit.
///
/// The tick a book was created over is what its ladder means, so a
/// finer one is a different book rather than a setting on this one.
pub fn fine_book_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("book"),
        config: vec![
            Value::Address(BASE.address()),
            Value::Address(QUOTE.address()),
            scaled_rate(ONE_PER_TICK / 2),
        ],
        salt: Hash32([13; 32]),
    }
}

/// The finely quoted book instance.
pub fn fine_book() -> book::Book {
    book::Book::at(fine_book_meta().address(&TestHasher))
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

/// The resource the issuer mints: its own provenance, under its own
/// declared mark.
pub fn nf_resource() -> ResourceAddr {
    nf::badge(&TestHasher, nf_issuer().address())
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

/// The registrar's terms, which every derived resource address folds.
pub const fn terms() -> security::Terms {
    security::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// The share issuer: the package that writes the movement rules down.
pub fn issuer_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("security"),
        config: vec![Value::Address(REGISTRAR.address())],
        salt: Hash32([12; 32]),
    }
}

/// The issuer instance.
pub fn issuer() -> security::Security {
    security::Security::at(issuer_meta().address(&TestHasher))
}

/// The register entry: soulbound, one unit per admitted holder.
pub fn registered() -> ResourceAddr {
    issuer().issued_registered(&TestHasher, terms())
}

/// The register-mode share class, moved by whoever the register holds.
pub fn share() -> ResourceAddr {
    issuer().issued_share(&TestHasher, terms())
}

/// The approval-mode share class, moved in whatever transaction the
/// registrar signed.
pub fn approved() -> ResourceAddr {
    issuer().issued_approved(&TestHasher, terms())
}

/// A pool trading the register-mode class against a plain resource.
///
/// A venue rather than an account, which is the whole of what it is
/// here to show: the pool declares nothing about the register and holds
/// the share class anyway, so both of its own movements are judged
/// against an entry its author never read.
pub fn register_pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        config: vec![
            Value::Address(share().address()),
            Value::Address(RES_X.address()),
            Value::U128(30 * (1_000_000_000_000_000_000 / 10_000)),
        ],
        salt: Hash32([13; 32]),
    }
}

/// A trade of the register-mode class: Alice pays X and is paid in
/// shares.
pub fn register_swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 500)?;
        let out = register_pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

/// One registration for `holder`, as the register keeps them: an entry
/// of their own interval for the badge, at the registration's id.
///
/// Seeded rather than transacted for the venue, which has no method that
/// takes a badge — a pool declares nothing about the register and cannot
/// be made to. What the seam reads is the leaf, so the leaf is the fact.
pub fn register(store: &mut MemoryStore, holder: impl Into<Address>, id: u64) {
    let holder = holder.into();
    store.entry_write(
        holder,
        holdings_collection(&TestHasher, holder, registered()),
        u128::from(id),
        vec![1],
    );
}

/// The venue stocked and both parties admitted, or the venue left off
/// the register.
pub fn register_store(venue_admitted: bool) -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store.write(
        declared_vault(register_pool(), amm::RESERVES, RES_X),
        encode_amount(1_000).to_vec(),
    );
    store.write(
        declared_vault(register_pool(), amm::RESERVES, share()),
        encode_amount(1_000).to_vec(),
    );
    register(&mut store, ALICE, 1);
    if venue_admitted {
        register(&mut store, register_pool(), 2);
    }
    store
}

/// The register-mode pool.
pub fn register_pool() -> amm::Amm {
    amm::Amm::at(register_pool_meta().address(&TestHasher))
}

/// The same venue over the approval-mode class.
pub fn approval_pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        config: vec![
            Value::Address(approved().address()),
            Value::Address(RES_X.address()),
            Value::U128(30 * (1_000_000_000_000_000_000 / 10_000)),
        ],
        salt: Hash32([14; 32]),
    }
}

/// The approval-mode pool.
pub fn approval_pool() -> amm::Amm {
    amm::Amm::at(approval_pool_meta().address(&TestHasher))
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
    ("security", "security"),
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
    /// Boxed: a receipt carries every delta a transaction produced, so
    /// it dwarfs the refusal variants beside it and every one of them
    /// would pay for its size.
    Completed(Box<Receipt>),
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
    /// Admission never let it in, naming the node it refused at.
    ///
    /// Its own variant rather than a refusal outcome, because the two
    /// are not the same event: a refused transaction is included and
    /// records a receipt, and an inadmissible one is never included at
    /// all. A gate whose rule reads the node's own presented evidence is
    /// answered here — before anything routes, and before any leg could
    /// have committed on the strength of it.
    Inadmissible(u32),
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
    world: &Records,
    store: MemoryStore,
    graph: &ManifestGraph,
    under: Signing,
) -> Result<(TxResult, MemoryStore)> {
    let Signing {
        tx,
        signer,
        clock_ms,
    } = under;
    let admitted = match admit_here(graph, signer, world) {
        Ok(admitted) => admitted,
        // A verdict on what a node presented is admission's, and a lane
        // reports it rather than failing: nothing about it is a defect
        // in the driver, and it is exactly the refusal a wallet hears
        // before it signs.
        Err(AdmissionError::EvidenceUnsatisfied { node, .. }) => {
            return Ok((TxResult::Inadmissible(node), store));
        }
        Err(source) => return Err(WasmtimeError::new(source).context("admission")),
    };
    let routing = route(&admitted, &PrefixShardResolver { bits: 0 });
    // The null resolver puts every effect on one shard, so the whole
    // declaration is the sole entry — taken as that rather than by naming
    // an id the resolver is free to choose.
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().clone();
    let entry =
        BatchTx::new(tx, declaration, EnvInputs { clock_ms, ..env() }).with_calls(routing.calls);

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
        EnvInputs { clock_ms, ..env() },
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
                .finish(vec![], fuel)
                .expect("the oracle stands on every corpus receipt");
            Ok((
                TxResult::Completed(Box::new(receipt)),
                threaded.collapse_onto(before),
            ))
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

/// Admit `graph` over the records its own calls need.
///
/// A resource whose entries can stop a movement binds by its own
/// address, and the address is the hash of the rules — so admission
/// needs the preimage, and nothing on chain hands it over, because a
/// record is committed under its issuer. The composer finds them off
/// the graph and presents them, which is what a wallet does and what
/// every path into admission here does with it.
pub fn admit_here(
    graph: &ManifestGraph,
    signer: PrincipalAddr,
    world: &Records,
) -> Result<Admitted, AdmissionError> {
    let records = graph_records(graph, world, &TestHasher);
    let grants = PresentedGrants::from_presented(&TestHasher, &records);
    admit_presenting(graph, signer, world, &grants, &TestHasher)
}

pub fn sharded_routing(world: &Records, graph: &ManifestGraph) -> Routing {
    let admitted = admit_here(graph, composer(graph), world).expect("admits");
    let first = route(&admitted, &PrefixShardResolver { bits: 8 });
    let second = route(&admitted, &PrefixShardResolver { bits: 8 });
    assert_eq!(first, second, "route is a function over the corpus");
    first
}

/// A stable rendering of everything a routing carries — the pre-image the
/// fingerprint digests, and the witness a drift is discharged against: the
/// encoded role sets, calls, frames, and folded declaration in full.
pub fn routing_rendering(routing: &Routing) -> String {
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
    out
}

/// The rendering digested, so the pin is one line per pattern rather than
/// pages of debug output.
pub fn routing_fingerprint(routing: &Routing) -> String {
    use std::fmt::Write as _;
    let rendering = routing_rendering(routing);
    let digest = TestHasher.hash(b"routing-vector", &[rendering.as_bytes()]);
    digest.0.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// The star the classifier reads off a graph's admitted form.
pub fn star_of(world: &Records, graph: &ManifestGraph) -> StarShape {
    star_and_shape(world, graph).0
}

/// The star and the shape it was read off, plus the owners the
/// declaration reaches — everything [`StarShape::decomposes`] asks for.
pub fn star_and_shape(
    world: &Records,
    graph: &ManifestGraph,
) -> (StarShape, Vec<NodeShape>, Vec<Vec<Address>>) {
    let admitted = admit_here(graph, composer(graph), world).expect("admits");
    let roles = classify_roles(
        admitted.manifest(),
        world,
        &admitted.answered_at_admission(),
    )
    .expect("the corpus resolves every target");
    let shape = shape_of(admitted.manifest());
    let declared = admitted.declares();
    (
        star_at(&roles, &shape, &PrefixShardResolver { bits: 8 }),
        shape,
        declared,
    )
}

/// Whether the corpus shape `graph` decomposes.
pub fn decomposes(world: &Records, graph: &ManifestGraph) -> bool {
    let (star, shape, declared) = star_and_shape(world, graph);
    star.decomposes(&shape, &declared, &PrefixShardResolver { bits: 8 })
}

pub fn run_both(
    world: &Records,
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
) -> (Vec<TxResult>, MemoryStore) {
    run_both_signed(world, store, transactions, None)
}

/// Admit, route and execute one envelope tree on both lanes.
///
/// The tree's own path rather than the bare graph's: an envelope carries
/// its bindings and its records itself, so nothing is attached here, and
/// the nullifier of every bound subintent rides the batch entry that
/// makes it once-only.
///
/// # Errors
///
/// Admission's verdict on the composition, reached before any lane runs.
pub fn run_both_tree(
    world: &Records,
    store: &MemoryStore,
    tree: &EnvelopeTree,
    composer: PrincipalAddr,
) -> Result<(BatchOutcome, MemoryStore), AdmissionError> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, composer, identity, world, &TestHasher)?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    let entry = BatchTx::new(TxHash(identity.0), routing.declaration().clone(), env())
        .with_calls(routing.calls)
        .with_nullifiers(admitted.subintents);
    Ok(run_lanes(&LANES, store, &[entry]))
}

/// As [`run_both`], with one signature riding every graph — how a test
/// puts the wrong signer behind an authorization.
pub fn run_both_signed(
    world: &Records,
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
    signer: Option<PrincipalAddr>,
) -> (Vec<TxResult>, MemoryStore) {
    run_both_at(world, store, transactions, signer, env().clock_ms)
}

/// As [`run_both_signed`], at an explicit transaction clock — how the
/// recovery tests move weighted time between transactions.
pub fn run_both_at(
    world: &Records,
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
/// configuration names something only execution can produce — an instance id
/// — is registered by the test rather than by the shared fixture.
pub fn graph_in(
    world: &Records,
    write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> ManifestGraph {
    TypedBuilder::compose(world, &TestHasher, ALICE, write)
        .expect("every call types and every output is consumed")
}

/// As [`graph`], signed by somebody other than Alice — the registrar's
/// own compositions, where the signer is what the recall's entry names.
pub fn graph_signed(
    signer: PrincipalAddr,
    write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
) -> ManifestGraph {
    TypedBuilder::compose(&world(), &TestHasher, signer, write)
        .expect("every call types and every output is consumed")
}

pub fn transfer_graph() -> ManifestGraph {
    graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 100)?;
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
            .call_presenting(proof, ALICE, "withdraw", (RES_X, 100u128))?
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
            stored_rule(BOB),
            stored_rule(BOB),
            stored_rule(BOB),
            DAY_MS,
        )
    })
}

pub fn swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

pub fn fill_graph() -> ManifestGraph {
    graph(|b| {
        let taker = account::authorize(b, TAKER)?;
        let payment = b.presenting(taker, |b| account::withdraw(b, TAKER, QUOTE, 100))?;
        let [bought, refund] = book().fill_asks(b, 3, 5, payment)?;
        account::deposit(b, TAKER, bought)?;
        account::deposit(b, TAKER, refund)
    })
}
