//! What a holder can know before signing, and that it agrees with what
//! the chain derives afterwards.
//!
//! The report composes functions the chain already runs, so the test that
//! matters is that composing them changed nothing: every quantity here is
//! checked against the same call made directly.

use hyperscale_vm_effects::stdlib::{account_metadata, staking_metadata};
use hyperscale_vm_effects::{
    ComponentAddr, Constraint, Hash32, Hasher, InstanceMeta, InstanceRegistry, MetadataCache,
    PackageHash, PrefixShardResolver, PrincipalAddr, ResourceAddr, SchemeId, TestHasher, TextError,
    Value, admit, declared_work, footprint, route, signature_work,
};
use hyperscale_vm_manifest_builder::native::{account, staking};
use hyperscale_vm_manifest_builder::{
    Authority, EnvelopeBuilder, PreflightError, TypedBuilder, preflight, preflight_tree,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// A pool whose operator surface names a principal, and one whose names a
/// slot its configuration does not have.
fn pool_meta(operator: Option<PrincipalAddr>) -> InstanceMeta {
    let mut config = vec![Value::Address(RES_X.address())];
    config.extend(operator.map(|operator| Value::Address(operator.address())));
    InstanceMeta {
        package: pkg("staking"),
        config,
        salt: Hash32([2; 32]),
    }
}

fn pool(operator: Option<PrincipalAddr>) -> ComponentAddr {
    pool_meta(operator).address(&TestHasher)
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("staking"), staking_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, pool_meta(Some(OPERATOR)));
    instances.create(&TestHasher, pool_meta(None));
    (cache, instances)
}

const SHARDS: PrefixShardResolver = PrefixShardResolver { bits: 2 };

#[test]
fn a_report_is_what_the_chain_derives() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice_proof = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice_proof, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();

    let report = preflight(
        &graph,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        NETWORK,
    )
    .unwrap();

    // Nothing new is computed here, so everything must equal the direct
    // call it composes.
    let admitted = admit(&graph, ALICE, &cache, &instances, &TestHasher).unwrap();
    let routing = route(&admitted, &cache, &instances, &TestHasher, &SHARDS).unwrap();
    assert_eq!(report.identity(), admitted.identity());
    assert_eq!(report.manifest(), admitted.manifest());
    assert_eq!(report.routing, routing);
    assert_eq!(
        report.footprint(),
        routing
            .per_shard
            .values()
            .fold(0u64, |total, set| total + footprint(set)),
        "the reservation is taken once against every shard's declaration"
    );
    assert_eq!(
        report.declared_work(7_000, &[SchemeId::ED25519]),
        declared_work(report.footprint(), 7_000, signature_work(SchemeId::ED25519)),
    );
    assert!(
        report.declared_work(7_000, &[SchemeId::ED25519, SchemeId::ED25519])
            > report.declared_work(7_000, &[SchemeId::ED25519]),
        "a second signature is a second verification to pay for"
    );
    assert_eq!(report.shards().count(), routing.per_shard.len());
}

#[test]
fn a_withdrawal_names_its_own_signer_and_a_deposit_names_nobody() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice_proof = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice_proof, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(
        &graph,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        NETWORK,
    )
    .unwrap();

    // Spending is the sender's; being paid is nobody's to refuse, so a
    // transfer composes under one signature — presented once, at the
    // sign-in, and carried to the withdrawal as its proof.
    assert_eq!(report.authority[0].authority, Authority::Signature(ALICE));
    assert_eq!(report.authority[1].authority, Authority::Signature(ALICE));
    assert_eq!(report.authority[2].authority, Authority::Anyone);
    assert_eq!(report.signers(), std::iter::once(ALICE).collect());
    assert_eq!(report.unsatisfiable().count(), 0);
}

#[test]
fn a_configured_operator_is_the_signature_its_surface_names() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let operator = account::authorize(&mut b, OPERATOR).unwrap();
    staking::unjail(&mut b, operator, pool(Some(OPERATOR)), 42).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(
        &graph,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        NETWORK,
    )
    .unwrap();

    // A pool is owned by nobody, so its operator surface names the
    // principal its configuration carries rather than the pool.
    assert_eq!(
        report.authority[0].authority,
        Authority::Signature(OPERATOR)
    );
    assert_eq!(report.signers(), std::iter::once(OPERATOR).collect());
}

/// A method requiring an identity the instance does not configure is
/// unsatisfiable by construction, and admission says so from the
/// signature and the creation-fixed record alone.
#[test]
fn a_slot_naming_no_principal_is_refused() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let operator = account::authorize(&mut b, OPERATOR).unwrap();
    staking::unjail(&mut b, operator, pool(None), 42).unwrap();
    let graph = b.build().unwrap();
    assert!(matches!(
        preflight(
            &graph,
            ALICE,
            &cache,
            &instances,
            &TestHasher,
            &SHARDS,
            NETWORK
        ),
        Err(PreflightError::Admission(_))
    ));
}

#[test]
fn every_address_the_report_names_is_named_for_the_network() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice_proof = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice_proof, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(
        &graph,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        NETWORK,
    )
    .unwrap();

    for (address, text) in &report.named {
        assert_eq!(*text, address.to_text(NETWORK).unwrap());
        assert!(text.contains(NETWORK), "the word is in the text: {text}");
    }
    assert_eq!(
        report.text(ALICE),
        report.named.get(&ALICE.address()).map(String::as_str)
    );
    // A report on one network says nothing about another.
    let elsewhere = preflight(
        &graph,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        "testnet",
    )
    .unwrap();
    assert_ne!(elsewhere.named, report.named);
}

#[test]
fn a_network_word_the_encoding_refuses_fails_once() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice_proof = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice_proof, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    assert!(matches!(
        preflight(
            &graph,
            ALICE,
            &cache,
            &instances,
            &TestHasher,
            &SHARDS,
            "Main Net"
        ),
        Err(PreflightError::Network(TextError::InvalidCharacter(_)))
    ));
    assert!(matches!(
        preflight(&graph, ALICE, &cache, &instances, &TestHasher, &SHARDS, ""),
        Err(PreflightError::Network(TextError::IncompletePrefix))
    ));
}

#[test]
fn a_composition_names_every_signer_it_needs() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);

    let taken = root.declare(RES_Y, [Constraint::MinAmount(10)]);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, 100).unwrap();
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken).unwrap();

    let mut sub = env.subintent(BOB);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let bob_proof = account::authorize(&mut sub, BOB).unwrap();
    let funds = account::withdraw(&mut sub, bob_proof, RES_Y, 10).unwrap();
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken).unwrap();

    let [wants_y] = env
        .seal(root)
        .unwrap()
        .try_into()
        .expect("one declared parameter");
    let [wants_x] = env
        .seal(sub)
        .unwrap()
        .try_into()
        .expect("one declared parameter");
    env.bind(wants_y, paid_y);
    env.bind(wants_x, paid_x);
    let tree = env.build().unwrap();

    let report = preflight_tree(
        &tree,
        ALICE,
        &cache,
        &instances,
        &TestHasher,
        &SHARDS,
        NETWORK,
    )
    .unwrap();
    // Both withdrawals name their own account, and the subintent's signer
    // signs its declaration; here the two sets coincide.
    assert_eq!(report.signers(), [ALICE, BOB].into_iter().collect());
    assert_eq!(report.subintents.len(), 1);
    assert_eq!(report.subintents[0].signer, BOB);
    // The nullifier the composition would spend, named before signing.
    assert_eq!(report.identity(), tree.hash(&TestHasher));
}
