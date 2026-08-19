//! The wrappers, held to the signatures they mirror.
//!
//! A wrapper is a hand-written claim about a method: its parameter kinds,
//! their order, and how many edges it produces. Every claim here is made
//! against the authored metadata and then admitted, so drift is a failing
//! test rather than a client that builds graphs the chain refuses. What
//! that leaves is a method nobody wrapped, which the coverage check at the
//! bottom is for.
//!
//! Only `account` and `staking` have committed guests. The rest are
//! exercised against their metadata alone, which is all a wrapper can
//! drift from.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{
    EvidenceRef, Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache,
    PackageHash, PackageMetadata, RoleSet, StoredRule, TestHasher, Value, admit, resource_address,
};
use hyperscale_vm_fixtures::{amm, book, lottery, nf, registry, splitter};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{Address, ComponentAddr, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const BASE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const QUOTE: ResourceAddr = ResourceAddr::new([0xE2; 31]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// One instance per package that has any, each configured as its
/// signatures read their configuration.
fn instance(package: &str, config: Vec<Value>) -> InstanceMeta {
    InstanceMeta {
        package: pkg(package),
        config,
        salt: Hash32([7; 32]),
    }
}

fn address(package: &str, config: Vec<Value>) -> ComponentAddr {
    instance(package, config).address(&TestHasher)
}

fn pool_config() -> Vec<Value> {
    vec![
        Value::Address(BASE.address()),
        Value::Address(OPERATOR.address()),
    ]
}

fn pair_config() -> Vec<Value> {
    vec![
        Value::Address(BASE.address()),
        Value::Address(QUOTE.address()),
    ]
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    for (name, metadata) in stdlib() {
        cache.publish_unchecked(pkg(name), metadata);
    }
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    for (name, config) in [
        ("staking", pool_config()),
        ("amm", pair_config()),
        ("book", pair_config()),
        ("nf", vec![]),
        ("nf", vec![Value::Address(BASE.address())]),
        ("registry", vec![]),
        ("splitter", vec![]),
        ("lottery", vec![]),
    ] {
        instances.create(&TestHasher, instance(name, config));
    }
    (cache, instances)
}

/// Every authored package, by the name its hash derives from.
fn stdlib() -> Vec<(&'static str, PackageMetadata)> {
    vec![
        ("account", account::metadata()),
        ("amm", amm::metadata()),
        ("book", book::metadata()),
        ("lottery", lottery::metadata()),
        ("nf", nf::metadata()),
        ("registry", registry::metadata()),
        ("splitter", splitter::metadata()),
        ("staking", staking::metadata()),
    ]
}

/// Build through `write` and admit the result, so a wrapper disagreeing
/// with its signature fails here rather than at a signer's node.
fn admits(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    write(&mut b).expect("every wrapper types against its own signature");
    let graph = b.build().expect("every output is consumed");
    admit(&graph, ALICE, &cache, &instances, &TestHasher).expect("a wrapped graph admits");
    graph
}

#[test]
fn the_account_wrappers_match_their_signatures() {
    let graph = admits(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, BASE, 100)?;
        account::deposit(b, BOB, funds)?;
        account::securify_uniform(
            b,
            alice,
            StoredRule::Require(BOB.address().into()),
            86_400_000,
        )?;
        account::propose(
            b,
            ALICE,
            RoleSet::uniform(StoredRule::Require(BOB.address().into())),
            86_400_000,
        )?;
        account::cancel(b, ALICE)?;
        account::confirm(b, ALICE)
    });
    assert_eq!(graph.nodes.len(), 7);
}

/// A rule literal is judged by decoding it as the vocabulary — the same
/// predicate admission runs — so the vacuous threshold, the one that
/// would hand the account to anyone, is refused at the call site that
/// writes it.
#[test]
fn a_degenerate_rule_is_refused_where_it_is_written() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let refused = account::securify_uniform(
        &mut b,
        alice,
        StoredRule::CountOf {
            count: 0,
            rules: vec![],
        },
        86_400_000,
    );
    assert!(matches!(
        refused,
        Err(TypedError::ParamKind {
            expected: "role-set",
            ..
        })
    ));
}

/// A chained sign-in composes and admits: the second authorize presents
/// the first's minted proof rather than the intent's signature.
#[test]
fn a_chained_sign_in_admits() {
    let graph = admits(|b| {
        let alice = account::authorize(b, ALICE)?;
        let bob = account::authorize_as(b, alice, BOB)?;
        let funds = account::withdraw(b, bob, BASE, 100)?;
        account::deposit(b, ALICE, funds)
    });
    assert_eq!(
        graph.nodes[1].evidence,
        BTreeSet::from([EvidenceRef::Node(0)])
    );
}

/// Misplaced evidence refuses at the call site, mirroring admission: a
/// proof to a method admitting anyone, a bare signature to a guarded
/// one, a minted proof asked of a method that mints nothing.
#[test]
fn misplaced_evidence_is_refused_at_the_call_site() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice, BASE, 100).unwrap();
    assert!(matches!(
        b.call_as(alice, BOB, "deposit", (funds,)),
        Err(TypedError::UnexpectedEvidence { .. })
    ));
    assert!(matches!(
        b.call(ALICE, "withdraw", (BASE, 100_u128)),
        Err(TypedError::SignatureForGuarded { .. })
    ));
    assert!(matches!(
        b.call_minting(ALICE, "withdraw", ()),
        Err(TypedError::UnmintingProof { .. })
    ));
}

#[test]
fn the_staking_wrappers_match_their_signatures() {
    let pool = staking::Staking::at(address("staking", pool_config()));
    let graph = admits(|b| {
        // One sign-in acts for the whole graph: the delegation round
        // trip and the operator surface both present Alice's proof.
        let alice = account::authorize(b, ALICE)?;

        // The delegation round trip: funds in, the pool's own units out
        // and into an account, then units back to the pool.
        let funds = account::withdraw(b, alice, BASE, 100)?;
        let units = pool.stake(b, funds)?;
        account::deposit(b, ALICE, units)?;
        let returned = account::withdraw(b, alice, staking_units(pool), 40)?;
        pool.unstake(b, returned)?;

        // The operator surface, which supplies no funds and produces none.
        pool.register_validator(b, alice, 7, vec![0xAA; 48], vec![0xBB; 96])?;
        pool.deactivate_validator(b, alice, 7)?;
        pool.unjail(b, alice, 7)?;
        pool.cast_param_vote(b, alice, 9_000, 30, 12)?;
        pool.clear_param_vote(b, alice)
    });
    assert_eq!(graph.nodes.len(), 11);
}

/// The resource a pool issues, which its `stake` output derives from the
/// pool's own address.
fn staking_units(pool: staking::Staking) -> ResourceAddr {
    resource_address(&TestHasher, Address::from(pool), &[])
}

#[test]
fn the_amm_wrapper_matches_its_signature() {
    let pool = amm::Amm::at(address("amm", pair_config()));
    admits(|b| {
        // The pool's output is typed by its second configured resource,
        // so what comes back is quote against a base input.
        let alice_proof = account::authorize(b, ALICE)?;
        let input = account::withdraw(b, alice_proof, BASE, 100)?;
        let proceeds = pool.swap(b, input, 1)?;
        account::deposit(b, ALICE, proceeds)
    });
}

#[test]
fn the_book_wrappers_match_their_signatures() {
    let book = book::Book::at(address("book", pair_config()));
    admits(|b| {
        let alice_proof = account::authorize(b, ALICE)?;
        let offered = account::withdraw(b, alice_proof, BASE, 100)?;
        book.place_ask(b, 10, offered)?;
        let bob_proof = account::authorize(b, BOB)?;
        let payment = account::withdraw(b, bob_proof, QUOTE, 50)?;
        let [bought, unspent] = book.fill_asks(b, 1, 20, payment)?;
        account::deposit(b, BOB, bought)?;
        account::deposit(b, BOB, unspent)
    });
}

#[test]
fn the_registry_wrappers_match_their_signatures() {
    let registry_addr = address("registry", vec![]);
    admits(|b| {
        registry::bind(b, registry_addr, 7, 700)?;
        registry::check(b, registry_addr, 7, 700)?;
        registry::drain(b, registry_addr, 0)
    });
}

#[test]
fn the_lottery_wrappers_match_their_signatures() {
    let lottery_addr = lottery::Lottery::at(address("lottery", vec![]));
    admits(|b| {
        let alice_proof = account::authorize(b, ALICE)?;
        let stake = account::withdraw(b, alice_proof, BASE, 100)?;
        // Alice pays and Bob is entered: the entrant is named by the
        // composer, not by whoever the funds came from.
        lottery_addr.enter(b, BOB, stake)?;
        lottery_addr.draw(b)
    });
}

#[test]
fn the_splitter_wrapper_matches_its_signature() {
    let splitter = address("splitter", vec![]);
    admits(|b| {
        let alice_proof = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice_proof, BASE, 100)?;
        let [taken, rest] = splitter::take(b, splitter, funds, 30)?;
        account::deposit(b, BOB, taken)?;
        account::deposit(b, ALICE, rest)
    });
}

#[test]
fn the_nf_wrappers_match_their_signatures() {
    let issuer = address("nf", vec![]);
    let resource = resource_address(&TestHasher, issuer.address(), &[]);
    admits(|b| {
        let minted = nf::mint(b, issuer)?;
        nf::deposit(b, issuer, minted)?;
        let moved = nf::withdraw(b, issuer, resource, &[7, 9])?;
        nf::burn(b, issuer, moved)
    });
}

#[test]
fn the_custody_wrappers_match_their_signatures() {
    let issuer = address("nf", vec![]);
    let resource = resource_address(&TestHasher, issuer.address(), &[]);
    let gated = address("nf", vec![Value::Address(BASE.address())]);
    admits(|b| {
        let minted = nf::mint(b, issuer)?;
        account::deposit_nf(b, ALICE, minted)?;
        let badge = account::present_badge(b, ALICE, BASE)?;
        nf::operate(b, gated, badge)?;
        let moved = account::withdraw_nf(b, badge, resource, &[7])?;
        account::deposit_nf(b, BOB, moved)
    });
}

#[test]
fn every_hand_written_method_has_a_wrapper() {
    // The one drift a call site cannot catch: a method added to a package
    // that no wrapper names. Only the hand-written packages can drift —
    // `#[blueprint]` emits a wrapper per method, so for a derived package
    // this list would be a second text saying what the first one already
    // says. Exhaustive over the three that are written by hand: adding a
    // method breaks this, which is the point.
    let wrapped: Vec<(&str, &[&str])> = vec![
        (
            "nf",
            &[
                "burn",
                "deposit",
                "mint",
                "operate",
                "operate-instance",
                "operate-quorum",
                "withdraw",
            ],
        ),
        ("registry", &["bind", "check", "drain"]),
        ("splitter", &["take"]),
    ];
    let hand_written: Vec<(&str, PackageMetadata)> = vec![
        ("nf", nf::metadata()),
        ("registry", registry::metadata()),
        ("splitter", splitter::metadata()),
    ];
    // Zipping would truncate silently, so the lists are held to one
    // length first: a package appended to one and not the other is the
    // same drift as a method, and would otherwise go unchecked.
    assert_eq!(hand_written.len(), wrapped.len());
    for ((package, metadata), (named, methods)) in hand_written.into_iter().zip(wrapped) {
        assert_eq!(package, named);
        let declared: BTreeSet<&str> = metadata.methods.keys().map(String::as_str).collect();
        let wrapped: BTreeSet<&str> = methods.iter().copied().collect();
        assert_eq!(declared, wrapped, "{package}");
    }
}
