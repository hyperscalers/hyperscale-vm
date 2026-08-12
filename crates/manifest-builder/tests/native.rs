//! The wrappers, held to the signatures they mirror.
//!
//! A wrapper is a hand-written claim about a method: its parameter kinds,
//! their order, and how many edges it produces. Every claim here is made
//! against the authored metadata and then admitted, so drift is a failing
//! test rather than a client that builds graphs the chain refuses. What
//! that leaves is a method nobody wrapped, which the coverage check at the
//! bottom is for.
//!
//! Only `account` and `staking` have guests. The other three are exercised
//! against their metadata alone, which is all a wrapper can drift from.

use std::collections::BTreeSet;

use hyperscale_vm_effects::stdlib::{
    account_metadata, amm_metadata, book_metadata, splitter_metadata, staking_metadata,
};
use hyperscale_vm_effects::{
    ComponentAddr, Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache,
    PackageHash, PackageMetadata, PrincipalAddr, ResourceAddr, TestHasher, Value, admit,
    resource_address,
};
use hyperscale_vm_manifest_builder::native::{account, amm, book, splitter, staking};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};

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
        cache.publish(pkg(name), metadata);
    }
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    for (name, config) in [
        ("staking", pool_config()),
        ("amm", pair_config()),
        ("book", pair_config()),
        ("splitter", vec![]),
    ] {
        instances.create(&TestHasher, instance(name, config));
    }
    (cache, instances)
}

/// Every authored package, by the name its hash derives from.
fn stdlib() -> Vec<(&'static str, PackageMetadata)> {
    vec![
        ("account", account_metadata()),
        ("amm", amm_metadata()),
        ("book", book_metadata()),
        ("splitter", splitter_metadata()),
        ("staking", staking_metadata()),
    ]
}

/// Build through `write` and admit the result, so a wrapper disagreeing
/// with its signature fails here rather than at a signer's node.
fn admits(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    write(&mut b).expect("every wrapper types against its own signature");
    let graph = b.build().expect("every output is consumed");
    admit(&graph, &cache, &instances, &TestHasher).expect("a wrapped graph admits");
    graph
}

#[test]
fn the_account_wrappers_match_their_signatures() {
    let graph = admits(|b| {
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        account::deposit(b, BOB, funds)?;
        account::stamp_entropy(b, ALICE)
    });
    assert_eq!(graph.nodes.len(), 3);
}

#[test]
fn the_staking_wrappers_match_their_signatures() {
    let pool = address("staking", pool_config());
    let graph = admits(|b| {
        // The delegation round trip: funds in, the pool's own units out
        // and into an account, then units back to the pool.
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        let units = staking::stake(b, pool, funds)?;
        account::deposit(b, ALICE, units)?;
        let returned = account::withdraw(b, ALICE, staking_units(pool), 40)?;
        staking::unstake(b, pool, returned)?;

        // The operator surface, which supplies no funds and produces none.
        staking::register_validator(b, pool, 7, vec![0xAA; 48], vec![0xBB; 96])?;
        staking::deactivate_validator(b, pool, 7)?;
        staking::unjail(b, pool, 7)?;
        staking::cast_param_vote(b, pool, 9_000, 30, 12)?;
        staking::clear_param_vote(b, pool)
    });
    assert_eq!(graph.nodes.len(), 10);
}

/// The resource a pool issues, which its `stake` output derives from the
/// pool's own address.
fn staking_units(pool: ComponentAddr) -> ResourceAddr {
    resource_address(&TestHasher, pool, &[])
}

#[test]
fn the_amm_wrapper_matches_its_signature() {
    let pool = address("amm", pair_config());
    admits(|b| {
        // The pool's output is typed by its second configured resource,
        // so what comes back is quote against a base input.
        let input = account::withdraw(b, ALICE, BASE, 100)?;
        let proceeds = amm::swap(b, pool, input, 1)?;
        account::deposit(b, ALICE, proceeds)
    });
}

#[test]
fn the_book_wrappers_match_their_signatures() {
    let book = address("book", pair_config());
    admits(|b| {
        let offered = account::withdraw(b, ALICE, BASE, 100)?;
        book::place_ask(b, book, 10, offered)?;
        let payment = account::withdraw(b, BOB, QUOTE, 50)?;
        let [bought, unspent] = book::fill_asks(b, book, 1, 20, payment)?;
        account::deposit(b, BOB, bought)?;
        account::deposit(b, BOB, unspent)
    });
}

#[test]
fn the_splitter_wrapper_matches_its_signature() {
    let splitter = address("splitter", vec![]);
    admits(|b| {
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        let [taken, rest] = splitter::take(b, splitter, funds, 30)?;
        account::deposit(b, BOB, taken)?;
        account::deposit(b, ALICE, rest)
    });
}

#[test]
fn every_stdlib_method_has_a_wrapper() {
    // The one drift a call site cannot catch: a method added to a package
    // that no wrapper names. Exhaustive on purpose — adding a method
    // breaks this list, which is the point.
    let wrapped: Vec<(&str, &[&str])> = vec![
        ("account", &["deposit", "stamp-entropy", "withdraw"]),
        ("amm", &["swap"]),
        ("book", &["fill-asks", "place-ask"]),
        ("splitter", &["take"]),
        (
            "staking",
            &[
                "cast-param-vote",
                "clear-param-vote",
                "deactivate-validator",
                "register-validator",
                "stake",
                "unjail",
                "unstake",
            ],
        ),
    ];
    for ((package, metadata), (named, methods)) in stdlib().into_iter().zip(wrapped) {
        assert_eq!(package, named);
        let declared: BTreeSet<&str> = metadata.methods.keys().map(String::as_str).collect();
        let wrapped: BTreeSet<&str> = methods.iter().copied().collect();
        assert_eq!(declared, wrapped, "{package}");
    }
}
