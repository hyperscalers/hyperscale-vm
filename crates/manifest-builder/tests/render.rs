//! The projection, pinned by what it prints.
//!
//! These expectations are the surface syntax, so they are meant to be read
//! rather than regenerated: a diff here is a change to what a wallet shows
//! somebody before they sign.

use hyperscale_vm_effects::stdlib::{account_metadata, amm_metadata, splitter_metadata};
use hyperscale_vm_effects::{
    ComponentAddr, Hash32, Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash,
    PrincipalAddr, ResourceAddr, TestHasher, TextError, Value,
};
use hyperscale_vm_manifest_builder::native::{account, amm, splitter};
use hyperscale_vm_manifest_builder::{GraphBuilder, Names, Param, TypedBuilder, render};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const USDC: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn instance(package: &str, config: Vec<Value>) -> InstanceMeta {
    InstanceMeta {
        package: pkg(package),
        config,
        salt: Hash32([2; 32]),
    }
}

fn pair() -> Vec<Value> {
    vec![
        Value::Address(XRD.address()),
        Value::Address(USDC.address()),
    ]
}

fn pool() -> ComponentAddr {
    instance("amm", pair()).address(&TestHasher)
}

fn splitter() -> ComponentAddr {
    instance("splitter", vec![]).address(&TestHasher)
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("splitter"), splitter_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, instance("amm", pair()));
    instances.create(&TestHasher, instance("splitter", vec![]));
    (cache, instances)
}

/// What a wallet knows the addresses by.
fn vocabulary() -> Names {
    Names::none()
        .with(ALICE, "alice")
        .with(BOB, "bob")
        .with(pool(), "pool")
        .with(splitter(), "splitter")
        .with(XRD, "xrd")
        .with(USDC, "usdc")
}

#[test]
fn a_swap_reads_as_the_surface_syntax_names_it() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    let proceeds = amm::swap(&mut b, pool(), funds, 1).unwrap();
    account::deposit(&mut b, ALICE, proceeds).unwrap();
    let graph = b.build().unwrap();

    // The shape [08](08-manifest.md) promises, reached from a graph that
    // knows none of these words until the caller supplies them.
    assert_eq!(
        render(
            &graph,
            &cache,
            &instances,
            &TestHasher,
            NETWORK,
            &vocabulary()
        )
        .unwrap(),
        "let xrd = alice.withdraw(@xrd, 100);\n\
         let usdc = pool.swap(xrd, 1);\n\
         alice.deposit(usdc);\n"
    );
}

#[test]
fn an_unnamed_address_renders_as_itself_and_types_its_binding() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();

    let text = render(
        &graph,
        &cache,
        &instances,
        &TestHasher,
        NETWORK,
        &Names::none(),
    )
    .unwrap();
    // Nothing is named, so every address is its own bech32m form and the
    // binding falls back to a positional name carrying its type.
    let alice = ALICE.address().to_text(NETWORK).unwrap();
    let bob = BOB.address().to_text(NETWORK).unwrap();
    let xrd = XRD.address().to_text(NETWORK).unwrap();
    assert_eq!(
        text,
        format!(
            "let v1: {xrd} = {alice}.withdraw(@{xrd}, 100);\n\
             {bob}.deposit(v1);\n"
        )
    );
}

#[test]
fn a_split_binds_both_halves_and_numbers_the_repeat() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    let [taken, rest] = splitter::take(&mut b, splitter(), funds, 30).unwrap();
    account::deposit(&mut b, BOB, taken.min(1)).unwrap();
    account::deposit(&mut b, ALICE, rest).unwrap();
    let graph = b.build().unwrap();

    // Three edges carry the same resource, so the name it was given is
    // taken three times and the later two say which they are. The bound
    // the author asserted rides its own use site.
    assert_eq!(
        render(
            &graph,
            &cache,
            &instances,
            &TestHasher,
            NETWORK,
            &vocabulary()
        )
        .unwrap(),
        "let xrd = alice.withdraw(@xrd, 100);\n\
         let xrd2, xrd3 = splitter.take(xrd, 30);\n\
         bob.deposit(xrd2{>= 1});\n\
         alice.deposit(xrd3);\n"
    );
}

#[test]
fn a_graph_renders_without_any_metadata_at_all() {
    let (cache, instances) = world();
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (XRD, 100u128));
    let [] = b.call(BOB, "deposit", (funds.resource_is(XRD),));
    let graph = b.build().unwrap();

    // An empty world: no target resolves, so no output type is evaluated
    // and the arity is whatever the consumers named. Targets, methods and
    // positional arguments still read, and the author's own assertion is
    // the only thing left saying what the edge carries.
    let text = render(
        &graph,
        &MetadataCache::new(),
        &InstanceRegistry::new(),
        &TestHasher,
        NETWORK,
        &vocabulary(),
    )
    .unwrap();
    assert_eq!(
        text,
        "let v1 = alice.withdraw(@xrd, 100);\n\
         bob.deposit(v1{is xrd});\n"
    );
    // The same graph against the real world types the binding instead,
    // and the assertion stops being worth printing twice.
    assert_eq!(
        render(
            &graph,
            &cache,
            &instances,
            &TestHasher,
            NETWORK,
            &vocabulary()
        )
        .unwrap(),
        "let xrd = alice.withdraw(@xrd, 100);\n\
         bob.deposit(xrd);\n"
    );
}

#[test]
fn a_yield_parameter_renders_as_the_hole_it_is() {
    let (cache, instances) = world();
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (XRD, 100u128));
    let _ = b.export(funds);
    let [] = b.call(ALICE, "deposit", (Param(0),));
    let graph = b.build().unwrap();

    let text = render(
        &graph,
        &cache,
        &instances,
        &TestHasher,
        NETWORK,
        &vocabulary(),
    )
    .unwrap();
    // The exported edge has no consumer in this graph, so nothing names
    // its binding; the hole the composition will fill is `$0`.
    assert!(text.ends_with("alice.deposit($0);\n"), "{text}");
}

#[test]
fn a_network_word_the_encoding_refuses_fails_here_too() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    assert!(matches!(
        render(
            &graph,
            &cache,
            &instances,
            &TestHasher,
            "Main Net",
            &Names::none()
        ),
        Err(TextError::InvalidCharacter(_))
    ));
}
