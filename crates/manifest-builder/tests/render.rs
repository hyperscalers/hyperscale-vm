//! The projection, pinned by what it prints.
//!
//! These expectations are the surface syntax, so they are meant to be read
//! rather than regenerated: a diff here is a change to what a wallet shows
//! somebody before they sign.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{
    GraphArg, GraphNode, Hash32, Hasher, InstanceMeta, PackageHash, Records, TestHasher, Value,
};
use hyperscale_vm_fixtures::{amm, payouts};
use hyperscale_vm_manifest_builder::{GraphBuilder, Names, TypedBuilder, render};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr, ResourceAddr, TextError};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const USDC: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";
/// A quarter, at the scale a bounded configuration number holds.
const QUARTER: u128 = 1_000_000_000_000_000_000 / 4;

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

fn pool() -> amm::Amm {
    amm::Amm::at(instance("amm", pair()).address(&TestHasher))
}

fn splitter_config() -> Vec<Value> {
    vec![
        Value::Address(XRD.address()),
        Value::U128(QUARTER),
        Value::U128(QUARTER),
        Value::U128(2 * QUARTER),
    ]
}

fn splitter() -> ComponentAddr {
    instance("payouts", splitter_config()).address(&TestHasher)
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("amm"), amm::metadata());
    chain
        .packages
        .publish_unchecked(pkg("payouts"), payouts::metadata());
    chain.instances.serve_principals(pkg("account"));
    chain.instances.create(&TestHasher, instance("amm", pair()));
    chain
        .instances
        .create(&TestHasher, instance("payouts", splitter_config()));
    chain
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
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    let proceeds = pool().swap(&mut b, funds, 1).unwrap();
    account::deposit(&mut b, ALICE, proceeds).unwrap();
    let graph = b.build().unwrap();

    // The shape [08](08-manifest.md) promises, reached from a graph that
    // knows none of these words until the caller supplies them.
    assert_eq!(
        render(&graph, &chain, &TestHasher, NETWORK, &vocabulary()).unwrap(),
        "alice.authorize();\n\
         let xrd = alice.withdraw(@xrd, 100);\n\
         let usdc = pool.swap(xrd, 1);\n\
         alice.deposit(usdc);\n"
    );
}

#[test]
fn an_unnamed_address_renders_as_itself_and_types_its_binding() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();

    let text = render(&graph, &chain, &TestHasher, NETWORK, &Names::none()).unwrap();
    // Nothing is named, so every address is its own bech32m form and the
    // binding falls back to a positional name carrying its type.
    let alice = ALICE.address().to_text(NETWORK).unwrap();
    let bob = BOB.address().to_text(NETWORK).unwrap();
    let xrd = XRD.address().to_text(NETWORK).unwrap();
    assert_eq!(
        text,
        format!(
            "{alice}.authorize();\n\
             let v1: {xrd} = {alice}.withdraw(@{xrd}, 100);\n\
             {bob}.deposit(v1);\n"
        )
    );
}

#[test]
fn a_split_binds_both_halves_and_numbers_the_repeat() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    let [taken, rest] = payouts::Payouts::at(splitter())
        .in_lots(&mut b, funds, 30u128)
        .unwrap();
    account::deposit(&mut b, BOB, taken.min(1)).unwrap();
    account::deposit(&mut b, ALICE, rest).unwrap();
    let graph = b.build().unwrap();

    // Three edges carry the same resource, so the name it was given is
    // taken three times and the later two say which they are. The bound
    // the author asserted rides its own use site.
    assert_eq!(
        render(&graph, &chain, &TestHasher, NETWORK, &vocabulary()).unwrap(),
        "alice.authorize();\n\
         let xrd = alice.withdraw(@xrd, 100);\n\
         let xrd2, xrd3 = splitter.in-lots(xrd, 30);\n\
         bob.deposit(xrd2{>= 1});\n\
         alice.deposit(xrd3);\n"
    );
}

#[test]
fn a_graph_renders_without_any_metadata_at_all() {
    let chain = world();
    let mut b = GraphBuilder::new();
    let [] = b.call_signed(ALICE, "authorize", ());
    let [funds] = b.call_bearing(ALICE, "withdraw", (XRD, 100u128), 0);
    let [] = b.call(BOB, "deposit", (funds.resource_is(XRD),));
    let graph = b.build().unwrap();

    // An empty world: no target resolves, so no output type is evaluated
    // and the arity is whatever the consumers named. Targets, methods and
    // positional arguments still read, and the author's own assertion is
    // the only thing left saying what the edge carries.
    let text = render(&graph, &Records::new(), &TestHasher, NETWORK, &vocabulary()).unwrap();
    assert_eq!(
        text,
        "alice.authorize();\n\
         let v1 = alice.withdraw(@xrd, 100);\n\
         bob.deposit(v1{is xrd});\n"
    );
    // The same graph against the real world types the binding instead,
    // and the assertion stops being worth printing twice.
    assert_eq!(
        render(&graph, &chain, &TestHasher, NETWORK, &vocabulary()).unwrap(),
        "alice.authorize();\n\
         let xrd = alice.withdraw(@xrd, 100);\n\
         bob.deposit(xrd);\n"
    );
}

#[test]
fn a_socket_renders_as_the_opening_it_is() {
    let chain = world();
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (XRD, 100u128));
    let _ = b.export(funds);
    let mut graph = b.build().unwrap();
    // The socket reference arrives the way one reaches a renderer: in a
    // declaration composed elsewhere, not from a token this graph minted.
    graph.nodes.push(GraphNode {
        target: ALICE.into(),
        method: "deposit".into(),
        args: vec![GraphArg::Socket(0)],
        evidence: BTreeSet::new(),
    });

    let text = render(&graph, &chain, &TestHasher, NETWORK, &vocabulary()).unwrap();
    // The exported edge has no consumer in this graph, so nothing names
    // its binding; the socket the composition will fill is `$0`.
    assert!(text.ends_with("alice.deposit($0);\n"), "{text}");
}

#[test]
fn a_network_word_the_encoding_refuses_fails_here_too() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, XRD, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    assert!(matches!(
        render(&graph, &chain, &TestHasher, "Main Net", &Names::none()),
        Err(TextError::InvalidCharacter(_))
    ));
}
