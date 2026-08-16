//! Where a rest edge goes when the author did not say.
//!
//! Linearity is not negotiable — every output is consumed or the graph is
//! refused — so the only question a policy answers is who consumes what
//! nobody claimed. A builder with no policy still refuses, because routing
//! value somewhere the author never named is worse than making them say.

use hyperscale_vm_effects::stdlib::{account_metadata, splitter_metadata};
use hyperscale_vm_effects::{
    CallTarget, ComponentAddr, Constraint, GraphArg, Hash32, Hasher, InstanceMeta,
    InstanceRegistry, MetadataCache, PackageHash, PrincipalAddr, ResourceAddr, TestHasher, admit,
};
use hyperscale_vm_fixtures::calls::splitter;
use hyperscale_vm_manifest_builder::{BuildError, GraphBuilder, TypedBuilder, TypedError};
use hyperscale_vm_stdlib::calls::account;

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn splitter_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("splitter"),
        config: vec![],
        salt: Hash32([2; 32]),
    }
}

fn splitter() -> ComponentAddr {
    splitter_meta().address(&TestHasher)
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("splitter"), splitter_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, splitter_meta());
    (cache, instances)
}

#[test]
fn without_a_policy_a_rest_edge_is_still_a_refusal() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice, RES, 100).unwrap();
    let [taken, _rest] = splitter::take(&mut b, splitter(), funds, 30).unwrap();
    account::deposit(&mut b, BOB, taken).unwrap();
    assert_eq!(
        b.build(),
        Err(TypedError::Build(BuildError::DanglingOutput {
            producer: 2,
            output: 1
        }))
    );
}

#[test]
fn a_policy_deposits_what_nothing_claimed() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    b.rest_to(ALICE);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice, RES, 100).unwrap();
    let [taken, _rest] = splitter::take(&mut b, splitter(), funds, 30).unwrap();
    account::deposit(&mut b, BOB, taken).unwrap();
    let graph = b.build().unwrap();

    // The split's other half went home, as a fourth node nobody wrote.
    assert_eq!(graph.nodes.len(), 5);
    assert_eq!(graph.nodes[4].target, CallTarget::Principal(ALICE));
    assert_eq!(graph.nodes[4].method, "deposit");
    // And it went home typed: the splitter's signature typed the slot,
    // so the appended argument asserts the resource like any other.
    let GraphArg::Edge { edge, constraints } = &graph.nodes[4].args[0] else {
        panic!("a rest edge binds an edge");
    };
    assert_eq!(edge.producer, 2);
    assert_eq!(edge.output, 1);
    assert_eq!(constraints, &vec![Constraint::ResourceIs(RES.into())]);
    admit(&graph, ALICE, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn explicit_consumption_wins() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    b.rest_to(ALICE);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice, RES, 100).unwrap();
    let [taken, rest] = splitter::take(&mut b, splitter(), funds, 30).unwrap();
    account::deposit(&mut b, BOB, taken).unwrap();
    account::deposit(&mut b, BOB, rest).unwrap();
    let graph = b.build().unwrap();

    // Both halves were routed, so the policy saw nothing and appended
    // nothing — and the second half went where the author sent it.
    assert_eq!(graph.nodes.len(), 5);
    assert_eq!(graph.nodes[4].target, CallTarget::Principal(BOB));
    admit(&graph, ALICE, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn every_rest_edge_is_routed_not_just_the_first() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    b.rest_to(ALICE);
    let alice = account::authorize(&mut b, ALICE).unwrap();
    let funds = account::withdraw(&mut b, alice, RES, 100).unwrap();
    let [taken, _rest] = splitter::take(&mut b, splitter(), funds, 30).unwrap();
    let [_a, _b] = splitter::take(&mut b, splitter(), taken, 10).unwrap();
    let graph = b.build().unwrap();

    // Three halves nothing claimed, three deposits appended in node order.
    assert_eq!(graph.nodes.len(), 7);
    for node in &graph.nodes[4..] {
        assert_eq!(node.target, CallTarget::Principal(ALICE));
        assert_eq!(node.method, "deposit");
    }
    admit(&graph, ALICE, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn the_untyped_builder_routes_by_class_alone() {
    let (cache, instances) = world();
    // No metadata here, and none needed: a principal answers through the
    // protocol's account blueprint, so a deposit to one is well-formed on
    // the strength of the sink's class.
    let mut b = GraphBuilder::new();
    b.rest_to(ALICE);
    let [] = b.call_signed(ALICE, "authorize", ());
    let [_funds] = b.call_bearing(ALICE, "withdraw", (RES, 100u128), 0);
    let graph = b.build().unwrap();
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.nodes[2].target, CallTarget::Principal(ALICE));
    // Untyped means untyped: nothing typed the slot, so the appended
    // argument asserts nothing either.
    let GraphArg::Edge { constraints, .. } = &graph.nodes[2].args[0] else {
        panic!("a rest edge binds an edge");
    };
    assert!(constraints.is_empty());
    admit(&graph, ALICE, &cache, &instances, &TestHasher).unwrap();
}
