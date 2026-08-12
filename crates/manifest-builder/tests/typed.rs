//! What holding the target's signature buys: the verdicts it moves to the
//! call site, and the edge types it derives so the author does not assert
//! them.

use hyperscale_vm_effects::stdlib::{account_metadata, splitter_metadata, staking_metadata};
use hyperscale_vm_effects::{
    ComponentAddr, Constraint, EdgeRef, GraphArg, Hash32, Hasher, InstanceMeta, InstanceRegistry,
    ManifestGraph, MetadataCache, PackageHash, PrincipalAddr, ResourceAddr, ResourceRef,
    TestHasher, Value, admit, resource_address,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
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

fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("staking"),
        config: vec![
            Value::Address(RES.address()),
            Value::Address(OPERATOR.address()),
        ],
        salt: Hash32([3; 32]),
    }
}

fn splitter() -> ComponentAddr {
    splitter_meta().address(&TestHasher)
}

fn pool() -> ComponentAddr {
    pool_meta().address(&TestHasher)
}

/// The resource the pool issues: derived from the pool's own address, not
/// from anything it was configured with.
fn unit() -> ResourceAddr {
    resource_address(&TestHasher, pool(), &[])
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("splitter"), splitter_metadata());
    cache.publish(pkg("staking"), staking_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, splitter_meta());
    instances.create(&TestHasher, pool_meta());
    (cache, instances)
}

/// The resource every edge argument of `node` asserts, in argument order —
/// `None` for an argument that is not an edge or asserts no resource.
fn asserted(graph: &ManifestGraph, node: usize) -> Vec<Option<ResourceRef>> {
    graph.nodes[node]
        .args
        .iter()
        .map(|arg| match arg {
            GraphArg::Edge { constraints, .. } => {
                constraints.iter().find_map(|constraint| match constraint {
                    Constraint::ResourceIs(resource) => Some(*resource),
                    Constraint::MinAmount(_) | Constraint::MaxAmount(_) => None,
                })
            }
            GraphArg::Literal(_) | GraphArg::Param(_) => None,
        })
        .collect()
}

#[test]
fn a_typed_edge_asserts_its_own_resource() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    // Nothing here says the withdrawal produces `RES`; `withdraw`'s
    // declared output does, and the deposit carries the assertion.
    let funds = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    b.call(BOB, "deposit", (funds,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 1), vec![Some(RES.into())]);
    admit(&graph, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn a_split_of_a_typed_edge_is_two_typed_edges() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    // `take` types both outputs by the resource of its input, so the type
    // travels the length of the chain from the one literal that fixed it.
    let [taken, rest] = b
        .call(splitter(), "take", (funds, 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), Some(RES.into()));
    assert_eq!(rest.resource(), Some(RES.into()));
    b.call(BOB, "deposit", (taken,)).unwrap().none().unwrap();
    b.call(ALICE, "deposit", (rest.min(1),))
        .unwrap()
        .none()
        .unwrap();
    let graph = b.build().unwrap();
    // The derived assertion leads, and the author's bound follows it.
    assert_eq!(
        graph.nodes[3].args,
        vec![GraphArg::Edge {
            edge: EdgeRef {
                producer: 1,
                output: 1
            },
            constraints: vec![Constraint::ResourceIs(RES.into()), Constraint::MinAmount(1)],
        }]
    );
    admit(&graph, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn a_pool_types_its_units_by_itself() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    // The units derive from the pool's own address rather than from its
    // configuration or its input, so the target alone determines them.
    let units = b.call(pool(), "stake", (funds,)).unwrap().one().unwrap();
    assert_eq!(units.resource(), Some(unit().into()));
    b.call(ALICE, "deposit", (units,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 2), vec![Some(unit().into())]);
    admit(&graph, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn an_edge_nothing_typed_stays_untyped() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    // The untyped path mints an edge with no declared type behind it.
    // `take` types its outputs by that edge, so neither output can be
    // typed either — and the layer leaves them alone rather than guessing.
    let [funds] = b.untyped().call(ALICE, "withdraw", (RES, 100u128));
    let [taken, rest] = b
        .call(splitter(), "take", (funds, 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), None);
    assert_eq!(rest.resource(), None);
    b.call(BOB, "deposit", (taken,)).unwrap().none().unwrap();
    b.call(ALICE, "deposit", (rest,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 2), vec![None]);
    // Untyped is not unadmitted: admission evaluates the same output
    // expressions against the graph it can see whole.
    admit(&graph, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn an_asserted_type_carries_through_the_untyped_path() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    // An author who types the edge by hand tells the layer as much as a
    // signature would, and the type propagates from the assertion.
    let [funds] = b.untyped().call(ALICE, "withdraw", (RES, 100u128));
    let [taken, rest] = b
        .call(splitter(), "take", (funds.resource_is(RES), 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), Some(RES.into()));
    assert_eq!(rest.resource(), Some(RES.into()));
}

#[test]
#[should_panic(expected = "types this edge as a different resource")]
fn a_typed_edge_refuses_a_contradicting_assertion() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    let _ = funds.resource_is(ResourceAddr::new([0xE2; 31]));
}

#[test]
fn a_call_is_typed_against_the_signature_it_names() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);

    // Four of admission's verdicts, reached one graph early.
    assert!(matches!(
        b.call(ALICE, "withdraw", (RES,)),
        Err(TypedError::ArityMismatch {
            expected: 2,
            found: 1,
            ..
        })
    ));
    assert!(matches!(
        b.call(ALICE, "withdraw", (RES, 100u64)),
        Err(TypedError::ParamKind {
            param: 1,
            expected: "u128",
            found: "u64",
            ..
        })
    ));
    assert!(matches!(
        b.call(ALICE, "deposit", (100u128,)),
        Err(TypedError::LiteralForBucketParam { param: 0, .. })
    ));
    let one = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    let two = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    assert!(matches!(
        b.call(splitter(), "take", (one, two)),
        Err(TypedError::EdgeForValueParam { param: 1, .. })
    ));
}

#[test]
fn a_refused_call_appends_nothing() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    let funds = b
        .call(ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    assert!(matches!(
        b.call(BOB, "deposit", (100u128,)),
        Err(TypedError::LiteralForBucketParam { .. })
    ));
    // The refusal judged its arguments before appending, so the builder
    // still describes exactly the graph its accepted calls built.
    b.call(BOB, "deposit", (funds,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(graph.nodes.len(), 2);
    admit(&graph, &cache, &instances, &TestHasher).unwrap();
}

#[test]
fn a_target_or_method_that_does_not_resolve_is_refused() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    assert!(matches!(
        b.call(ComponentAddr::new([0xAA; 31]), "take", (30u128,)),
        Err(TypedError::UnknownInstance(_))
    ));
    assert!(matches!(
        b.call(ALICE, "mint", (RES, 1u128)),
        Err(TypedError::UnknownMethod { .. })
    ));
}

#[test]
fn outputs_unpack_only_into_the_arity_the_method_declares() {
    let (cache, instances) = world();
    let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
    // Naming a slot the producer does not have takes stating an arity,
    // and the signature is what an arity is checked against.
    let outputs = b.call(ALICE, "withdraw", (RES, 100u128)).unwrap();
    assert_eq!(outputs.len(), 1);
    assert!(matches!(
        outputs.into_array::<2>(),
        Err(TypedError::OutputArity {
            declared: 1,
            claimed: 2,
            ..
        })
    ));
}
