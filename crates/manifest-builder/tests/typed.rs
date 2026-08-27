//! What holding the target's signature buys: the verdicts it moves to the
//! call site, and the edge types it derives so the author does not assert
//! them.

use hyperscale_vm_effects::{
    Constraint, EdgeRef, EvidenceRef, GraphArg, Hash32, Hasher, InstanceMeta, ManifestGraph,
    PackageHash, Records, TestHasher, Value, admit,
};
use hyperscale_vm_fixtures::payouts;
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);
/// A quarter, at the scale a bounded configuration number holds.
const QUARTER: u128 = 1_000_000_000_000_000_000 / 4;

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn splitter_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("payouts"),
        config: vec![
            Value::Address(RES.address()),
            Value::U128(QUARTER),
            Value::U128(QUARTER),
            Value::U128(2 * QUARTER),
        ],
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
    staking::Staking::at(pool()).issued_stake_unit(&TestHasher)
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("payouts"), payouts::metadata());
    chain
        .packages
        .publish_unchecked(pkg("staking"), staking::metadata());
    chain.instances.serve_principals(pkg("account"));
    chain.instances.create(&TestHasher, splitter_meta());
    chain.instances.create(&TestHasher, pool_meta());
    chain
}

/// The resource every edge argument of `node` asserts, in argument order —
/// `None` for an argument that is not an edge or asserts no resource.
fn asserted(graph: &ManifestGraph, node: usize) -> Vec<Option<ResourceAddr>> {
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
            GraphArg::Literal(_) | GraphArg::Socket(_) => None,
        })
        .collect()
}

#[test]
fn a_typed_edge_asserts_its_own_resource() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    // Nothing here says the withdrawal produces `RES`; `withdraw`'s
    // declared output does, and the deposit carries the assertion.
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    b.call(BOB, "deposit", (funds,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 2), vec![Some(RES)]);
    admit(&graph, ALICE, &chain, &TestHasher).unwrap();
}

/// An answer is asked of the declaration, where the method is named,
/// rather than of the receipt, where nothing would ever be filed.
#[test]
fn an_answer_from_a_method_that_answers_nothing_is_refused() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    let outputs = b.call(BOB, "deposit", (funds,)).unwrap();
    assert!(matches!(
        outputs.answering::<u128>(),
        Err(TypedError::AnswersNothing { method }) if method == "deposit"
    ));
}

#[test]
fn a_split_of_a_typed_edge_is_two_typed_edges() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    // `take` types both outputs by the resource of its input, so the type
    // travels the length of the chain from the one literal that fixed it.
    let [taken, rest] = b
        .call(splitter(), "in-lots", (funds, 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), Some(RES));
    assert_eq!(rest.resource(), Some(RES));
    b.call(BOB, "deposit", (taken,)).unwrap().none().unwrap();
    b.call(ALICE, "deposit", (rest.min(1),))
        .unwrap()
        .none()
        .unwrap();
    let graph = b.build().unwrap();
    // The derived assertion leads, and the author's bound follows it.
    assert_eq!(
        graph.nodes[4].args,
        vec![GraphArg::Edge {
            edge: EdgeRef {
                producer: 2,
                output: 1
            },
            constraints: vec![Constraint::ResourceIs(RES), Constraint::MinAmount(1)],
        }]
    );
    admit(&graph, ALICE, &chain, &TestHasher).unwrap();
}

#[test]
fn a_pool_types_its_units_by_itself() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    // The units derive from the pool's own address rather than from its
    // configuration or its input, so the target alone determines them.
    let units = b.call(pool(), "stake", (funds,)).unwrap().one().unwrap();
    assert_eq!(units.resource(), Some(unit()));
    b.call(ALICE, "deposit", (units,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 3), vec![Some(unit())]);
    admit(&graph, ALICE, &chain, &TestHasher).unwrap();
}

#[test]
fn an_edge_nothing_typed_stays_untyped() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    // The untyped path mints an edge with no declared type behind it.
    // `take` types its outputs by that edge, so neither output can be
    // typed either — and the layer leaves them alone rather than guessing.
    let sign_in = b.untyped().len();
    let [] = b.untyped().call_signed(ALICE, "authorize", ());
    let [funds] = b
        .untyped()
        .call_bearing(ALICE, "withdraw", (RES, 100u128), sign_in);
    let [taken, rest] = b
        .call(splitter(), "in-lots", (funds, 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), None);
    assert_eq!(rest.resource(), None);
    b.call(BOB, "deposit", (taken,)).unwrap().none().unwrap();
    b.call(ALICE, "deposit", (rest,)).unwrap().none().unwrap();
    let graph = b.build().unwrap();
    assert_eq!(asserted(&graph, 3), vec![None]);
    // Untyped is not unadmitted: admission evaluates the same output
    // expressions against the graph it can see whole.
    admit(&graph, ALICE, &chain, &TestHasher).unwrap();
}

#[test]
fn an_asserted_type_carries_through_the_untyped_path() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    // An author who types the edge by hand tells the layer as much as a
    // signature would, and the type propagates from the assertion.
    let sign_in = b.untyped().len();
    let [] = b.untyped().call_signed(ALICE, "authorize", ());
    let [funds] = b
        .untyped()
        .call_bearing(ALICE, "withdraw", (RES, 100u128), sign_in);
    let [taken, rest] = b
        .call(splitter(), "in-lots", (funds.resource_is(RES), 30u128))
        .unwrap()
        .into_array()
        .unwrap();
    assert_eq!(taken.resource(), Some(RES));
    assert_eq!(rest.resource(), Some(RES));
}

#[test]
#[should_panic(expected = "types this edge as a different resource")]
fn a_typed_edge_refuses_a_contradicting_assertion() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    let _ = funds.resource_is(ResourceAddr::new([0xE2; 31]));
}

#[test]
fn a_call_is_typed_against_the_signature_it_names() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);

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
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let one = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    let two = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap()
        .one()
        .unwrap();
    assert!(matches!(
        b.call(splitter(), "in-lots", (one, two)),
        Err(TypedError::EdgeForValueParam { param: 1, .. })
    ));
}

#[test]
fn a_refused_call_appends_nothing() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let funds = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
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
    assert_eq!(graph.nodes.len(), 3);
    admit(&graph, ALICE, &chain, &TestHasher).unwrap();
}

#[test]
fn a_target_or_method_that_does_not_resolve_is_refused() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
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
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    // Naming a slot the producer does not have takes stating an arity,
    // and the signature is what an arity is checked against.
    let alice = b.call_proving(ALICE, "authorize", ()).unwrap();
    let outputs = b
        .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))
        .unwrap();
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

/// The pool's owner badge, through the package's own derivation.
fn owner_badge() -> ResourceAddr {
    staking::Staking::at(pool()).issued_owner_badge(&TestHasher)
}

/// A scope's evidence reaches a gate no per-call spelling names.
///
/// The badge is presented once, for the span; the gated call inside it
/// is written bare and still carries the scope's proof — beside whatever
/// the builder proved for itself, because ambient evidence only adds.
#[test]
fn a_scope_presents_where_a_gate_wants_claims() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, OPERATOR);
    let presented = b
        .call_proving(OPERATOR, "present-badge", (owner_badge(),))
        .unwrap();
    b.presenting(presented, |b| {
        b.call(pool(), "deactivate-validator", (8u64,))?.none()
    })
    .unwrap();
    let graph = b.build().unwrap();

    let gated = graph.nodes.last().expect("the gated call is a node");
    assert_eq!(gated.method, "deactivate-validator");
    assert!(
        gated.evidence.contains(&EvidenceRef::Node(0)),
        "the scope's proof rides the gated call: {:?}",
        gated.evidence
    );
}

/// A call wanting no evidence composes identically inside a scope.
#[test]
fn a_scope_is_invisible_to_a_call_wanting_nothing() {
    let chain = world();
    let bare = TypedBuilder::compose(&chain, &TestHasher, ALICE, |b| {
        let alice = b.call_proving(ALICE, "authorize", ())?;
        let funds = b
            .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))?
            .one()?;
        b.call(BOB, "deposit", (funds,))?.none()
    })
    .unwrap();
    let scoped = TypedBuilder::compose(&chain, &TestHasher, ALICE, |b| {
        let alice = b.call_proving(ALICE, "authorize", ())?;
        b.presenting(alice, |b| {
            let funds = b
                .call_presenting(alice, ALICE, "withdraw", (RES, 100u128))?
                .one()?;
            b.call(BOB, "deposit", (funds,))?.none()
        })
    })
    .unwrap();
    assert_eq!(bare, scoped, "the scope changed a call that wanted nothing");
}

/// Nested scopes union: a call inside both draws from both.
#[test]
fn nested_scopes_present_together() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, OPERATOR);
    let signed_in = b.call_proving(OPERATOR, "authorize", ()).unwrap();
    let presented = b
        .call_proving(OPERATOR, "present-badge", (owner_badge(),))
        .unwrap();
    b.presenting(signed_in, |b| {
        b.presenting(presented, |b| {
            b.call(pool(), "deactivate-validator", (8u64,))?.none()
        })
    })
    .unwrap();
    let graph = b.build().unwrap();

    let gated = graph.nodes.last().expect("the gated call is a node");
    assert!(
        gated.evidence.contains(&EvidenceRef::Node(0))
            && gated.evidence.contains(&EvidenceRef::Node(1)),
        "both scopes' proofs ride the gated call: {:?}",
        gated.evidence
    );
}

/// Evidence a call names explicitly overrules the ambient reading.
#[test]
fn explicit_evidence_stands_alone_inside_a_scope() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, OPERATOR);
    let signed_in = b.call_proving(OPERATOR, "authorize", ()).unwrap();
    let presented = b
        .call_proving(OPERATOR, "present-badge", (owner_badge(),))
        .unwrap();
    b.presenting(signed_in, |b| {
        b.call_presenting(presented, pool(), "deactivate-validator", (8u64,))?
            .none()
    })
    .unwrap();
    let graph = b.build().unwrap();

    let gated = graph.nodes.last().expect("the gated call is a node");
    assert_eq!(
        gated.evidence,
        std::iter::once(EvidenceRef::Node(1)).collect(),
        "the per-call spelling is the whole of the evidence"
    );
}

/// A gate the signer cannot prove is answered by the scope that covers
/// it: the pool's seal gates on its configured founder, the signer is
/// somebody else, and the founder's sign-in rides the span.
#[test]
fn a_scope_covers_a_gate_the_signer_cannot_prove() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, BOB);
    let (seal, _) = b.seal_of(pool()).unwrap();
    let founder = b.call_proving(OPERATOR, "authorize", ()).unwrap();
    b.presenting(founder, |b| {
        let badge = b.call(pool(), &seal, ())?.one()?;
        account::deposit_nf(b, OPERATOR, badge)
    })
    .unwrap();
    let graph = b.build().unwrap();

    let sealed = &graph.nodes[1];
    assert_eq!(sealed.method, seal);
    assert!(
        sealed.evidence.contains(&EvidenceRef::Node(0)),
        "the founder's sign-in rides the seal: {:?}",
        sealed.evidence
    );
}

/// A gate read whole that nothing in scope covers refuses at the call,
/// naming the claim — before admission ever sees the graph.
#[test]
fn an_uncovered_gate_refuses_with_the_claim_named() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, BOB);
    let (seal, _) = b.seal_of(pool()).unwrap();
    let unrelated = b
        .call_proving(BOB, "present-badge", (owner_badge(),))
        .unwrap();
    let refused = b.presenting(unrelated, |b| b.call(pool(), &seal, ()).map(|_| ()));
    assert!(
        matches!(&refused, Err(TypedError::UncoveredGate { method, .. }) if *method == seal),
        "an uncovered gate names itself: {refused:?}"
    );
}
