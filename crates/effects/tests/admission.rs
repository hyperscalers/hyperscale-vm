//! Admission end to end: a well-formed graph lowers to the routing view
//! and routes; every malformed-graph mutation of it rejects — dangling
//! edge, double consumption, cycle shape, type mismatch, constraint
//! contradictions — with a deterministic verdict.

mod common;

use std::collections::BTreeSet;

use common::{ALICE, BOB, RES_X, payouts, pkg, resolver, shard_of, vault, world};
use hyperscale_vm_effects::vocabulary::{AUTH, CONFIG, VAULT};
use hyperscale_vm_effects::{
    AbiParam, AdmissionError, Clause, Constraint, EdgeRef, EvalError, EvidenceRef, Expr, GraphArg,
    GraphNode, Hash32, InstanceMeta, JudgedLeaf, MAX_VALUE_DEPTH, ManifestGraph, MethodSignature,
    ModeExpr, PackageMetadata, ParamType, Presented, Records, ResourceKind, Rule, RuleExpr,
    RuleLeaf, SlotRef, TargetExpr, TestHasher, Totality, Value, admit, child_key, fresh_id,
    holdings_entry, route,
};
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Effect, EffectTarget, Mode, Presence, ResourceAddr,
};
use proptest::collection::vec as prop_vec;
use proptest::prelude::{any, proptest};

/// A quarter, at the scale a bounded configuration number holds.
const QUARTER: u128 = 1_000_000_000_000_000_000 / 4;

fn splitter_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("payouts"),
        config: vec![
            Value::Address(RES_X.address()),
            Value::U128(QUARTER),
            Value::U128(QUARTER),
            Value::U128(2 * QUARTER),
        ],
        salt: Hash32([1; 32]),
    }
}

/// The splitter instance, at the address its record derives.
fn splitter() -> ComponentAddr {
    splitter_meta().address(&TestHasher)
}

/// A package whose one method denominates its bucket by a parameter bound
/// *after* it.
///
/// Authored here rather than in the fixtures, because no guest writes
/// this: what it exists to pin is when a denomination is evaluated, and
/// a shape the corpus happens not to contain is exactly the shape a hand
/// written metadata section could carry.
fn sorter_metadata() -> PackageMetadata {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "sort".into(),
        MethodSignature {
            totality: Totality::Infallible,
            params: vec![ParamType::Bucket, ParamType::Address],
            abi: vec![AbiParam::Bucket(0), AbiParam::Derived(Expr::Arg(1))],
            denominations: vec![Some(Expr::Arg(1)), None],
            ..MethodSignature::default()
        },
    );
    package
}

fn sorter_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("sorter"),
        config: vec![],
        salt: Hash32([9; 32]),
    }
}

fn sorter() -> ComponentAddr {
    sorter_meta().address(&TestHasher)
}

fn setup() -> Records {
    let mut chain = world();
    chain
        .packages
        .publish_unchecked(pkg("payouts"), payouts::metadata());
    chain.instances.create(&TestHasher, splitter_meta());
    chain
}

/// Sign in, withdraw 100, split off 30, deposit the taken part to Bob
/// and the rest back to Alice — the rest-edge shape, fully consumed.
fn valid_graph() -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE.into(),
                method: "authorize".into(),
                args: vec![],
                evidence: [EvidenceRef::IntentSignature].into(),
            },
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X.address())),
                    GraphArg::Literal(Value::U128(100)),
                ],
                evidence: [EvidenceRef::Node(0)].into(),
            },
            GraphNode {
                target: splitter().into(),
                method: "in-lots".into(),
                args: vec![
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 1,
                            output: 0,
                        },
                        constraints: vec![Constraint::ResourceIs(RES_X)],
                    },
                    GraphArg::Literal(Value::U128(30)),
                ],
                evidence: BTreeSet::new(),
            },
            GraphNode {
                target: BOB.into(),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 2,
                        output: 0,
                    },
                    constraints: vec![Constraint::MinAmount(30), Constraint::MaxAmount(30)],
                }],
                evidence: BTreeSet::new(),
            },
            GraphNode {
                target: ALICE.into(),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 2,
                        output: 1,
                    },
                    constraints: vec![],
                }],
                evidence: BTreeSet::new(),
            },
        ],
    }
}

#[test]
fn a_well_formed_graph_lowers_and_routes() {
    let chain = setup();
    let admitted = admit(&valid_graph(), ALICE, &chain, &TestHasher).expect("admits");

    // The lowered edges carry their static resource types.
    let routing = route(&admitted, &resolver());
    let alice_set = &routing.per_shard[&shard_of(ALICE)];
    assert!(alice_set.contains(&Effect {
        target: EffectTarget::Point(vault(ALICE, RES_X)),
        mode: Mode::Reserve { amount: 100 },
    }));
    // The credits either side: a deposit only pays in, and the
    // declaration carries that rather than answering for a debit it
    // could not make.
    assert!(alice_set.contains(&Effect {
        target: EffectTarget::Point(vault(ALICE, RES_X)),
        mode: Mode::Credit,
    }));
    let bob_set = &routing.per_shard[&shard_of(BOB)];
    assert!(bob_set.contains(&Effect {
        target: EffectTarget::Point(vault(BOB, RES_X)),
        mode: Mode::Credit,
    }));
}

#[test]
fn constraint_changes_reach_lowering_and_the_fresh_id_root() {
    let chain = setup();
    let mut loosened = valid_graph();
    let GraphArg::Edge { constraints, .. } = &mut loosened.nodes[3].args[0] else {
        panic!("edge arg");
    };
    constraints[0] = Constraint::MinAmount(29);

    let strict = admit(&valid_graph(), ALICE, &chain, &TestHasher).expect("admits");
    let loose = admit(&loosened, ALICE, &chain, &TestHasher).expect("admits");
    // A bound is execution-relevant, so lowering carries it: the two
    // manifests differ where the constraint does. The identity differs
    // too — it is the signed graph's hash, so two distinct signed
    // transactions never share a fresh-ID root.
    assert_ne!(strict.manifest(), loose.manifest());
    assert_ne!(strict.identity(), loose.identity());
    assert_ne!(
        fresh_id(&TestHasher, strict.identity(), 1, 0),
        fresh_id(&TestHasher, loose.identity(), 1, 0)
    );
}

/// Evidence is refused where nothing reads it: a presentation the callee
/// never consults would be authority travelling further than its author
/// could see.
#[test]
fn evidence_is_presented_exactly_where_it_is_required() {
    let chain = setup();
    let mut extra = valid_graph();
    extra.nodes[2].evidence = [EvidenceRef::IntentSignature].into();
    assert_eq!(
        admit(&extra, ALICE, &chain, &TestHasher),
        Err(AdmissionError::UnexpectedEvidence { node: 2 })
    );

    // The mirror: a guarded call presenting nothing.
    let mut missing = valid_graph();
    missing.nodes[1].evidence.clear();
    assert_eq!(
        admit(&missing, ALICE, &chain, &TestHasher),
        Err(AdmissionError::MissingEvidence { node: 1 })
    );

    // And the proof rule itself: a signature signs in, so presenting it
    // to the guarded withdrawal is refused whoever signed.
    let mut signature = valid_graph();
    signature.nodes[1].evidence = [EvidenceRef::IntentSignature].into();
    assert_eq!(
        admit(&signature, ALICE, &chain, &TestHasher),
        Err(AdmissionError::SignatureForGuarded { node: 1 })
    );
}

/// Authorize Alice, withdraw on her proof rather than on the signature,
/// deposit to Bob — the minted-proof shape, fully consumed.
fn proof_graph() -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE.into(),
                method: "authorize".into(),
                args: vec![],
                evidence: [EvidenceRef::IntentSignature].into(),
            },
            GraphNode {
                target: ALICE.into(),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X.address())),
                    GraphArg::Literal(Value::U128(100)),
                ],
                evidence: [EvidenceRef::Node(0)].into(),
            },
            GraphNode {
                target: BOB.into(),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                    constraints: vec![],
                }],
                evidence: BTreeSet::new(),
            },
        ],
    }
}

/// A minted proof resolves at admission to its producer's target — the
/// same address set an intent signature would have produced for a
/// virtual account, reached through the authorizing node instead.
#[test]
fn a_minted_proof_resolves_to_its_producers_target() {
    let chain = setup();
    let admitted = admit(&proof_graph(), ALICE, &chain, &TestHasher).expect("admits");

    // The authorizing gate is the rule that governs the cell the
    // method's own declared read names: what is stored there, or — while
    // nothing is — the identity that address itself derives. The guarded
    // withdrawal keeps the pure identity match.
    let authorize = &admitted.manifest().nodes[0];
    assert_eq!(authorize.evidence, vec![Presented::of_subject(ALICE)]);
    let cell = child_key(&TestHasher, ALICE, AUTH, &[]);
    assert_eq!(
        admitted.calls()[0].requires,
        vec![Rule::CountOf {
            count: 1,
            rules: vec![
                Rule::Require(JudgedLeaf::Stored { cell }),
                Rule::CountOf {
                    count: 2,
                    rules: vec![
                        Rule::Require(JudgedLeaf::Presence {
                            target: EffectTarget::Point(cell),
                            expect: Presence::Absent,
                        }),
                        Rule::Require(JudgedLeaf::Claim(Presented::of_subject(ALICE))),
                    ],
                },
            ],
        }]
    );

    let withdraw = &admitted.manifest().nodes[1];
    assert_eq!(withdraw.evidence, vec![Presented::of_subject(ALICE)]);
    assert_eq!(
        admitted.calls()[1].requires,
        vec![Rule::Require(JudgedLeaf::Claim(Presented::of_subject(
            ALICE
        )))]
    );

    let _ = route(&admitted, &resolver());
}

/// A custodian fixture: an authorizing method minting whatever identity
/// its metadata names, and a guarded method opening for the configured
/// one.
/// What the custodian's `present` method declares: `Identity` mints the
/// target's own address off its stored rule alone; the badge shapes add
/// the possession read, its condition, and the badge's mint.
enum Presenting {
    Identity,
    Fungible(Expr),
    Instance(Expr, Expr),
}

fn custodian_world(presenting: &Presenting, config: Vec<Value>) -> (Records, ComponentAddr) {
    let auth_cell = || Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(AUTH),
        material: vec![],
    };
    let read = |target| Clause::Effect {
        reach: None,
        guard: None,
        target,
        mode: ModeExpr::Read,
        denomination: None,
    };
    let satisfies = || Clause::Requires {
        guard: None,
        rule: RuleExpr::Require(RuleLeaf::Stored { cell: auth_cell() }),
    };
    let holds = |target| Clause::Requires {
        guard: None,
        rule: RuleExpr::Require(RuleLeaf::Presence {
            target: Box::new(target),
            expect: Presence::Present,
        }),
    };
    let mints = |claim| Clause::Mints { guard: None, claim };
    let vault = |badge: &Expr| {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(VAULT),
            material: vec![badge.clone()],
        })
    };
    let effects = match presenting {
        Presenting::Identity => vec![
            read(TargetExpr::Point(auth_cell())),
            satisfies(),
            mints(Expr::SelfAddr),
        ],
        Presenting::Fungible(badge) => vec![
            read(TargetExpr::Point(auth_cell())),
            read(vault(badge)),
            satisfies(),
            holds(vault(badge)),
            mints(badge.clone()),
        ],
        Presenting::Instance(badge, id) => vec![
            read(TargetExpr::Point(auth_cell())),
            read(holdings_entry(badge.clone(), id.clone())),
            satisfies(),
            holds(holdings_entry(badge.clone(), id.clone())),
            mints(Expr::Tuple(vec![badge.clone(), id.clone()])),
        ],
    };
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "present".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects,
            ..MethodSignature::default()
        },
    );
    package.methods.insert(
        "operate".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Requires {
                guard: None,
                rule: RuleExpr::claim(Expr::Config(0)),
            }],
            ..MethodSignature::default()
        },
    );
    let mut chain = setup();
    chain.packages.publish_unchecked(pkg("custodian"), package);
    let meta = InstanceMeta {
        package: pkg("custodian"),
        config,
        salt: Hash32([9; 32]),
    };
    let custodian = meta.address(&TestHasher);
    chain.instances.create(&TestHasher, meta);
    (chain, custodian)
}

fn custodian_graph(custodian: ComponentAddr) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: custodian.into(),
                method: "present".into(),
                args: vec![],
                evidence: [EvidenceRef::IntentSignature].into(),
            },
            GraphNode {
                target: custodian.into(),
                method: "operate".into(),
                args: vec![],
                evidence: [EvidenceRef::Node(0)].into(),
            },
        ],
    }
}

/// A custodial mint is the badge its shape ties the gate to; an
/// authorizing mint is the target and nothing else; and no other
/// accessibility mints at all.
#[test]
fn a_custodial_method_mints_the_badge_its_gate_verifies() {
    let badge = ResourceAddr::new([0xB0; 31]);

    let (chain, custodian) = custodian_world(
        &Presenting::Fungible(Expr::Config(0)),
        vec![Value::Address(badge.address())],
    );
    let admitted = admit(&custodian_graph(custodian), ALICE, &chain, &TestHasher).expect("admits");
    assert_eq!(
        admitted.calls()[0].requires,
        vec![Rule::Require(JudgedLeaf::Stored {
            cell: child_key(&TestHasher, custodian, AUTH, &[]),
        })],
        "the holder's rule rides the call"
    );
    assert!(
        admitted
            .declaration()
            .conditions
            .contains(&Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(child_key(
                    &TestHasher,
                    custodian,
                    VAULT,
                    &[Value::Address(badge.address()).canonical_bytes()],
                )),
                expect: Presence::Present,
            })),
        "the badge-keyed vault's possession joins the union declaration"
    );
    let operate = &admitted.manifest().nodes[1];
    assert_eq!(
        operate.evidence,
        vec![Presented::of_subject(badge)],
        "the proof presents the badge, not the producer's address"
    );
    assert_eq!(
        admitted.calls()[1].requires,
        vec![Rule::Require(JudgedLeaf::Claim(Presented::of_subject(
            badge
        )))],
        "a gate naming a resource address wants the badge, by the class alone"
    );

    // An identity sign-in mints the target itself: satisfying one's own
    // rule is no feat, so an identity it could name beyond itself would
    // be forgeable — which is why the justification check names none.
    let (chain, custodian) =
        custodian_world(&Presenting::Identity, vec![Value::Address(badge.address())]);
    let admitted = admit(&custodian_graph(custodian), ALICE, &chain, &TestHasher).expect("admits");
    assert_eq!(
        admitted.manifest().nodes[1].evidence,
        vec![Presented::of_subject(custodian)]
    );
    // A badge that is not a resource address has nothing possessable
    // behind it.
    // An instance mint widens to its resource where possession was
    // verified: the minted set carries both claims.
    let (chain, custodian) = custodian_world(
        &Presenting::Instance(Expr::Config(0), Expr::Literal(Value::U64(7))),
        vec![Value::Address(badge.address())],
    );
    let admitted = admit(&custodian_graph(custodian), ALICE, &chain, &TestHasher).expect("admits");
    assert_eq!(
        admitted.manifest().nodes[1].evidence,
        vec![
            Presented::of_instance(badge, 7),
            Presented::of_subject(badge),
        ],
        "one instance held is the badge held, where possession was verified"
    );

    // A badge that is not a resource address has nothing possessable
    // behind it: the mint's claim evaluates to no badge.
    let (chain, custodian) = custodian_world(
        &Presenting::Fungible(Expr::Config(0)),
        vec![Value::Address(Address::new(
            [0xB0; 31],
            AddressClass::Component,
        ))],
    );
    assert!(admit(&custodian_graph(custodian), ALICE, &chain, &TestHasher).is_err());
}

/// A proof consumer never runs ahead of its producer, and never draws
/// authority from a method that merely does something.
#[test]
fn a_proof_is_drawn_from_an_earlier_minting_node_or_refused() {
    let chain = setup();

    // Its own node: not earlier.
    let mut own = proof_graph();
    own.nodes[1].evidence = [EvidenceRef::Node(1)].into();
    assert_eq!(
        admit(&own, ALICE, &chain, &TestHasher),
        Err(AdmissionError::ForwardProof {
            node: 1,
            producer: 1
        })
    );

    // A later node, which is also every out-of-range index.
    let mut later = proof_graph();
    later.nodes[1].evidence = [EvidenceRef::Node(2)].into();
    assert_eq!(
        admit(&later, ALICE, &chain, &TestHasher),
        Err(AdmissionError::ForwardProof {
            node: 1,
            producer: 2
        })
    );

    // An earlier node whose method does not mint: naming it does
    // something, and doing something is not authorizing. The error
    // precedes linearity, so the appended node's dangling output never
    // gets judged.
    let mut unminting = proof_graph();
    unminting.nodes.push(GraphNode {
        target: ALICE.into(),
        method: "withdraw".into(),
        args: vec![
            GraphArg::Literal(Value::Address(RES_X.address())),
            GraphArg::Literal(Value::U128(1)),
        ],
        evidence: [EvidenceRef::Node(2)].into(),
    });
    assert_eq!(
        admit(&unminting, ALICE, &chain, &TestHasher),
        Err(AdmissionError::UnmintingProof {
            node: 3,
            producer: 2
        })
    );

    // The authorizing node's own gate takes evidence like any other.
    let mut unsigned = proof_graph();
    unsigned.nodes[0].evidence.clear();
    assert_eq!(
        admit(&unsigned, ALICE, &chain, &TestHasher),
        Err(AdmissionError::MissingEvidence { node: 0 })
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one assertion block per mutation class
fn every_malformed_mutation_rejects() {
    let chain = setup();
    let admit_it = |graph: &ManifestGraph| admit(graph, ALICE, &chain, &TestHasher);

    // Dangling edge: drop the rest-consuming node.
    let mut dangling = valid_graph();
    dangling.nodes.pop();
    assert_eq!(
        admit_it(&dangling),
        Err(AdmissionError::UnconsumedOutput {
            producer: 2,
            output: 1,
        })
    );

    // Double consumption: the last node consumes the taken part again.
    let mut double = valid_graph();
    double.nodes[4].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 2,
            output: 0,
        },
        constraints: vec![],
    };
    assert_eq!(
        admit_it(&double),
        Err(AdmissionError::DoubleConsumption {
            producer: 2,
            output: 0,
        })
    );

    // The cycle shape: a producer at or after its consumer cannot parse.
    let mut cyclic = valid_graph();
    cyclic.nodes[2].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 3,
            output: 0,
        },
        constraints: vec![],
    };
    assert_eq!(
        admit_it(&cyclic),
        Err(AdmissionError::ForwardEdge {
            node: 2,
            producer: 3,
        })
    );
    let mut self_edge = valid_graph();
    self_edge.nodes[2].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 2,
            output: 0,
        },
        constraints: vec![],
    };
    assert_eq!(
        admit_it(&self_edge),
        Err(AdmissionError::ForwardEdge {
            node: 2,
            producer: 2,
        })
    );

    // Type mismatches: a literal of the wrong kind, a literal where a
    // bucket is due, an edge into a value parameter, a phantom output.
    let mut wrong_kind = valid_graph();
    wrong_kind.nodes[1].args[1] = GraphArg::Literal(Value::U64(100));
    assert_eq!(
        admit_it(&wrong_kind),
        Err(AdmissionError::ParamKind {
            node: 1,
            param: 1,
            expected: "u128",
            found: "u64",
        })
    );
    // An address literal outside the classes the parameter declares: the
    // account's withdraw names a denomination, and a component is not one.
    let mut wrong_class = valid_graph();
    wrong_class.nodes[1].args[0] = GraphArg::Literal(Value::Address(Address::new(
        [0x77; 31],
        AddressClass::Component,
    )));
    assert_eq!(
        admit_it(&wrong_class),
        Err(AdmissionError::ParamKind {
            node: 1,
            param: 0,
            expected: "resource-address",
            found: "address",
        })
    );
    let mut literal_bucket = valid_graph();
    literal_bucket.nodes[3].args[0] = GraphArg::Literal(Value::U128(30));
    assert_eq!(
        admit_it(&literal_bucket),
        Err(AdmissionError::LiteralForBucketParam { node: 3, param: 0 })
    );
    let mut edge_value = valid_graph();
    edge_value.nodes[2].args[1] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 1,
            output: 0,
        },
        constraints: vec![],
    };
    assert_eq!(
        admit_it(&edge_value),
        Err(AdmissionError::EdgeForValueParam { node: 2, param: 1 })
    );
    // An edge of one kind into a parameter declaring the other. The
    // producer's projection says what crosses and the callee's signature
    // says what it takes, so a disagreement is a graph nothing should
    // sign rather than a cell whose framing a guest decodes its way out
    // of.
    let mut wrong_edge_kind = valid_graph();
    wrong_edge_kind.nodes[3].method = "deposit-nf".into();
    assert_eq!(
        admit_it(&wrong_edge_kind),
        Err(AdmissionError::ResourceKindMismatch {
            node: 3,
            param: 0,
            expected: "nf-bucket",
            found: ResourceKind::Fungible,
        })
    );
    let mut phantom = valid_graph();
    phantom.nodes[3].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 1,
            output: 5,
        },
        constraints: vec![],
    };
    assert_eq!(
        admit_it(&phantom),
        Err(AdmissionError::NoSuchOutput {
            producer: 1,
            output: 5,
        })
    );

    // Arity.
    let mut arity = valid_graph();
    arity.nodes[1].args.pop();
    assert_eq!(
        admit_it(&arity),
        Err(AdmissionError::ArityMismatch {
            node: 1,
            expected: 2,
            found: 1,
        })
    );

    // Constraints: a contradicted resource, an empty amount window.
    let mut wrong_resource = valid_graph();
    wrong_resource.nodes[2].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 1,
            output: 0,
        },
        constraints: vec![Constraint::ResourceIs(common::RES_Y)],
    };
    assert_eq!(
        admit_it(&wrong_resource),
        Err(AdmissionError::ResourceMismatch { node: 2, param: 0 })
    );
    let mut empty_window = valid_graph();
    empty_window.nodes[3].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 2,
            output: 0,
        },
        constraints: vec![Constraint::MinAmount(31), Constraint::MaxAmount(30)],
    };
    assert_eq!(
        admit_it(&empty_window),
        Err(AdmissionError::UnsatisfiableConstraint { node: 3, param: 0 })
    );
}

#[test]
fn a_literal_nested_past_the_bound_rejects_ahead_of_the_hash() {
    let chain = setup();
    let nest = |levels: usize| {
        let mut value = Value::U64(0);
        for _ in 0..levels {
            value = Value::Tuple(vec![value]);
        }
        value
    };

    let mut graph = valid_graph();
    graph.nodes[1].args[0] = GraphArg::Literal(nest(MAX_VALUE_DEPTH));
    assert_eq!(
        admit(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::ValueTooDeep { node: 1, param: 0 })
    );

    // One level shallower the depth check passes and ordinary typing
    // takes over, so the bound is exactly where it says it is.
    graph.nodes[1].args[0] = GraphArg::Literal(nest(MAX_VALUE_DEPTH - 1));
    assert!(matches!(
        admit(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::ParamKind { .. })
    ));
}

#[test]
fn repeated_amount_bounds_fold_to_their_conjunction() {
    let chain = setup();
    let admit_it = |graph: &ManifestGraph| admit(graph, ALICE, &chain, &TestHasher);

    // Execution enforces every constraint in the list, so admission judges
    // the conjunction — greatest lower bound against least upper bound.
    // Under last-wins the first of these admits and then cannot be
    // satisfied by anything.
    let mut unsatisfiable = valid_graph();
    unsatisfiable.nodes[3].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 2,
            output: 0,
        },
        constraints: vec![
            Constraint::MinAmount(10),
            Constraint::MinAmount(1),
            Constraint::MaxAmount(5),
        ],
    };
    assert_eq!(
        admit_it(&unsatisfiable),
        Err(AdmissionError::UnsatisfiableConstraint { node: 3, param: 0 })
    );

    // A satisfiable conjunction still admits, however it is spelled.
    let mut satisfiable = valid_graph();
    satisfiable.nodes[3].args[0] = GraphArg::Edge {
        edge: EdgeRef {
            producer: 2,
            output: 0,
        },
        constraints: vec![
            Constraint::MinAmount(1),
            Constraint::MinAmount(4),
            Constraint::MaxAmount(30),
            Constraint::MaxAmount(5),
        ],
    };
    assert!(admit_it(&satisfiable).is_ok());
}

/// A denomination is an expression over the whole bound argument list, so
/// one naming a later parameter than the position it constrains resolves.
///
/// The property is about when the check runs rather than what it decides:
/// evaluated as each argument was bound, this expression would read a
/// position nothing had filled in yet, and the method would be
/// unpublishable for a reason nobody wrote down.
#[test]
fn a_denomination_reads_a_parameter_bound_after_the_one_it_constrains() {
    let mut chain = setup();
    chain
        .packages
        .publish_unchecked(pkg("sorter"), sorter_metadata());
    chain.instances.create(&TestHasher, sorter_meta());
    let sorted = |resource: ResourceAddr| ManifestGraph {
        nodes: vec![
            valid_graph().nodes[0].clone(),
            valid_graph().nodes[1].clone(),
            GraphNode {
                target: sorter().into(),
                method: "sort".into(),
                args: vec![
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 1,
                            output: 0,
                        },
                        constraints: vec![],
                    },
                    GraphArg::Literal(Value::Address(resource.address())),
                ],
                evidence: BTreeSet::new(),
            },
        ],
    };

    // The edge carries what the later argument names.
    assert_eq!(
        admit(&sorted(RES_X), ALICE, &chain, &TestHasher).map(|_| ()),
        Ok(())
    );
    // And does not.
    assert!(matches!(
        admit(&sorted(common::RES_Y), ALICE, &chain, &TestHasher),
        Err(AdmissionError::WrongDenomination {
            node: 2,
            param: 0,
            ..
        })
    ));
}

/// A denomination names a resource, and an address of any other class is
/// refused at admission, naming the class the caller wrote.
#[test]
fn a_component_address_where_a_resource_belongs_is_refused() {
    let mut chain = setup();
    chain
        .packages
        .publish_unchecked(pkg("sorter"), sorter_metadata());
    chain.instances.create(&TestHasher, sorter_meta());
    let component = Address::new([0x44; 31], AddressClass::Component);
    let graph = ManifestGraph {
        nodes: vec![
            valid_graph().nodes[0].clone(),
            valid_graph().nodes[1].clone(),
            GraphNode {
                target: sorter().into(),
                method: "sort".into(),
                args: vec![
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 1,
                            output: 0,
                        },
                        constraints: vec![],
                    },
                    GraphArg::Literal(Value::Address(component)),
                ],
                evidence: BTreeSet::new(),
            },
        ],
    };
    assert!(matches!(
        admit(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::Eval {
            node: 2,
            source: EvalError::NotAResource(err),
        }) if err.found == AddressClass::Component
    ));
}

proptest! {
    /// Any multiset of bounds admits exactly when its conjunction is
    /// satisfiable, independent of the order they are written in.
    #[test]
    fn repeated_bounds_admit_iff_the_conjunction_holds(
        mins in prop_vec(any::<u128>(), 1..4),
        maxes in prop_vec(any::<u128>(), 1..4),
    ) {
        let chain = setup();
        let mut graph = valid_graph();
        let mut constraints: Vec<Constraint> =
            mins.iter().copied().map(Constraint::MinAmount).collect();
        constraints.extend(maxes.iter().copied().map(Constraint::MaxAmount));
        graph.nodes[3].args[0] = GraphArg::Edge {
            edge: EdgeRef { producer: 2, output: 0 },
            constraints,
        };
        let verdict = admit(&graph, ALICE, &chain, &TestHasher);
        let lower = mins.iter().copied().max().expect("non-empty");
        let upper = maxes.iter().copied().min().expect("non-empty");
        if lower > upper {
            assert_eq!(
                verdict,
                Err(AdmissionError::UnsatisfiableConstraint { node: 3, param: 0 })
            );
        } else {
            assert!(verdict.is_ok());
        }
    }

    /// Point any edge reference anywhere: admission either accepts a graph
    /// equivalent to the valid one or rejects deterministically — it never
    /// panics and never mistypes an edge.
    #[test]
    fn arbitrary_edge_rewires_never_break_admission(
        node in 1usize..5,
        arg in 0usize..2,
        producer in any::<u32>(),
        output in any::<u32>(),
    ) {
        let chain = setup();
        let mut graph = valid_graph();
        let args = &mut graph.nodes[node].args;
        let slot = arg.min(args.len() - 1);
        args[slot] = GraphArg::Edge {
            edge: EdgeRef { producer, output },
            constraints: vec![],
        };
        let first = admit(&graph, ALICE, &chain, &TestHasher);
        let second = admit(&graph, ALICE, &chain, &TestHasher);
        assert_eq!(first, second);
    }

    /// Amount-window constraints reject exactly when the window is empty.
    #[test]
    fn amount_windows_admit_iff_satisfiable(min in any::<u128>(), max in any::<u128>()) {
        let chain = setup();
        let mut graph = valid_graph();
        graph.nodes[3].args[0] = GraphArg::Edge {
            edge: EdgeRef { producer: 2, output: 0 },
            constraints: vec![Constraint::MinAmount(min), Constraint::MaxAmount(max)],
        };
        let verdict = admit(&graph, ALICE, &chain, &TestHasher);
        if min > max {
            assert_eq!(
                verdict,
                Err(AdmissionError::UnsatisfiableConstraint { node: 3, param: 0 })
            );
        } else {
            assert!(verdict.is_ok());
        }
    }
}

/// A `Requires` clause rides admission's single walk: the evaluated
/// authority condition lands on the node's lowered call, the presence
/// condition joins the union declaration, and the evidence policy reads
/// the conditions — a stored leaf is what admits a signature as
/// evidence, exactly as a stored-rule gate is.
#[test]
fn a_condition_lowers_to_the_call_and_the_union_declaration() {
    use hyperscale_vm_effects::{JudgedLeaf, Rule, RuleLeaf};

    let auth_cell = || Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(AUTH),
        material: vec![],
    };
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "act".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![
                Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(auth_cell()),
                    mode: ModeExpr::Read,
                    denomination: None,
                },
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(TargetExpr::Point(auth_cell())),
                        expect: Presence::Present,
                    }),
                },
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::CountOf {
                        count: 1,
                        rules: vec![
                            RuleExpr::claim(Expr::Config(0)),
                            RuleExpr::Require(RuleLeaf::Stored { cell: auth_cell() }),
                        ],
                    },
                },
            ],
            abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
            ..MethodSignature::default()
        },
    );
    let mut chain = setup();
    // Through the checked door: the composed signature check admits the
    // condition-carrying shape.
    chain
        .packages
        .publish(pkg("conditional"), package)
        .expect("publishes");
    let meta = InstanceMeta {
        package: pkg("conditional"),
        config: vec![Value::Address(ALICE.address())],
        salt: Hash32([4; 32]),
    };
    let target = meta.address(&TestHasher);
    chain.instances.create(&TestHasher, meta);

    let graph = ManifestGraph {
        nodes: vec![GraphNode {
            target: target.into(),
            method: "act".into(),
            args: vec![],
            evidence: [EvidenceRef::IntentSignature].into(),
        }],
    };
    let admitted = admit(&graph, ALICE, &chain, &TestHasher).expect("admits");

    let key = child_key(&TestHasher, target, AUTH, &[]);
    // The signature's own condition, then the instantiation fence
    // admission puts on every component call.
    assert_eq!(
        admitted.declaration().conditions,
        vec![
            Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(key),
                expect: Presence::Present,
            }),
            Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(child_key(&TestHasher, target, CONFIG, &[])),
                expect: Presence::Present,
            }),
        ]
    );
    assert_eq!(
        admitted.calls()[0].requires,
        vec![Rule::CountOf {
            count: 1,
            rules: vec![
                Rule::Require(JudgedLeaf::Claim(Presented::of_subject(ALICE))),
                Rule::Require(JudgedLeaf::Stored { cell: key }),
            ],
        }]
    );
    // The signature was admissible as evidence because the declaration
    // reads a stored rule; the presented identity is the signer's.
    assert_eq!(
        admitted.calls()[0].evidence,
        vec![Presented::of_subject(ALICE)]
    );
}

/// What a call must present is a property of the declaration it
/// evaluated, not of the clause list its signature was written with.
///
/// A `Requires` clause carries a guard, so a signature stating one says
/// nothing about whether this call requires anything — and demanding a
/// proof for a condition that never fired would be a refusal no caller
/// could act on, while accepting one would put an evidence assignment
/// into a signed graph that nothing validates. Both are the same mistake
/// from opposite sides, and reading the evaluated frame answers both.
#[test]
fn evidence_follows_the_conditions_this_call_evaluated() {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "settle".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::U64],
            effects: vec![Clause::Requires {
                guard: Some(Box::new(Expr::Eq(
                    Box::new(Expr::Arg(0)),
                    Box::new(Expr::Literal(Value::U64(1))),
                ))),
                rule: RuleExpr::Require(RuleLeaf::Stored {
                    cell: Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotRef::Fixed(AUTH),
                        material: vec![],
                    },
                }),
            }],
            ..MethodSignature::default()
        },
    );
    let mut chain = setup();
    chain.packages.publish_unchecked(pkg("settler"), package);
    let meta = InstanceMeta {
        package: pkg("settler"),
        config: vec![],
        salt: Hash32([11; 32]),
    };
    let settler = meta.address(&TestHasher);
    chain.instances.create(&TestHasher, meta);

    let call = |guarded: bool, evidence: BTreeSet<EvidenceRef>| ManifestGraph {
        nodes: vec![GraphNode {
            target: settler.into(),
            method: "settle".into(),
            args: vec![GraphArg::Literal(Value::U64(u64::from(guarded)))],
            evidence,
        }],
    };

    // The guard fires: the condition is there, so a proof is required and
    // the signature answers for it.
    assert!(
        admit(
            &call(true, [EvidenceRef::IntentSignature].into()),
            ALICE,
            &chain,
            &TestHasher
        )
        .is_ok()
    );
    assert_eq!(
        admit(&call(true, BTreeSet::new()), ALICE, &chain, &TestHasher),
        Err(AdmissionError::MissingEvidence { node: 0 })
    );

    // The guard does not fire: the frame carries no condition, so the
    // same call needs nothing — and a proof presented anyway is refused
    // rather than carried past everything that could have read it.
    assert!(admit(&call(false, BTreeSet::new()), ALICE, &chain, &TestHasher).is_ok());
    assert_eq!(
        admit(
            &call(false, [EvidenceRef::IntentSignature].into()),
            ALICE,
            &chain,
            &TestHasher
        ),
        Err(AdmissionError::UnexpectedEvidence { node: 0 })
    );
}
