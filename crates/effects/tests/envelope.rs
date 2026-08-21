//! Envelope tree admission: composed intents flatten deterministically
//! along their yield edges, the nullifier vocabulary derives canonical
//! addresses, and every malformed composition rejects exactly.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{
    AdmissionError, AdmittedTree, Bounds, ChainRecords, Constraint, EdgeContent, EdgeRef,
    EnvelopeTree, GraphArg, GraphNode, Hash32, Hasher, InstanceMeta, IntentDecl, MAX_VALUE_DEPTH,
    MAX_YIELD_PARAMS, ManifestGraph, ManifestHash, NULLIFIER_SLOT, NodeInput, PackageHash,
    PrefixShardResolver, Records, ResourceKind, ShardResolver, Subintent, TestHasher, Value,
    YieldBinding, YieldParam, admit, admit_tree, child_key, nullifier_key, route_tree,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    Address, CallTarget, Effect, EffectTarget, MAX_SUBINTENTS, Mode, PrincipalAddr, ResourceAddr,
};
use proptest::prelude::{any, proptest};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> Records {
    let mut chain = Records::new();
    chain.packages.publish_unchecked(pkg(), account::metadata());
    chain.instances.serve_principals(pkg());
    chain
}

fn authorize(target: impl Into<CallTarget>) -> GraphNode {
    GraphNode::signed(target, "authorize", vec![])
}

fn withdraw(
    target: impl Into<CallTarget>,
    resource: impl Into<Address>,
    amount: u128,
) -> GraphNode {
    GraphNode::bearing(
        target,
        "withdraw",
        vec![
            GraphArg::Literal(Value::Address(resource.into())),
            GraphArg::Literal(Value::U128(amount)),
        ],
        0,
    )
}

fn deposit_param(target: impl Into<CallTarget>, param: u32) -> GraphNode {
    GraphNode::new(target, "deposit", vec![GraphArg::Param(param)])
}

/// The two-signer composition: the root withdraws X and deposits the
/// yielded Y; the subintent withdraws Y and deposits the yielded X.
fn composed_tree(pay: u128) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![
                    authorize(ALICE),
                    withdraw(ALICE, RES_X, pay),
                    deposit_param(ALICE, 0),
                ],
            },
            params: vec![YieldParam {
                resource: RES_Y,
                constraints: vec![Constraint::MinAmount(10)],
            }],
        },
        root_bindings: vec![YieldBinding {
            intent: 1,
            edge: EdgeRef {
                producer: 1,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![
                        authorize(BOB),
                        withdraw(BOB, RES_Y, 10),
                        deposit_param(BOB, 0),
                    ],
                },
                params: vec![YieldParam {
                    resource: RES_X,
                    constraints: vec![Constraint::MinAmount(100)],
                }],
            },
            signer: BOB,
            bindings: vec![YieldBinding {
                intent: 0,
                edge: EdgeRef {
                    producer: 1,
                    output: 0,
                },
            }],
        }],
        instances: Vec::new(),
        resources: Vec::new(),
    }
}

fn admit_composed(tree: &EnvelopeTree) -> Result<AdmittedTree, AdmissionError> {
    let chain = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, ALICE, identity, &chain, &TestHasher)
}

#[test]
fn a_composed_tree_flattens_deterministically() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).unwrap();
    let manifest = admitted.admitted.manifest();

    // Root nodes lead where ready, yields interleave the rest: each
    // intent's sign-in and withdraw, then the two deposits consuming
    // each other's yields.
    let shape: Vec<(Address, &str)> = manifest
        .nodes
        .iter()
        .map(|node| (node.target, node.method.as_str()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (ALICE.address(), "authorize"),
            (ALICE.address(), "withdraw"),
            (BOB.address(), "authorize"),
            (BOB.address(), "withdraw"),
            (ALICE.address(), "deposit"),
            (BOB.address(), "deposit"),
        ]
    );
    assert_eq!(
        manifest.nodes[4].inputs,
        vec![NodeInput::Edge {
            source: 3,
            output: 0,
            resource: RES_Y,
            content: EdgeContent::Fungible,
            bounds: Bounds {
                min: Some(10),
                max: None,
            },
        }]
    );
    assert_eq!(
        manifest.nodes[5].inputs,
        vec![NodeInput::Edge {
            source: 1,
            output: 0,
            resource: RES_X,
            content: EdgeContent::Fungible,
            bounds: Bounds {
                min: Some(100),
                max: None,
            },
        }]
    );

    // The nullifier record: canonical address under the signer.
    let record = admitted.subintents[0];
    assert_eq!(record.signer, BOB);
    assert_eq!(
        record.nullifier,
        nullifier_key(&TestHasher, BOB, record.subintent)
    );
    assert_eq!(record.nullifier.owner, BOB);
}

#[test]
fn routing_carries_the_nullifier_creation_write() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).unwrap();
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 8 });
    let record = admitted.subintents[0];
    // Asked of the resolver rather than restated: the claim is that the
    // write lands at the signer's shard and nowhere else, not what those
    // shards happen to be called.
    let resolver = PrefixShardResolver { bits: 8 };
    let signer = resolver.shard_of(record.signer.address());
    let root = resolver.shard_of(ALICE.address());
    assert_ne!(signer, root);
    assert!(routing.per_shard[&signer].contains(&Effect {
        target: EffectTarget::Point(record.nullifier),
        mode: Mode::Write,
    }));
    // The root's shard carries no nullifier write.
    assert!(!routing.per_shard[&root].iter().any(|effect| {
        matches!(effect.target, EffectTarget::Point(key) if key == record.nullifier)
    }));
}

#[test]
fn identities_differ_while_subintent_hashes_agree() {
    let first = composed_tree(100);
    let second = composed_tree(120);
    assert_ne!(first.hash(&TestHasher), second.hash(&TestHasher));
    assert_eq!(
        first.subintents[0].decl.hash(&TestHasher),
        second.subintents[0].decl.hash(&TestHasher)
    );
    // Same tree, different signer: a different nullifier.
    let hash = first.subintents[0].decl.hash(&TestHasher);
    assert_ne!(
        nullifier_key(&TestHasher, ALICE, hash),
        nullifier_key(&TestHasher, BOB, hash)
    );
    // The nullifier is an ordinary child key under the reserved role.
    assert_eq!(
        nullifier_key(&TestHasher, BOB, hash),
        child_key(&TestHasher, BOB, NULLIFIER_SLOT, &[hash.0.0.to_vec()])
    );
}

#[test]
fn the_declaration_hash_covers_params_and_constraints() {
    let decl = composed_tree(100).subintents[0].decl.clone();
    let mut reconstrained = decl.clone();
    reconstrained.params[0].constraints = vec![Constraint::MinAmount(101)];
    assert_ne!(decl.hash(&TestHasher), reconstrained.hash(&TestHasher));
    let mut retyped = decl.clone();
    retyped.params[0].resource = RES_Y;
    assert_ne!(decl.hash(&TestHasher), retyped.hash(&TestHasher));
}

#[test]
fn mutual_yields_with_no_order_are_a_cycle() {
    // Each intent's only node consumes the other's yield; neither can
    // produce first.
    let mut tree = composed_tree(100);
    tree.root.graph.nodes = vec![deposit_param(ALICE, 0)];
    tree.subintents[0].decl.graph.nodes = vec![deposit_param(BOB, 0)];
    tree.root_bindings[0].edge.producer = 0;
    tree.subintents[0].bindings[0].edge.producer = 0;
    assert_eq!(admit_composed(&tree), Err(AdmissionError::CyclicYields));
}

#[test]
fn a_yielded_resource_must_match_the_declared_type() {
    let mut tree = composed_tree(100);
    tree.subintents[0].decl.params[0].resource = RES_Y;
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::YieldResourceMismatch {
            intent: 1,
            param: 0
        })
    );
}

/// The subintent's producer, yielding named instances instead of an
/// amount.
fn withdraw_nf(target: impl Into<CallTarget>, resource: impl Into<Address>, id: u64) -> GraphNode {
    GraphNode::bearing(
        target,
        "withdraw-nf",
        vec![
            GraphArg::Literal(Value::Address(resource.into())),
            GraphArg::Literal(Value::List(vec![Value::U64(id)])),
        ],
        0,
    )
}

#[test]
fn a_yielded_edge_is_judged_by_its_kind() {
    let nf_tree = |consumer: GraphNode| EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![authorize(ALICE), withdraw(ALICE, RES_X, 100), consumer],
            },
            params: vec![YieldParam {
                resource: RES_Y,
                constraints: vec![],
            }],
        },
        root_bindings: vec![YieldBinding {
            intent: 1,
            edge: EdgeRef {
                producer: 1,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![
                        authorize(BOB),
                        withdraw_nf(BOB, RES_Y, 7),
                        deposit_param(BOB, 0),
                    ],
                },
                params: vec![YieldParam {
                    resource: RES_X,
                    constraints: vec![],
                }],
            },
            signer: BOB,
            bindings: vec![YieldBinding {
                intent: 0,
                edge: EdgeRef {
                    producer: 1,
                    output: 0,
                },
            }],
        }],
        instances: Vec::new(),
        resources: Vec::new(),
    };

    // Named instances into the fungible `deposit`: refused by kind, the
    // same judgment a direct edge gets.
    let wrong = nf_tree(deposit_param(ALICE, 0));
    assert!(matches!(
        admit_composed(&wrong),
        Err(AdmissionError::ResourceKindMismatch {
            found: ResourceKind::NonFungible,
            ..
        })
    ));

    // The same yield into `deposit-nf` admits.
    let right = nf_tree(GraphNode::new(
        ALICE,
        "deposit-nf",
        vec![GraphArg::Param(0)],
    ));
    admit_composed(&right).expect("an NF yield binds an NF parameter");

    // And a fungible yield into `deposit-nf` refuses the other way.
    let mut crossed = composed_tree(100);
    crossed.root.graph.nodes[2] = GraphNode::new(ALICE, "deposit-nf", vec![GraphArg::Param(0)]);
    assert!(matches!(
        admit_composed(&crossed),
        Err(AdmissionError::ResourceKindMismatch {
            found: ResourceKind::Fungible,
            ..
        })
    ));
}

#[test]
fn param_consumption_is_exactly_once() {
    let mut unused = composed_tree(100);
    unused.subintents[0].decl.graph.nodes[2] = withdraw(BOB, RES_Y, 1);
    assert_eq!(
        admit_composed(&unused),
        Err(AdmissionError::UnusedYieldParam {
            intent: 1,
            param: 0
        })
    );

    let mut reused = composed_tree(100);
    reused.subintents[0]
        .decl
        .graph
        .nodes
        .push(deposit_param(BOB, 0));
    assert_eq!(
        admit_composed(&reused),
        Err(AdmissionError::YieldParamReused {
            intent: 1,
            param: 0
        })
    );
}

#[test]
fn bindings_must_cover_the_declared_params() {
    let mut tree = composed_tree(100);
    tree.subintents[0].bindings.clear();
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::BindingArity {
            intent: 1,
            expected: 1,
            found: 0,
        })
    );

    let mut dangling = composed_tree(100);
    dangling.root_bindings[0].intent = 7;
    assert_eq!(
        admit_composed(&dangling),
        Err(AdmissionError::UnknownYieldSource {
            intent: 0,
            param: 0
        })
    );
}

#[test]
fn two_bindings_cannot_consume_one_output() {
    // A second subintent binds the same root output the first consumes.
    let chain = world();
    let second_signer = PrincipalAddr::new([0x21; 31]);
    let mut tree = composed_tree(100);
    let mut second = tree.subintents[0].clone();
    second.signer = second_signer;
    second.decl.graph.nodes[1] = withdraw(BOB, RES_Y, 11);
    tree.subintents.push(second);
    let identity = tree.hash(&TestHasher);
    let result = admit_tree(&tree, ALICE, identity, &chain, &TestHasher);
    assert_eq!(
        result,
        Err(AdmissionError::DoubleConsumption {
            producer: 1,
            output: 0,
        })
    );
}

#[test]
fn duplicate_subintents_reject() {
    let mut tree = composed_tree(100);
    let copy = tree.subintents[0].clone();
    tree.subintents.push(copy);
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::DuplicateSubintent { index: 1 })
    );
}

#[test]
fn an_intent_cannot_declare_unbounded_yield_params() {
    // The parameter count bounds the binding vector, and both index by
    // `u32` — so the cap is what makes those positions expressible by
    // construction rather than by hope.
    let mut tree = composed_tree(100);
    let param = tree.subintents[0].decl.params[0].clone();
    let binding = tree.subintents[0].bindings[0];
    for _ in 0..MAX_YIELD_PARAMS {
        tree.subintents[0].decl.params.push(param.clone());
        tree.subintents[0].bindings.push(binding);
    }
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::TooManyYieldParams { intent: 1 })
    );
}

#[test]
fn a_yield_param_cannot_bind_a_value_parameter() {
    // `withdraw(resource, amount)` takes no bucket, so binding a yield
    // into it is a parameter defect — not the edge defect the shared
    // arity check would otherwise report.
    let mut tree = composed_tree(100);
    tree.subintents[0].decl.graph.nodes[2] = GraphNode::bearing(
        BOB,
        "withdraw",
        vec![GraphArg::Param(0), GraphArg::Literal(Value::U128(1))],
        0,
    );
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::ParamForValueParam { node: 5, param: 0 })
    );
}

#[test]
fn a_bare_graph_admits_no_params() {
    let chain = world();
    let graph = ManifestGraph {
        nodes: vec![deposit_param(ALICE, 0)],
    };
    assert_eq!(
        admit(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::UnboundParam { node: 0, param: 0 })
    );
}

#[test]
fn fresh_keys_root_at_the_envelope_identity() {
    // Two envelopes carrying the same tree but different identities mint
    // different fresh keys: the identity, not the tree, roots the
    // derivation.
    let chain = world();
    let tree = composed_tree(100);
    let identities = [
        tree.hash(&TestHasher),
        ManifestHash(TestHasher.hash(b"envelope", &[b"other"])),
    ];
    let admitted: Vec<_> = identities
        .iter()
        .map(|identity| admit_tree(&tree, ALICE, *identity, &chain, &TestHasher).unwrap())
        .collect();
    assert_eq!(
        admitted[0].admitted.manifest(),
        admitted[1].admitted.manifest(),
        "the corpus graph mints no fresh keys, so the manifests agree"
    );
    assert_ne!(
        admitted[0].admitted.identity(),
        admitted[1].admitted.identity()
    );
}

#[test]
fn the_subintent_cap_is_checked_before_anything_else() {
    // At the cap the count check passes and ordinary rules take over —
    // here the duplicate scan. One past it, the count is the verdict.
    let mut at_cap = composed_tree(100);
    let copy = at_cap.subintents[0].clone();
    at_cap.subintents.resize(MAX_SUBINTENTS, copy.clone());
    assert_eq!(
        admit_composed(&at_cap),
        Err(AdmissionError::DuplicateSubintent { index: 1 })
    );

    let mut past_cap = at_cap;
    past_cap.subintents.push(copy);
    assert_eq!(
        admit_composed(&past_cap),
        Err(AdmissionError::TooManySubintents)
    );
}

#[test]
fn the_envelope_hash_covers_the_bindings_the_composer_chose() {
    // The subintent's own hash is the signer's; the bindings are the
    // composer's, and only the envelope identity covers them.
    let tree = composed_tree(100);
    let mut rebound = tree.clone();
    rebound.root_bindings[0].edge = EdgeRef {
        producer: 2,
        output: 0,
    };
    assert_ne!(tree.hash(&TestHasher), rebound.hash(&TestHasher));
    assert_eq!(
        tree.subintents[0].decl.hash(&TestHasher),
        rebound.subintents[0].decl.hash(&TestHasher)
    );

    let mut resigned = tree.clone();
    resigned.subintents[0].signer = ALICE;
    assert_ne!(tree.hash(&TestHasher), resigned.hash(&TestHasher));

    let mut rebound_subintent = tree.clone();
    rebound_subintent.subintents[0].bindings[0].edge = EdgeRef {
        producer: 2,
        output: 0,
    };
    assert_ne!(tree.hash(&TestHasher), rebound_subintent.hash(&TestHasher));

    // Every field of a binding, and the count of them: bindings encode to
    // fixed-width records concatenated into one hashed part, so a field
    // the encoding dropped or a list length it did not frame would both
    // read as the same composition.
    let mut retargeted = tree.clone();
    retargeted.root_bindings[0].intent = retargeted.root_bindings[0].intent.wrapping_add(1);
    assert_ne!(tree.hash(&TestHasher), retargeted.hash(&TestHasher));

    let mut extended = tree.clone();
    let repeated = extended.root_bindings[0];
    extended.root_bindings.push(repeated);
    assert_ne!(tree.hash(&TestHasher), extended.hash(&TestHasher));

    let mut resliced = tree.clone();
    resliced.root_bindings[0].edge.output += 1;
    assert_ne!(tree.hash(&TestHasher), resliced.hash(&TestHasher));
}

proptest! {
    /// Point any yield binding anywhere: tree admission either accepts a
    /// composition or rejects it deterministically — it never panics and
    /// never disagrees with itself.
    #[test]
    fn arbitrary_yield_rebinds_never_break_admission(
        intent in any::<u32>(),
        producer in any::<u32>(),
        output in any::<u32>(),
        on_subintent in any::<bool>(),
    ) {
        let chain = world();
        let mut tree = composed_tree(100);
        let binding = YieldBinding { intent, edge: EdgeRef { producer, output } };
        if on_subintent {
            tree.subintents[0].bindings[0] = binding;
        } else {
            tree.root_bindings[0] = binding;
        }
        let identity = tree.hash(&TestHasher);
        let first = admit_tree(&tree, ALICE, identity, &chain, &TestHasher);
        let second = admit_tree(&tree, ALICE, identity, &chain, &TestHasher);
        assert_eq!(first, second);
    }
}

/// The record a call resolves against is the composer's signed claim,
/// so it rides inside the identity everything else derives from.
#[test]
fn presented_instances_are_covered_by_the_tree_identity() {
    let mut tree = composed_tree(100);
    let plain = tree.hash(&TestHasher);
    tree.instances.push(InstanceMeta {
        package: pkg(),
        config: vec![Value::U64(1)],
        salt: Hash32([9; 32]),
    });
    assert_ne!(tree.hash(&TestHasher), plain);
}

/// A presented record's configuration values clear the same nesting
/// bound graph literals do, refused before any composition touches them.
#[test]
fn a_deep_instance_config_value_refuses_at_admission() {
    let mut tree = composed_tree(100);
    let mut value = Value::U64(0);
    for _ in 0..MAX_VALUE_DEPTH {
        value = Value::Tuple(vec![value]);
    }
    tree.instances.push(InstanceMeta {
        package: pkg(),
        config: vec![value],
        salt: Hash32([9; 32]),
    });
    assert!(matches!(
        admit_composed(&tree),
        Err(AdmissionError::InstanceValueTooDeep { .. })
    ));
}

/// A presented record brings a component up, and does nothing else.
///
/// Once a component is actual its record is the chain's to answer with,
/// so a caller carrying one alongside an ordinary call is stating the
/// configuration of something the chain already holds — two sources for
/// one fact, which need never agree. The seal is the one call with no
/// committed record to resolve against, so it is the one call a record
/// may stand for.
#[test]
fn a_record_stands_for_a_seal_and_for_no_other_call() {
    let drawing = PackageHash(TestHasher.hash(b"package", &[b"lottery"]));
    let mut chain = Records::new();
    chain.packages.publish_unchecked(pkg(), account::metadata());
    chain
        .packages
        .publish_unchecked(drawing, lottery::metadata());
    chain.instances.serve_principals(pkg());

    let meta = InstanceMeta {
        package: drawing,
        config: Vec::new(),
        salt: Hash32([5; 32]),
    };
    let round = meta.address(&TestHasher);
    let calling = |method: &str, args: Vec<GraphArg>, records: Vec<InstanceMeta>| EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![GraphNode {
                    target: round.into(),
                    method: method.into(),
                    args,
                    evidence: BTreeSet::new(),
                }],
            },
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: records,
        resources: Vec::new(),
    };
    let admit_with = |tree: &EnvelopeTree, chain: &dyn ChainRecords| {
        admit_tree(tree, ALICE, tree.hash(&TestHasher), chain, &TestHasher)
    };

    // The seal: nothing committed answers for the component yet, which
    // is exactly what the record is for.
    let seal = calling("instantiate", Vec::new(), vec![meta.clone()]);
    assert!(admit_with(&seal, &chain).is_ok());

    // Any other call carrying the same record is refused, though the
    // record is honest and derives the address it claims.
    let draw = || {
        calling(
            "draw",
            vec![GraphArg::Literal(Value::U64(8))],
            vec![meta.clone()],
        )
    };
    let drawn = draw();
    assert!(
        matches!(
            admit_with(&drawn, &chain),
            Err(AdmissionError::PresentedForCall { node: 0, .. })
        ),
        "a record stands for the seal alone: {:?}",
        admit_with(&drawn, &chain)
    );

    // And once the chain answers for the component, the same call
    // admits carrying nothing at all.
    let mut sealed = chain.clone();
    sealed.instances.create(&TestHasher, meta.clone());
    let bare = calling("draw", vec![GraphArg::Literal(Value::U64(8))], Vec::new());
    assert!(admit_with(&bare, &sealed).is_ok());

    // A record presented beside a component the chain already holds is
    // refused on the same terms — the chain's answer is the one that
    // stands, so a caller's copy is never consulted.
    assert!(matches!(
        admit_with(&drawn, &sealed),
        Err(AdmissionError::PresentedForCall { node: 0, .. })
    ));
}
