//! Envelope tree admission: composed intents flatten deterministically
//! along their yield edges, the nullifier vocabulary derives canonical
//! addresses, and every malformed composition rejects exactly.

use hyperscale_vm_effects::stdlib::account_metadata;
use hyperscale_vm_effects::{
    Address, AdmissionError, AdmittedTree, Constraint, EdgeRef, Effect, EffectTarget, EnvelopeTree,
    GraphArg, GraphNode, Hasher, InstanceMeta, InstanceRegistry, IntentDecl, MAX_SUBINTENTS,
    MAX_YIELD_PARAMS, ManifestGraph, ManifestHash, MetadataCache, Mode, NULLIFIER_ROLE, NodeInput,
    PackageHash, PrefixShardResolver, RoleId, ShardId, Subintent, TestHasher, Value, YieldBinding,
    YieldParam, admit, admit_tree, child_key, nullifier_key, route_tree,
};
use proptest::prelude::{any, proptest};

const ALICE: Address = Address([0x10; 16]);
const BOB: Address = Address([0x20; 16]);
const RES_X: Address = Address([0xE1; 16]);
const RES_Y: Address = Address([0xE2; 16]);

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    for account in [ALICE, BOB] {
        instances.register(
            account,
            InstanceMeta {
                package: pkg(),
                config: vec![],
            },
        );
    }
    (cache, instances)
}

fn withdraw(target: Address, resource: Address, amount: u128) -> GraphNode {
    GraphNode {
        target,
        method: "withdraw".into(),
        args: vec![
            GraphArg::Literal(Value::Address(resource)),
            GraphArg::Literal(Value::U128(amount)),
        ],
    }
}

fn deposit_param(target: Address, param: u32) -> GraphNode {
    GraphNode {
        target,
        method: "deposit".into(),
        args: vec![GraphArg::Param(param)],
    }
}

/// The two-signer composition: the root withdraws X and deposits the
/// yielded Y; the subintent withdraws Y and deposits the yielded X.
fn composed_tree(pay: u128) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![withdraw(ALICE, RES_X, pay), deposit_param(ALICE, 0)],
            },
            params: vec![YieldParam {
                resource: RES_Y,
                constraints: vec![Constraint::MinAmount(10)],
            }],
        },
        root_bindings: vec![YieldBinding {
            intent: 1,
            edge: EdgeRef {
                producer: 0,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![withdraw(BOB, RES_Y, 10), deposit_param(BOB, 0)],
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
                    producer: 0,
                    output: 0,
                },
            }],
        }],
    }
}

fn admit_composed(tree: &EnvelopeTree) -> Result<AdmittedTree, AdmissionError> {
    let (cache, instances) = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, identity, &cache, &instances, &TestHasher)
}

#[test]
fn a_composed_tree_flattens_deterministically() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).unwrap();
    let manifest = admitted.admitted.manifest();

    // Root nodes lead where ready, yields interleave the rest: the
    // composer's withdraw, the subintent's withdraw, then the two
    // deposits consuming each other's yields.
    let shape: Vec<(Address, &str)> = manifest
        .nodes
        .iter()
        .map(|node| (node.target, node.method.as_str()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (ALICE, "withdraw"),
            (BOB, "withdraw"),
            (ALICE, "deposit"),
            (BOB, "deposit"),
        ]
    );
    assert_eq!(
        manifest.nodes[2].inputs,
        vec![NodeInput::Edge {
            source: 1,
            resource: RES_Y,
        }]
    );
    assert_eq!(
        manifest.nodes[3].inputs,
        vec![NodeInput::Edge {
            source: 0,
            resource: RES_X,
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
    let (cache, instances) = world();
    let admitted = admit_composed(&tree).unwrap();
    let routing = route_tree(
        &admitted,
        &cache,
        &instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .unwrap();
    let record = admitted.subintents[0];
    assert!(routing.per_shard[&ShardId(0x20)].contains(&Effect {
        target: EffectTarget::Point(record.nullifier),
        mode: Mode::Write,
    }));
    // The root's shard carries no nullifier write.
    assert!(!routing.per_shard[&ShardId(0x10)].iter().any(|effect| {
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
        child_key(&TestHasher, BOB, NULLIFIER_ROLE, &[hash.0.0.to_vec()])
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

#[test]
fn param_consumption_is_exactly_once() {
    let mut unused = composed_tree(100);
    unused.subintents[0].decl.graph.nodes[1] = withdraw(BOB, RES_Y, 1);
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
    let mut tree = composed_tree(100);
    let mut second = tree.subintents[0].clone();
    second.signer = Address([0x21; 16]);
    second.decl.graph.nodes[0] = withdraw(BOB, RES_Y, 11);
    tree.subintents.push(second);
    let (cache, mut instances) = world();
    instances.register(
        Address([0x21; 16]),
        InstanceMeta {
            package: pkg(),
            config: vec![],
        },
    );
    let identity = tree.hash(&TestHasher);
    let result = admit_tree(&tree, identity, &cache, &instances, &TestHasher);
    assert_eq!(
        result,
        Err(AdmissionError::DoubleConsumption {
            producer: 0,
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
    tree.subintents[0].decl.graph.nodes[1] = GraphNode {
        target: BOB,
        method: "withdraw".into(),
        args: vec![GraphArg::Param(0), GraphArg::Literal(Value::U128(1))],
    };
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::ParamForValueParam { node: 3, param: 0 })
    );
}

#[test]
fn a_bare_graph_admits_no_params() {
    let (cache, instances) = world();
    let graph = ManifestGraph {
        nodes: vec![deposit_param(ALICE, 0)],
    };
    assert_eq!(
        admit(&graph, &cache, &instances, &TestHasher),
        Err(AdmissionError::UnboundParam { node: 0, param: 0 })
    );
}

#[test]
fn fresh_keys_root_at_the_envelope_identity() {
    // Two envelopes carrying the same tree but different identities mint
    // different fresh keys: the identity, not the tree, roots the
    // derivation.
    let (cache, instances) = world();
    let tree = composed_tree(100);
    let identities = [
        tree.hash(&TestHasher),
        ManifestHash(TestHasher.hash(b"envelope", &[b"other"])),
    ];
    let admitted: Vec<_> = identities
        .iter()
        .map(|identity| admit_tree(&tree, *identity, &cache, &instances, &TestHasher).unwrap())
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
fn the_nullifier_role_stays_off_stdlib_roles() {
    assert!(NULLIFIER_ROLE > RoleId(0x00FF), "reserved role space");
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
        producer: 1,
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
        producer: 1,
        output: 0,
    };
    assert_ne!(tree.hash(&TestHasher), rebound_subintent.hash(&TestHasher));
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
        let (cache, instances) = world();
        let mut tree = composed_tree(100);
        let binding = YieldBinding { intent, edge: EdgeRef { producer, output } };
        if on_subintent {
            tree.subintents[0].bindings[0] = binding;
        } else {
            tree.root_bindings[0] = binding;
        }
        let identity = tree.hash(&TestHasher);
        let first = admit_tree(&tree, identity, &cache, &instances, &TestHasher);
        let second = admit_tree(&tree, identity, &cache, &instances, &TestHasher);
        assert_eq!(first, second);
    }
}
