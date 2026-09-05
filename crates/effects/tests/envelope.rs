//! Envelope tree admission: composed intents flatten deterministically
//! over the sockets they declare, the nullifier vocabulary derives
//! canonical addresses, and every malformed composition rejects exactly.

use std::collections::BTreeSet;

use hyperscale_hbor::from_slice;
use hyperscale_vm_effects::{
    AdmissionError, AdmittedTree, Binding, Bounds, ChainRecords, Claim, ClaimCell, Constraint,
    CrossingCell, CrossingSite, ESCROW_RECORD_SLOT, EdgeContent, EdgeRef, EnvelopeTree, GraphArg,
    GraphNode, Hash32, Hasher, InstanceMeta, IntentDecl, IntentHeader, MAX_SOCKETS,
    MAX_VALUE_DEPTH, ManifestGraph, ManifestHash, NULLIFIER_SLOT, NodeInput, PackageHash,
    PrefixShardResolver, Records, ResourceKind, ShardResolver, Socket, Subintent, SubintentHash,
    TestHasher, Value, admit, admit_tree, bucketed_child_key, child_key, escrow_claim_key,
    escrow_record_key, explain_admission_tree, nullifier_key, route_tree,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    Address, CallTarget, ESCROW_GRACE_MS, Effect, EffectTarget, MAX_SUBINTENTS, Mode, Moves,
    NetworkId, PrincipalAddr, ResourceAddr, SWEEP_BUCKET_SHIFT, SweepBucket, TxHash,
};
use proptest::prelude::{any, proptest};

/// Any expiry; what these assertions turn on is that it is covered.
const EXPIRY_MS: u64 = 1_000_000;

/// Any network; these tests only need every intent to name the same one.
const TEST_NETWORK: NetworkId = NetworkId(242);

/// Any window; these tests never validate one against a clock.
const TEST_HEADER: IntentHeader = IntentHeader {
    network: TEST_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

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
    GraphNode::new(target, "deposit", vec![GraphArg::Socket(param)])
}

/// The two-signer composition: the root withdraws X and deposits the
/// yielded Y; the subintent withdraws Y and deposits the yielded X.
fn composed_tree(pay: u128) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            header: TEST_HEADER,
            graph: ManifestGraph {
                nodes: vec![
                    authorize(ALICE),
                    withdraw(ALICE, RES_X, pay),
                    deposit_param(ALICE, 0),
                ],
            },
            sockets: vec![Socket::Value {
                resource: RES_Y,
                constraints: vec![Constraint::MinAmount(10)],
            }],
        },
        root_bindings: vec![Binding::Value {
            intent: 1,
            edge: EdgeRef {
                producer: 1,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                header: TEST_HEADER,
                graph: ManifestGraph {
                    nodes: vec![
                        authorize(BOB),
                        withdraw(BOB, RES_Y, 10),
                        deposit_param(BOB, 0),
                    ],
                },
                sockets: vec![Socket::Value {
                    resource: RES_X,
                    constraints: vec![Constraint::MinAmount(100)],
                }],
            },
            signer: BOB,
            bindings: vec![Binding::Value {
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

/// A refusal placed by flattened node index is explained at the call
/// the interleave put there — not the call sitting at that index in
/// concatenation order.
///
/// The root's only node waits on a socket the subintent fills, so the
/// emission order leads with the subintent's nodes: flattened node 0 is
/// the subintent's sign-in, while concatenation would call it the root's
/// deposit. The refusal is planted on the sign-in, and the explanation
/// must name it.
#[test]
fn a_tree_refusal_is_explained_at_the_interleaved_node() {
    let broken_authorize = GraphNode::signed(
        BOB,
        "authorize",
        // One argument to a method declaring none: an arity refusal at
        // whatever flattened index this node is emitted at — which is 0,
        // since the root's node cannot go first.
        vec![GraphArg::Literal(Value::U64(7))],
    );
    let tree = EnvelopeTree {
        root: IntentDecl {
            header: TEST_HEADER,
            graph: ManifestGraph {
                nodes: vec![deposit_param(ALICE, 0)],
            },
            sockets: vec![Socket::Value {
                resource: RES_X,
                constraints: vec![],
            }],
        },
        root_bindings: vec![Binding::Value {
            intent: 1,
            edge: EdgeRef {
                producer: 1,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                header: TEST_HEADER,
                graph: ManifestGraph {
                    nodes: vec![broken_authorize, withdraw(BOB, RES_X, 5)],
                },
                sockets: vec![],
            },
            signer: BOB,
            bindings: vec![],
        }],
        instances: Vec::new(),
        resources: Vec::new(),
    };
    let chain = world();
    let refusal = admit_composed(&tree).expect_err("one argument to a method declaring none");
    assert!(matches!(
        refusal,
        AdmissionError::ArityMismatch { node: 0, .. }
    ));
    let told = explain_admission_tree(&tree, &chain, &refusal);
    // The call at flattened node 0 is the subintent's sign-in; the
    // node at index 0 of the concatenation is the root's deposit, and
    // naming it would send the composer to the one call that is fine.
    assert!(told.contains("authorize"), "{told}");
    assert!(!told.contains("deposit"), "{told}");
}

/// A socket filled from the other channel is refused as exactly that,
/// in both directions.
///
/// The wrong half used to fall out of downstream destructures as
/// whichever verdict happened to catch it — "shaped for authority" over
/// a socket declared value, "not declared" over one that is — each
/// sending the composer to the wrong fix. The kind check at the
/// bindings is what gives the mismatch its one honest name.
#[test]
fn a_socket_filled_from_the_other_channel_names_the_mismatch() {
    // A value socket filled with a proof.
    let mut tree = composed_tree(100);
    tree.root_bindings[0] = Binding::Authority {
        intent: 1,
        producer: 0,
    };
    assert_eq!(
        admit_composed(&tree).expect_err("a proof does not fill a value socket"),
        AdmissionError::SocketKindMismatch {
            intent: 0,
            socket: 0,
            declared: "value",
            offered: "a proof",
        }
    );

    // An authority socket filled with an edge.
    let mut tree = composed_tree(100);
    tree.root.sockets[0] = Socket::Authority(Claim::of_subject(BOB));
    assert_eq!(
        admit_composed(&tree).expect_err("an edge does not fill an authority socket"),
        AdmissionError::SocketKindMismatch {
            intent: 0,
            socket: 0,
            declared: "authority",
            offered: "an edge",
        }
    );
}

#[test]
fn a_composed_tree_flattens_deterministically() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).unwrap();
    let manifest = admitted.admitted.manifest();

    // Root nodes lead where ready, sockets interleave the rest: each
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
        nullifier_key(&TestHasher, BOB, record.subintent, record.expiry_ms)
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
        mode: Mode::Write { moves: Moves::Both },
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
        nullifier_key(&TestHasher, ALICE, hash, EXPIRY_MS),
        nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS)
    );
    // The nullifier is a bucketed child key under the reserved role,
    // over the subintent and the moment the record stops being owed.
    assert_eq!(
        nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS),
        bucketed_child_key(
            &TestHasher,
            BOB,
            NULLIFIER_SLOT,
            SweepBucket::of(EXPIRY_MS),
            &[hash.0.0.to_vec(), EXPIRY_MS.to_le_bytes().to_vec()]
        )
    );
    // And the expiry is part of the identity, not only of the value: a
    // spend claiming a longer life names a cell its declaration does not.
    assert_ne!(
        nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS),
        nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS + 1)
    );
}

#[test]
fn a_nullifier_leads_with_the_bucket_its_expiry_falls_in() {
    let hash = composed_tree(100).subintents[0].decl.hash(&TestHasher);
    let key = nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS);
    assert_eq!(
        SweepBucket::claimed_by(key.local),
        SweepBucket::of(EXPIRY_MS)
    );

    // A whole bucket apart, the leaf keys order the way the expiries do,
    // which is what lets a sweep walk one signer's bucket as a range.
    let later = EXPIRY_MS + (1 << SWEEP_BUCKET_SHIFT);
    let later_key = nullifier_key(&TestHasher, BOB, hash, later);
    assert_ne!(
        SweepBucket::claimed_by(later_key.local),
        SweepBucket::of(EXPIRY_MS)
    );
    assert!(key.to_bytes() < later_key.to_bytes());

    // Within a bucket the body decides, so two lives one millisecond
    // apart are still two cells.
    let nudged = nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS + 1);
    assert_eq!(
        SweepBucket::claimed_by(nudged.local),
        SweepBucket::of(EXPIRY_MS)
    );
    assert_ne!(key, nudged);
}

/// A node's origin is the intent its own signer signed and its place
/// inside it — never its place in the flattened order, which is the
/// interleave the composition chose.
///
/// The two genuinely differ here: Alice's deposit and Bob's are manifest
/// nodes 4 and 5 and are both the third node of their own intent, so a
/// derivation reading the flattened index would give one party's cell a
/// number the other party's composition moved.
#[test]
fn an_origin_names_the_intent_its_node_signed() {
    let tree = composed_tree(100);
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(&tree, ALICE, identity, &world(), &TestHasher).expect("admits");
    let root = tree.root.hash(&TestHasher);
    let bob = tree.subintents[0].decl.hash(&TestHasher);

    let origins: Vec<(SubintentHash, u32)> = admitted
        .admitted
        .origins()
        .iter()
        .map(|origin| (origin.intent, origin.local))
        .collect();
    assert_eq!(
        origins,
        vec![
            (root, 0),
            (root, 1),
            (bob, 0),
            (bob, 1),
            (root, 2),
            (bob, 2),
        ],
    );
    // And each carries its own intent's horizon: the window that
    // intent's signer signed plus the escrow grace, which outlives the
    // nullifier's by the room a lapsed crossing's reclaim needs.
    for origin in admitted.admitted.origins() {
        assert_eq!(
            origin.expiry_ms,
            TEST_HEADER.validity_end_ms + ESCROW_GRACE_MS,
        );
    }
}

/// An escrow key is fixed by what its node's own signer signed, so a
/// composer rearranging everything around a bound subintent cannot move
/// the cells that subintent's nodes write.
///
/// This is the whole of D24 and the reason the family may take the
/// bucketed form at all: keyed by the transaction, both halves of a
/// collision would be material the composer chose, and the bound that
/// matters would drop from a second preimage to a birthday.
#[test]
fn an_escrow_key_is_fixed_by_the_intent_its_node_signed() {
    // Two compositions of one subintent, and the composer moved
    // everything it controls: what the root pays, and the root's own
    // window — which is the transaction's window, since every intent's
    // intersects into it.
    let first = composed_tree(100);
    let mut second = composed_tree(120);
    second.root.header.validity_end_ms += 60_000;
    assert_ne!(
        first.hash(&TestHasher),
        second.hash(&TestHasher),
        "the composer has to have moved the transaction, or this proves nothing",
    );

    let bob = first.subintents[0].decl.hash(&TestHasher);
    assert_eq!(bob, second.subintents[0].decl.hash(&TestHasher));

    // The material an escrow key is made of is what admission hands the
    // node, so the keys are derived from that and not from a figure this
    // test picked — a fixed expiry here would pass whatever the
    // derivation sourced it from.
    let origin_of = |tree: &EnvelopeTree| {
        let identity = tree.hash(&TestHasher);
        let admitted = admit_tree(tree, ALICE, identity, &world(), &TestHasher).expect("admits");
        admitted.admitted.origins()[3]
    };
    let (one, other) = (origin_of(&first), origin_of(&second));
    assert_eq!(one, other);
    assert_eq!(one.intent, bob);
    assert_eq!(
        escrow_record_key(&TestHasher, BOB, one.intent, one.local, 0),
        escrow_record_key(&TestHasher, BOB, other.intent, other.local, 0),
    );

    // The root's own nodes moved with the root's window, which is the
    // same rule read from the other side: the party whose signature
    // fixes the window is the party whose cells it keys.
    let root_of = |tree: &EnvelopeTree| {
        let identity = tree.hash(&TestHasher);
        let admitted = admit_tree(tree, ALICE, identity, &world(), &TestHasher).expect("admits");
        admitted.admitted.origins()[1]
    };
    assert_ne!(root_of(&first).expiry_ms, root_of(&second).expiry_ms);
}

/// The material separates every edge of every node of every intent, and
/// the role separates a record from the claim that takes it.
#[test]
fn an_escrow_key_separates_what_it_names() {
    let bob = composed_tree(100).subintents[0].decl.hash(&TestHasher);
    let key = escrow_record_key(&TestHasher, BOB, bob, 1, 0);

    // A record and its own claim share every part but the role, and the
    // two shards writing them never consult each other — so aliasing
    // here would let a claim read as the record it claims.
    assert_ne!(
        key,
        escrow_claim_key(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS)
    );
    // The owner is what distinguishes two consumers of one output.
    assert_ne!(key, escrow_record_key(&TestHasher, ALICE, bob, 1, 0));
    // A different node of the same intent, and a different output of the
    // same node.
    assert_ne!(key, escrow_record_key(&TestHasher, BOB, bob, 2, 0));
    assert_ne!(key, escrow_record_key(&TestHasher, BOB, bob, 1, 1));
    assert_eq!(key.owner, BOB.address());
    assert_eq!(
        key,
        child_key(
            &TestHasher,
            BOB,
            ESCROW_RECORD_SLOT,
            &[
                bob.0.0.to_vec(),
                1u32.to_le_bytes().to_vec(),
                0u32.to_le_bytes().to_vec(),
            ],
        ),
    );
}

/// A claim leads with the bucket its expiry falls in, so a sweep walks
/// one owner's cells for one bucket as a range — the property the
/// nullifier has, asserted here because the sweep asks the key rather
/// than the family.
///
/// A record does not, and that is the point: it is a balance, retired
/// by whoever consumes it, and a key that led with a bucket would be a
/// key a sweep could find.
#[test]
fn a_claim_leads_with_its_bucket_and_a_record_does_not() {
    let bob = composed_tree(100).subintents[0].decl.hash(&TestHasher);
    let claim = escrow_claim_key(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS);
    assert_eq!(
        SweepBucket::claimed_by(claim.local),
        SweepBucket::of(EXPIRY_MS),
    );

    let later = EXPIRY_MS + (1 << SWEEP_BUCKET_SHIFT);
    let later_claim = escrow_claim_key(&TestHasher, BOB, bob, 1, 0, later);
    assert!(claim.to_bytes() < later_claim.to_bytes());

    // A record's key does not move with the expiry at all: it names the
    // edge and nothing about when the edge stops being owed.
    assert_eq!(
        escrow_record_key(&TestHasher, BOB, bob, 1, 0),
        escrow_record_key(&TestHasher, BOB, bob, 1, 0),
    );
}

/// A crossing cell says what left, on which edge, when it stops being
/// claimable and which transaction issued it — so a reclaim reads the
/// leaf and nothing else, holding no transaction body and no window of
/// them. A successor inherits the prefix and its cells and has all of it.
#[test]
fn a_crossing_cell_carries_what_a_reclaim_needs() {
    let bob = composed_tree(100).subintents[0].decl.hash(&TestHasher);
    let cell = CrossingCell {
        resource: RES_X,
        amount: 500,
        intent: bob,
        local: 1,
        output: 0,
        expiry_ms: EXPIRY_MS,
        tx: TxHash(Hash32([9; 32])),
        origin: None,
    };
    let decoded: CrossingCell = from_slice(&cell.to_bytes()).expect("a crossing cell decodes");
    assert_eq!(decoded, cell);
    assert_eq!(CrossingCell::from_bytes(&cell.to_bytes()), Some(cell));
    assert_eq!(CrossingCell::from_bytes(b"not a record"), None);
    // A site built for this edge names the record; one built for another
    // edge does not, which is what keeps a reclaim from crediting off a
    // record written for a different crossing.
    assert!(CrossingSite::claim(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS).names(&decoded));
    assert!(!CrossingSite::claim(&TestHasher, BOB, bob, 2, 0, EXPIRY_MS).names(&decoded));
    assert!(CrossingSite::claim(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS + 1).names(&decoded));
    // The value re-derives the key, which is what lets a reader holding
    // the leaf tell that it is a record — and it re-derives the claim
    // key beside it, which is what a reclaim checks the crossing was
    // never taken against.
    assert_eq!(
        escrow_record_key(
            &TestHasher,
            BOB,
            decoded.intent,
            decoded.local,
            decoded.output
        ),
        escrow_record_key(&TestHasher, BOB, bob, 1, 0),
    );
    assert_eq!(
        escrow_claim_key(
            &TestHasher,
            BOB,
            decoded.intent,
            decoded.local,
            decoded.output,
            decoded.expiry_ms
        ),
        escrow_claim_key(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS),
    );

    // The claim beside it names the transaction that took the crossing
    // and the edge it took, so it re-derives its own key as the record
    // does — which is what makes the pair sweepable, not the record
    // alone.
    let claim = CrossingSite::claim(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS)
        .claimed_by(TxHash(Hash32([7; 32])));
    let decoded: ClaimCell = from_slice(&claim.to_bytes()).expect("a claim cell decodes");
    assert_eq!(decoded, claim);
    assert_eq!(decoded.tx, TxHash(Hash32([7; 32])));
    assert_eq!(
        escrow_claim_key(
            &TestHasher,
            BOB,
            decoded.intent,
            decoded.local,
            decoded.output,
            decoded.expiry_ms,
        ),
        CrossingSite::claim(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS).key(),
    );
}

#[test]
fn an_absurd_expiry_buckets_high_rather_than_wrapping() {
    // The bucket is signer-chosen content until a window check refuses
    // it, so the layout has to survive `u64::MAX`. Saturating puts the
    // cell above every frontier — unsweepable, never below one that has
    // already passed.
    assert_eq!(SweepBucket::of(u64::MAX), SweepBucket(u32::MAX));
    assert!(SweepBucket::of(u64::MAX) > SweepBucket::of(EXPIRY_MS));
}

#[test]
fn the_declaration_hash_covers_params_and_constraints() {
    let decl = composed_tree(100).subintents[0].decl.clone();
    let mut reconstrained = decl.clone();
    reconstrained.sockets[0] = Socket::Value {
        resource: RES_X,
        constraints: vec![Constraint::MinAmount(101)],
    };
    assert_ne!(decl.hash(&TestHasher), reconstrained.hash(&TestHasher));
    let mut retyped = decl.clone();
    retyped.sockets[0] = Socket::Value {
        resource: RES_Y,
        constraints: Vec::new(),
    };
    assert_ne!(decl.hash(&TestHasher), retyped.hash(&TestHasher));
}

#[test]
fn the_declaration_hash_covers_every_term_of_the_header() {
    // The header is what the intent is admissible under, and a signer
    // signs it with the rest. Two offers alike but for the network they
    // stand on, or the window they stand in, are two identities — and so
    // two nullifiers, which is what stops one signature answering for
    // both.
    let decl = composed_tree(100).subintents[0].decl.clone();

    let mut elsewhere = decl.clone();
    elsewhere.header.network = NetworkId(1);
    assert_ne!(decl.hash(&TestHasher), elsewhere.hash(&TestHasher));

    let mut later = decl.clone();
    later.header.validity_start_ms += 1;
    assert_ne!(decl.hash(&TestHasher), later.hash(&TestHasher));

    let mut longer = decl.clone();
    longer.header.validity_end_ms += 1;
    assert_ne!(decl.hash(&TestHasher), longer.hash(&TestHasher));

    // And the term that exists for no other purpose: two offers alike in
    // every other way are two declarations, two identities, and so two
    // nullifiers — which is what lets one signer stand behind the same
    // offer twice without the second reading as the first already spent.
    let mut again = decl.clone();
    again.header.discriminator += 1;
    let (first, second) = (decl.hash(&TestHasher), again.hash(&TestHasher));
    assert_ne!(first, second);
    assert_ne!(
        nullifier_key(&TestHasher, BOB, first, EXPIRY_MS),
        nullifier_key(&TestHasher, BOB, second, EXPIRY_MS)
    );
}

/// The same binding, naming another node of the same intent.
const fn rebind(binding: Binding, producer: u32) -> Binding {
    Binding::Value {
        intent: binding.intent(),
        edge: EdgeRef {
            producer,
            output: 0,
        },
    }
}

#[test]
fn mutual_sockets_with_no_order_are_a_cycle() {
    // Each intent's only node consumes what the other exports; neither
    // can produce first.
    let mut tree = composed_tree(100);
    tree.root.graph.nodes = vec![deposit_param(ALICE, 0)];
    tree.subintents[0].decl.graph.nodes = vec![deposit_param(BOB, 0)];
    tree.root_bindings[0] = rebind(tree.root_bindings[0], 0);
    tree.subintents[0].bindings[0] = rebind(tree.subintents[0].bindings[0], 0);
    assert_eq!(admit_composed(&tree), Err(AdmissionError::CyclicSockets));
}

#[test]
fn what_fills_a_socket_must_match_the_declared_resource() {
    let mut tree = composed_tree(100);
    tree.subintents[0].decl.sockets[0] = Socket::Value {
        resource: RES_Y,
        constraints: Vec::new(),
    };
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::SocketResourceMismatch {
            intent: 1,
            socket: 0
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
fn an_edge_filling_a_socket_is_judged_by_its_kind() {
    let nf_tree = |consumer: GraphNode| EnvelopeTree {
        root: IntentDecl {
            header: TEST_HEADER,
            graph: ManifestGraph {
                nodes: vec![authorize(ALICE), withdraw(ALICE, RES_X, 100), consumer],
            },
            sockets: vec![Socket::Value {
                resource: RES_Y,
                constraints: vec![],
            }],
        },
        root_bindings: vec![Binding::Value {
            intent: 1,
            edge: EdgeRef {
                producer: 1,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                header: TEST_HEADER,
                graph: ManifestGraph {
                    nodes: vec![
                        authorize(BOB),
                        withdraw_nf(BOB, RES_Y, 7),
                        deposit_param(BOB, 0),
                    ],
                },
                sockets: vec![Socket::Value {
                    resource: RES_X,
                    constraints: vec![],
                }],
            },
            signer: BOB,
            bindings: vec![Binding::Value {
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
        vec![GraphArg::Socket(0)],
    ));
    admit_composed(&right).expect("an NF yield binds an NF parameter");

    // And a fungible yield into `deposit-nf` refuses the other way.
    let mut crossed = composed_tree(100);
    crossed.root.graph.nodes[2] = GraphNode::new(ALICE, "deposit-nf", vec![GraphArg::Socket(0)]);
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
        Err(AdmissionError::UnconsumedSocket {
            intent: 1,
            socket: 0
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
        Err(AdmissionError::SocketReused {
            intent: 1,
            socket: 0
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
    dangling.root_bindings[0] = Binding::Value {
        intent: 7,
        edge: EdgeRef {
            producer: 0,
            output: 0,
        },
    };
    assert_eq!(
        admit_composed(&dangling),
        Err(AdmissionError::UnknownBinding {
            intent: 0,
            socket: 0
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
fn an_intent_cannot_declare_unbounded_sockets() {
    // The socket count bounds the binding vector, and both index by
    // `u32` — so the cap is what makes those positions expressible by
    // construction rather than by hope.
    let mut tree = composed_tree(100);
    let socket = tree.subintents[0].decl.sockets[0].clone();
    let binding = tree.subintents[0].bindings[0];
    for _ in 0..MAX_SOCKETS {
        tree.subintents[0].decl.sockets.push(socket.clone());
        tree.subintents[0].bindings.push(binding);
    }
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::TooManySockets { intent: 1 })
    );
}

#[test]
fn a_socket_cannot_fill_a_value_parameter() {
    // `withdraw(resource, amount)` takes no bucket, so filling one of
    // its parameters from a socket is a parameter defect — not the edge
    // defect the shared arity check would otherwise report.
    let mut tree = composed_tree(100);
    tree.subintents[0].decl.graph.nodes[2] = GraphNode::bearing(
        BOB,
        "withdraw",
        vec![GraphArg::Socket(0), GraphArg::Literal(Value::U128(1))],
        0,
    );
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::SocketForValueParam { node: 5, param: 0 })
    );
}

/// An authority socket passed where an argument goes is its own refusal.
///
/// The parameter is not what is wrong — `deposit` does take a bucket.
/// What is wrong is the socket: an argument takes value and a proof is
/// not value, so the fix is to present it as evidence rather than to
/// change the signature. Sharing `SocketForValueParam` with the case
/// above sent an author to the parameter, which is the one place the
/// answer is not.
#[test]
fn an_authority_socket_is_presented_not_passed() {
    let mut tree = composed_tree(100);
    tree.root.sockets = vec![Socket::Authority(Claim::of_subject(BOB.address()))];
    tree.root_bindings = vec![Binding::Authority {
        intent: 1,
        producer: 0,
    }];
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::AuthoritySocketAsArgument {
            node: 3,
            param: 0,
            socket: 0,
        })
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
        Err(AdmissionError::UnknownSocket {
            intent: 0,
            node: 0,
            socket: 0
        })
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
    rebound.root_bindings[0] = rebind(rebound.root_bindings[0], 2);
    assert_ne!(tree.hash(&TestHasher), rebound.hash(&TestHasher));
    assert_eq!(
        tree.subintents[0].decl.hash(&TestHasher),
        rebound.subintents[0].decl.hash(&TestHasher)
    );

    let mut resigned = tree.clone();
    resigned.subintents[0].signer = ALICE;
    assert_ne!(tree.hash(&TestHasher), resigned.hash(&TestHasher));

    let mut rebound_subintent = tree.clone();
    rebound_subintent.subintents[0].bindings[0] =
        rebind(rebound_subintent.subintents[0].bindings[0], 2);
    assert_ne!(tree.hash(&TestHasher), rebound_subintent.hash(&TestHasher));

    // Every field of a binding, and the count of them: bindings encode to
    // fixed-width records concatenated into one hashed part, so a field
    // the encoding dropped or a list length it did not frame would both
    // read as the same composition.
    let mut retargeted = tree.clone();
    retargeted.root_bindings[0] = Binding::Value {
        intent: retargeted.root_bindings[0].intent().wrapping_add(1),
        edge: EdgeRef {
            producer: retargeted.root_bindings[0].producer(),
            output: 0,
        },
    };
    assert_ne!(tree.hash(&TestHasher), retargeted.hash(&TestHasher));

    let mut extended = tree.clone();
    let repeated = extended.root_bindings[0];
    extended.root_bindings.push(repeated);
    assert_ne!(tree.hash(&TestHasher), extended.hash(&TestHasher));

    let mut resliced = tree.clone();
    resliced.root_bindings[0] = Binding::Value {
        intent: resliced.root_bindings[0].intent(),
        edge: EdgeRef {
            producer: resliced.root_bindings[0].producer(),
            output: 1,
        },
    };
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
        let binding = Binding::Value {
        intent, edge: EdgeRef { producer, output } };
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
            header: TEST_HEADER,
            graph: ManifestGraph {
                nodes: vec![GraphNode {
                    target: round.into(),
                    method: method.into(),
                    args,
                    evidence: BTreeSet::new(),
                }],
            },
            sockets: Vec::new(),
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
            "settle",
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
    let bare = calling("settle", vec![GraphArg::Literal(Value::U64(8))], Vec::new());
    assert!(admit_with(&bare, &sealed).is_ok());

    // A record presented beside a component the chain already holds is
    // refused on the same terms — the chain's answer is the one that
    // stands, so a caller's copy is never consulted.
    assert!(matches!(
        admit_with(&drawn, &sealed),
        Err(AdmissionError::PresentedForCall { node: 0, .. })
    ));
}
