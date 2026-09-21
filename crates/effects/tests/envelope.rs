//! Tree admission: intents composing intents flatten deterministically
//! over the interfaces they declare, the nullifier vocabulary derives
//! canonical addresses, scope is judged from signed content alone, and
//! every malformed tree rejects exactly.

use std::collections::BTreeSet;

use hyperscale_hbor::{Capped, from_slice_with_depth};
mod common;

use common::admit_leaf;
use hyperscale_vm_effects::vocabulary::AUTH;
use hyperscale_vm_effects::{
    AdmissionError, Admitted, Binding, Bounds, ChainRecords, Claim, ClaimRef, Constraint,
    CrossingCell, CrossingSite, ESCROW_RECORD_SLOT, EdgeContent, EdgeRef, GiveRef, GraphArg,
    GraphNode, Hash32, Hasher, InstanceMeta, Intent, IntentHash, IntentHeader, IntentRecord,
    IntentTree, JudgedLeaf, Kind, MAX_ACCOUNTS, MAX_SOCKETS, MAX_TREE_DEPTH, MAX_VALUE_DEPTH,
    ManifestGraph, ManifestHash, Marked, Marker, Member, NULLIFIER_SLOT, NodeInput,
    OWED_CLAIM_CELL_BYTES, OwedClaim, PackageHash, PrefixShardResolver, Records, ResourceKind,
    Rule, ShardResolver, SignedIntent, Socket, TREE_WIRE_DEPTH, Terms, TestHasher, TreeDecodeError,
    Value, ValueRef, admit_tree, bucketed_child_key, child_key, decode_tree, encode_tree,
    escrow_claim_key, escrow_record_key, explain_admission_tree, nullifier_key, owed_claim_key,
    per_shard,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    ARTIFACT_GRACE_MS, Address, COMMITTED_GRACE_MS, CROSSING_GRACE_MS, CallTarget, Effect,
    EffectTarget, MAX_ATTESTATIONS, MAX_INTENTS, MAX_MANIFEST_NODES, Mode, Moves, NetworkId,
    PrincipalAddr, ResourceAddr, SWEEP_BUCKET_SHIFT, SweepBucket, TxHash,
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
const CAROL: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const THIEF: PrincipalAddr = PrincipalAddr::new([0x66; 31]);
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

fn withdraw(account: PrincipalAddr, resource: impl Into<Address>, amount: u128) -> GraphNode {
    GraphNode::signed(
        account,
        account,
        "withdraw",
        vec![
            GraphArg::Literal(Value::Address(resource.into())),
            GraphArg::Literal(Value::U128(amount)),
        ],
    )
}

/// A deposit consuming the intent's own `socket`.
fn deposit_param(target: impl Into<CallTarget>, socket: u32) -> GraphNode {
    GraphNode::new(target, "deposit", vec![GraphArg::socket(socket)])
}

/// A deposit consuming an edge of the intent's own graph.
fn deposit_edge(target: impl Into<CallTarget>, producer: u32) -> GraphNode {
    GraphNode::new(
        target,
        "deposit",
        vec![GraphArg::edge(edge(producer, 0), Vec::new())],
    )
}

/// A deposit consuming a member's give, under `constraints`.
fn deposit_give(
    target: impl Into<CallTarget>,
    member: u32,
    give: u32,
    constraints: Vec<Constraint>,
) -> GraphNode {
    GraphNode::new(
        target,
        "deposit",
        vec![GraphArg::give(GiveRef { member, give }, constraints)],
    )
}

const fn edge(producer: u32, output: u32) -> EdgeRef {
    EdgeRef { producer, output }
}

const fn give(member: u32, give: u32) -> GiveRef {
    GiveRef { member, give }
}

/// An intent acting as `account`: its graph, its sockets, its gives, no
/// members yet.
fn intent(
    account: PrincipalAddr,
    nodes: Vec<GraphNode>,
    sockets: Vec<Socket>,
    gives: Vec<ValueRef>,
) -> Intent {
    Intent {
        sockets: Capped::new(sockets).unwrap(),
        gives: Capped::new(gives).unwrap(),
        ..Intent::leaf(
            TEST_HEADER,
            account,
            ManifestGraph {
                nodes: Capped::new(nodes).unwrap(),
            },
        )
    }
}

/// `composer` composing `members`, each with the wiring that fills it.
fn compose(mut composer: Intent, members: Vec<(Intent, Vec<Binding>)>) -> Intent {
    composer.members = members
        .into_iter()
        .map(|(intent, wiring)| Member {
            signed: SignedIntent::unsigned(intent),
            wiring: Capped::new(wiring).unwrap(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    composer
}

const fn tree(root: Intent) -> IntentTree {
    IntentTree::of_one(root)
}

/// Bob's offer: withdraw Y, bank whatever X arrives, at least a hundred
/// of it.
fn bobs_offer() -> Intent {
    intent(
        BOB,
        vec![withdraw(BOB, RES_Y, 10), deposit_param(BOB, 0)],
        vec![Socket::Value {
            resource: RES_X,
            constraints: vec![Constraint::MinAmount(100)],
        }],
        vec![ValueRef::Edge(edge(0, 0))],
    )
}

/// The two-signer swap: the root withdraws X and banks the Y Bob gives;
/// Bob withdraws Y and banks the X the root wires to him.
fn composed_tree(pay: u128) -> IntentTree {
    let root = intent(
        ALICE,
        vec![
            withdraw(ALICE, RES_X, pay),
            deposit_give(ALICE, 0, 0, vec![Constraint::MinAmount(10)]),
        ],
        Vec::new(),
        Vec::new(),
    );
    tree(compose(
        root,
        vec![(
            bobs_offer(),
            vec![Binding::Value(ValueRef::Edge(edge(0, 0)))],
        )],
    ))
}

fn admit_composed(tree: &IntentTree) -> Result<Admitted, AdmissionError> {
    let chain = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, identity, &chain, &TestHasher)
}

/// The flattened calls, as target and method.
fn shape(admitted: &Admitted) -> Vec<(Address, String)> {
    admitted
        .manifest()
        .nodes
        .iter()
        .map(|node| (node.target, node.method.clone()))
        .collect::<Vec<_>>()
}

/// An intent acts as an account and is attested by keys, and the two are
/// separate. A key deriving no part of the account it acts for is
/// admissible here — nothing at this stage could judge it, since whether
/// the account admits that key is state only the account's own cell
/// holds. What stands between the two is the condition injected beside
/// it, which that account's shard answers before any body runs.
#[test]
fn an_intent_is_attested_by_keys_the_account_need_not_derive() {
    let mut tree = composed_tree(100);
    tree.root.attested_by = Capped::new(vec![BOB]).unwrap();
    tree.root.members[0].signed.intent.attested_by = Capped::new(vec![ALICE]).unwrap();
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(&tree, identity, &world(), &TestHasher)
        .expect("a key that derives neither account still admits");

    for (account, key) in [(ALICE, BOB), (BOB, ALICE)] {
        let cell = child_key(&TestHasher, account.address(), AUTH, &[]);
        assert!(
            admitted
                .declaration()
                .conditions
                .iter()
                .any(|condition| matches!(
                    &condition.rule,
                    Rule::Require(JudgedLeaf::Signed { cell: at, keys })
                        if *at == cell && keys.as_slice() == [Claim::of_subject(key.address())]
                )),
            "the sign-in names the account's own cell and the key that attested it",
        );
    }
}

/// The attesting set is signed content with a shape: at least one
/// principal, at most the cap, none twice. Two attestations by one
/// principal would be one key counted twice against a threshold.
#[test]
fn an_attesting_set_is_non_empty_bounded_and_repeats_nobody() {
    let mut nobody = composed_tree(100);
    nobody.root.members[0].signed.intent.attested_by.clear();
    assert_eq!(
        admit_composed(&nobody),
        Err(AdmissionError::NoAttester { intent: 1 })
    );

    let mut twice = composed_tree(100);
    twice.root.attested_by = Capped::new(vec![ALICE, ALICE]).unwrap();
    assert_eq!(
        admit_composed(&twice),
        Err(AdmissionError::DuplicateAttester { intent: 0 })
    );

    // One attester past the cap is not a set the type can hold, so
    // admission never sees one.
    assert!(
        Capped::<Vec<PrincipalAddr>, MAX_ATTESTATIONS>::new(
            (0x80u8..)
                .take(MAX_ATTESTATIONS + 1)
                .map(|byte| PrincipalAddr::new([byte; 31]))
                .collect()
        )
        .is_err()
    );

    // The set is signed content: another set is another intent, and so
    // another nullifier.
    let base = composed_tree(100).root.hash(&TestHasher);
    let mut delegated = composed_tree(100).root;
    delegated.attested_by = Capped::new(vec![BOB]).unwrap();
    assert_ne!(base, delegated.hash(&TestHasher));
}

/// An account named twice is one nullifier and one sign-in stated
/// twice, refused where a repeated attester is.
#[test]
fn an_intent_acts_as_no_account_twice() {
    let mut twice = composed_tree(100);
    twice.root.accounts = Capped::new(vec![ALICE, ALICE]).unwrap();
    assert_eq!(
        admit_composed(&twice),
        Err(AdmissionError::DuplicateAccount { intent: 0 })
    );
}

/// A refusal placed by flattened node index is explained at the call
/// the interleave put there — not the call sitting at that index in
/// concatenation order.
///
/// The root's only node takes the give Bob's intent produces, so the
/// emission order leads with Bob's nodes: flattened node 0 is his
/// withdraw, while concatenation would call it the root's deposit. The
/// refusal is planted on that withdraw, and the explanation must name
/// it.
#[test]
fn a_tree_refusal_is_explained_at_the_interleaved_node() {
    let broken_withdraw = GraphNode::signed(
        BOB,
        BOB,
        "withdraw",
        // One argument to a method declaring two: an arity refusal at
        // whatever flattened index this node is emitted at — which is 0,
        // since the root's node cannot go first.
        vec![GraphArg::Literal(Value::U64(7))],
    );
    let root = intent(
        ALICE,
        vec![deposit_give(ALICE, 0, 0, Vec::new())],
        Vec::new(),
        Vec::new(),
    );
    let bob = intent(
        BOB,
        vec![broken_withdraw, deposit_edge(BOB, 0)],
        Vec::new(),
        vec![ValueRef::Edge(edge(0, 0))],
    );
    let tree = tree(compose(root, vec![(bob, Vec::new())]));
    let chain = world();
    let refusal = admit_composed(&tree).expect_err("one argument to a method declaring two");
    assert!(matches!(
        refusal,
        AdmissionError::ArityMismatch { node: 0, .. }
    ));
    let told = explain_admission_tree(&tree, &chain, &refusal);
    assert!(told.contains("withdraw"), "{told}");
}

/// A socket filled from the other channel is refused as exactly that,
/// in both directions.
#[test]
fn a_socket_filled_from_the_other_channel_names_the_mismatch() {
    // A value socket filled with a proof.
    let mut tree = composed_tree(100);
    tree.root.members[0].wiring[0] = Binding::Authority(ClaimRef::Node(0));
    assert_eq!(
        admit_composed(&tree).expect_err("a proof does not fill a value socket"),
        AdmissionError::SocketKindMismatch {
            intent: 1,
            socket: 0,
            declared: "value",
            offered: "a proof",
        }
    );

    // An authority socket filled with an edge.
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.sockets[0] = Socket::Authority(Claim::of_subject(BOB));
    assert_eq!(
        admit_composed(&tree).expect_err("an edge does not fill an authority socket"),
        AdmissionError::SocketKindMismatch {
            intent: 1,
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
    let manifest = admitted.manifest();

    // Root nodes lead where ready, the interface interleaves the rest:
    // each intent's withdraw, then the two deposits consuming each
    // other's yields.
    assert_eq!(
        shape(&admitted),
        vec![
            (ALICE.address(), "withdraw".into()),
            (BOB.address(), "withdraw".into()),
            (ALICE.address(), "deposit".into()),
            (BOB.address(), "deposit".into()),
        ]
    );
    assert_eq!(
        manifest.nodes[2].inputs,
        vec![NodeInput::Edge {
            source: 1,
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
        manifest.nodes[3].inputs,
        vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: RES_X,
            content: EdgeContent::Fungible,
            bounds: Bounds {
                min: Some(100),
                max: None,
            },
        }]
    );

    // The nullifier record: canonical address under the account.
    let record = &admitted.intents()[1];
    assert_eq!(record.accounts().collect::<Vec<_>>(), [BOB]);
    let [nullifier] = record.nullifiers.as_slice() else {
        panic!("one account, one nullifier");
    };
    assert_eq!(
        nullifier.key,
        nullifier_key(&TestHasher, BOB, record.intent, record.expiry_ms)
    );
    assert_eq!(nullifier.key.owner, BOB);
}

/// Every intent's nullifier is written, each at its own account's shard
/// and nowhere else — the root's included, which is one intent among the
/// tree's and not a different kind of thing.
#[test]
fn routing_carries_the_nullifier_creation_write() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).unwrap();
    let routing = per_shard(&admitted, &PrefixShardResolver { bits: 8 });
    assert_eq!(admitted.intents().len(), tree.intents().len());
    let resolver = PrefixShardResolver { bits: 8 };
    let creation = |record: &IntentRecord| Effect {
        target: EffectTarget::Point(record.nullifiers[0].key),
        mode: Mode::Write { moves: Moves::Both },
    };
    let (own, offered) = (&admitted.intents()[0], &admitted.intents()[1]);
    let (alice, bob) = (
        resolver.shard_of(own.nullifiers[0].account.address()),
        resolver.shard_of(offered.nullifiers[0].account.address()),
    );
    assert_ne!(alice, bob);
    assert!(routing[&alice].contains(&creation(own)));
    assert!(routing[&bob].contains(&creation(offered)));
    assert!(!routing[&alice].contains(&creation(offered)));
    assert!(!routing[&bob].contains(&creation(own)));
}

/// Two intents acting as one account are two offers, each once-only on
/// its own: two nullifiers under one prefix, keyed by each intent's own
/// hash.
#[test]
fn two_intents_acting_as_one_account_each_nullify() {
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.accounts = Capped::new(vec![ALICE]).unwrap();
    tree.root.members[0].signed.intent.graph.nodes =
        Capped::new(vec![withdraw(ALICE, RES_Y, 10), deposit_param(ALICE, 0)]).unwrap();
    let admitted = admit_composed(&tree).expect("one account may offer twice");
    let [own, again] = admitted.intents() else {
        panic!("two intents, two records");
    };
    assert_eq!(
        (own.nullifiers[0].account, again.nullifiers[0].account),
        (ALICE, ALICE)
    );
    assert_ne!(own.intent, again.intent);
    assert_ne!(own.nullifiers[0].key, again.nullifiers[0].key);
    assert_eq!(own.nullifiers[0].key.owner, ALICE.address());
    assert_eq!(again.nullifiers[0].key.owner, ALICE.address());
}

/// An intent acting as two accounts writes two nullifiers, signs in
/// twice, and each of its withdrawals presents the account it draws
/// from and no other; an intent acting as none is refused.
#[test]
fn an_intent_acting_as_two_accounts_nullifies_and_signs_in_for_each() {
    let mut root = intent(
        ALICE,
        vec![
            withdraw(ALICE, RES_X, 5),
            deposit_edge(BOB, 0),
            withdraw(BOB, RES_Y, 5),
            deposit_edge(ALICE, 2),
        ],
        Vec::new(),
        Vec::new(),
    );
    root.accounts = Capped::new(vec![ALICE, BOB]).unwrap();
    root.attested_by = Capped::new(vec![ALICE, BOB]).unwrap();
    let tree = IntentTree::of_one(root);
    let admitted = admit_composed(&tree).expect("one intent acts as both");
    let [record] = admitted.intents() else {
        panic!("one intent");
    };
    assert_eq!(record.accounts().collect::<Vec<_>>(), [ALICE, BOB]);
    assert_eq!(record.nullifiers[0].key.owner, ALICE.address());
    assert_eq!(record.nullifiers[1].key.owner, BOB.address());
    // Each account's sign-in is its own condition, over the one
    // attesting set — here every account attesting the intent itself.
    let attesting = [Claim::of_subject(ALICE), Claim::of_subject(BOB)];
    for account in [ALICE, BOB] {
        let cell = child_key(&TestHasher, account.address(), AUTH, &[]);
        assert!(
            admitted
                .declaration()
                .conditions
                .iter()
                .any(|condition| matches!(
                    &condition.rule,
                    Rule::Require(JudgedLeaf::Signed { cell: at, keys })
                        if *at == cell && keys.as_slice() == attesting
                )),
            "each account's sign-in is its own condition",
        );
    }
    // Each withdrawal presents the account it draws from: the claim is
    // the named account's, not every account's.
    let nodes = &admitted.manifest().nodes;
    assert_eq!(nodes[0].evidence, vec![Claim::of_subject(ALICE)]);
    assert_eq!(nodes[2].evidence, vec![Claim::of_subject(BOB)]);

    let mut nobody = tree;
    nobody.root.accounts.clear();
    assert_eq!(
        admit_composed(&nobody),
        Err(AdmissionError::NoAccount { intent: 0 })
    );
}

/// An intent at the account ceiling costs one nullifier, one `auth`
/// read and one sign-in per account, and encodes; one past it is
/// refused.
#[test]
fn an_intent_at_the_account_ceiling_costs_one_cell_per_account() {
    let accounts: Vec<PrincipalAddr> = (0x80u8..)
        .take(MAX_ACCOUNTS + 1)
        .map(|byte| PrincipalAddr::new([byte; 31]))
        .collect::<Vec<_>>();
    let acting_as = |accounts: &[PrincipalAddr]| {
        let mut root = intent(
            accounts[0],
            vec![
                withdraw(accounts[0], RES_X, 5),
                deposit_edge(accounts[0], 0),
            ],
            Vec::new(),
            Vec::new(),
        );
        root.accounts = Capped::new(accounts.to_vec()).unwrap();
        tree(root)
    };

    let full = acting_as(&accounts[..MAX_ACCOUNTS]);
    let admitted = admit_composed(&full).expect("the ceiling admits");
    let [record] = admitted.intents() else {
        panic!("one intent");
    };
    assert_eq!(record.nullifiers.len(), MAX_ACCOUNTS);
    let declaration = admitted.declaration();
    let auth_cells: BTreeSet<_> = accounts[..MAX_ACCOUNTS]
        .iter()
        .map(|account| child_key(&TestHasher, account.address(), AUTH, &[]))
        .collect();
    let auth_reads = declaration
        .ordered
        .iter()
        .filter(|access| match access.effect {
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Read,
            } => auth_cells.contains(&cell),
            _ => false,
        })
        .count();
    assert_eq!(auth_reads, MAX_ACCOUNTS);
    let sign_ins = declaration
        .conditions
        .iter()
        .filter(|condition| matches!(condition.rule, Rule::Require(JudgedLeaf::Signed { .. })))
        .count();
    assert_eq!(sign_ins, MAX_ACCOUNTS);
    assert_eq!(decode_tree(&encode_tree(&full)).as_ref(), Ok(&full));

    // One account past the cap is not a list the type can hold, so
    // admission never sees one.
    assert!(Capped::<Vec<PrincipalAddr>, MAX_ACCOUNTS>::new(accounts).is_err());
}

#[test]
fn identities_differ_while_member_hashes_agree() {
    let first = composed_tree(100);
    let second = composed_tree(120);
    assert_ne!(first.hash(&TestHasher), second.hash(&TestHasher));
    assert_eq!(
        first.root.members[0].signed.intent.hash(&TestHasher),
        second.root.members[0].signed.intent.hash(&TestHasher)
    );
    // Same tree, different account: a different nullifier.
    let hash = first.root.members[0].signed.intent.hash(&TestHasher);
    assert_ne!(
        nullifier_key(&TestHasher, ALICE, hash, EXPIRY_MS),
        nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS)
    );
    // The nullifier is a bucketed child key under the reserved role,
    // over the intent and the moment the record stops being owed.
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
    let hash = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let key = nullifier_key(&TestHasher, BOB, hash, EXPIRY_MS);
    assert_eq!(
        SweepBucket::claimed_by(key.local),
        SweepBucket::of(EXPIRY_MS)
    );

    // A whole bucket apart, the leaf keys order the way the expiries do,
    // which is what lets a sweep walk one account's bucket as a range.
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
#[test]
fn an_origin_names_the_intent_its_node_signed() {
    let tree = composed_tree(100);
    let admitted = admit_composed(&tree).expect("admits");
    let root = tree.root.hash(&TestHasher);
    let bob = tree.root.members[0].signed.intent.hash(&TestHasher);

    let origins: Vec<(IntentHash, u32)> = admitted
        .origins()
        .iter()
        .map(|origin| (origin.intent, origin.local))
        .collect();
    assert_eq!(origins, vec![(root, 0), (bob, 0), (root, 1), (bob, 1)],);
    // And each carries its own intent's horizon: the window that
    // intent's signer signed plus the crossing grace, which outlives the
    // nullifier's by the span a successor needs to decide an inherited
    // record across a reshape cut.
    for origin in admitted.origins() {
        assert_eq!(
            origin.expiry_ms,
            TEST_HEADER.validity_end_ms + CROSSING_GRACE_MS,
        );
    }
    for record in admitted.intents() {
        assert_eq!(
            record.expiry_ms,
            TEST_HEADER.validity_end_ms + ARTIFACT_GRACE_MS,
            "a nullifier is answered on its own chain and takes the default grace",
        );
    }
}

/// An escrow key is fixed by what its node's own signer signed, so a
/// composer rearranging everything around a member cannot move the
/// cells that member's nodes write.
///
/// Keyed by the transaction, both halves of a collision would be
/// material the composer chose, and the bound that matters would drop
/// from a second preimage to a birthday.
#[test]
fn an_escrow_key_is_fixed_by_the_intent_its_node_signed() {
    // Two compositions of one member, and the composer moved everything
    // it controls: what the root pays, and the root's own window — which
    // is the transaction's window, since every intent's intersects into
    // it.
    let first = composed_tree(100);
    let mut second = composed_tree(120);
    second.root.header.validity_end_ms += 60_000;
    assert_ne!(
        first.hash(&TestHasher),
        second.hash(&TestHasher),
        "the composer has to have moved the transaction, or this proves nothing",
    );

    let bob = first.root.members[0].signed.intent.hash(&TestHasher);
    assert_eq!(bob, second.root.members[0].signed.intent.hash(&TestHasher));

    let origin_of =
        |tree: &IntentTree, at: usize| admit_composed(tree).expect("admits").origins()[at];
    let (one, other) = (origin_of(&first, 1), origin_of(&second, 1));
    assert_eq!(one, other);
    assert_eq!(one.intent, bob);
    assert_eq!(
        escrow_record_key(&TestHasher, BOB, one.intent, one.local, 0),
        escrow_record_key(&TestHasher, BOB, other.intent, other.local, 0),
    );

    // The root's own nodes moved with the root's window, which is the
    // same rule read from the other side: the party whose signature
    // fixes the window is the party whose cells it keys.
    assert_ne!(
        origin_of(&first, 0).expiry_ms,
        origin_of(&second, 0).expiry_ms
    );
}

/// The material separates every edge of every node of every intent, and
/// the role separates a record from the claim that takes it.
#[test]
fn an_escrow_key_separates_what_it_names() {
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let key = escrow_record_key(&TestHasher, BOB, bob, 1, 0);

    assert_ne!(
        key,
        escrow_claim_key(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS),
        "a record and its claim are two cells"
    );
    assert_ne!(
        key,
        escrow_record_key(&TestHasher, BOB, bob, 1, 1),
        "two outputs of one node are two cells"
    );
    assert_ne!(
        key,
        escrow_record_key(&TestHasher, BOB, bob, 0, 0),
        "two nodes of one intent are two cells"
    );
    let other = composed_tree(100).root.hash(&TestHasher);
    assert_ne!(
        key,
        escrow_record_key(&TestHasher, BOB, other, 1, 0),
        "two intents are two cells"
    );
    assert_ne!(
        key,
        escrow_record_key(&TestHasher, ALICE, bob, 1, 0),
        "two owners are two cells"
    );
    // The record's key is a plain child key under the reserved role over
    // the edge's material: the intent, the node and the output.
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
            ]
        )
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
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let claim = escrow_claim_key(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS);
    assert_eq!(
        SweepBucket::claimed_by(claim.local),
        SweepBucket::of(EXPIRY_MS)
    );
    let later = escrow_claim_key(
        &TestHasher,
        BOB,
        bob,
        1,
        0,
        EXPIRY_MS + (1 << SWEEP_BUCKET_SHIFT),
    );
    assert!(claim.to_bytes() < later.to_bytes());

    let record = escrow_record_key(&TestHasher, BOB, bob, 1, 0);
    assert_eq!(
        record,
        child_key(
            &TestHasher,
            BOB,
            ESCROW_RECORD_SLOT,
            &[
                bob.0.0.to_vec(),
                1u32.to_le_bytes().to_vec(),
                0u32.to_le_bytes().to_vec(),
            ]
        ),
        "a record carries no bucket"
    );
}

/// A crossing cell says what left, on which edge, when it stops being
/// claimable, which transaction issued it and which cell would say it
/// was taken — so a reclaim reads the leaf and nothing else, holding no
/// transaction body and no window of them. A successor inherits the
/// prefix and its cells and has all of it.
#[test]
fn a_crossing_cell_carries_what_a_reclaim_needs() {
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let tx = TxHash(Hash32([7; 32]));
    let site = CrossingSite::record(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS);
    let consumer = CrossingSite::claim(&TestHasher, ALICE, bob, 1, 0, EXPIRY_MS, Kind::Escrowed);
    let credit = child_key(&TestHasher, BOB, ESCROW_RECORD_SLOT, &[b"vault".to_vec()]);
    let cell = site.crossing(tx, RES_Y, 10, consumer.key(), Terms::Escrowed { credit });

    assert_eq!(cell.resource, RES_Y);
    assert_eq!(cell.amount, 10);
    assert_eq!(cell.intent, bob);
    assert_eq!((cell.local, cell.output), (1, 0));
    assert_eq!(cell.expiry_ms, EXPIRY_MS);
    assert_eq!(cell.tx, tx);
    assert_eq!(cell.consumer_claim, consumer.key());
    assert_eq!(cell.terms, Terms::Escrowed { credit });

    // The value re-derives the key, and a site built for another edge
    // does not take it.
    assert!(site.names(&cell));
    assert!(!CrossingSite::record(&TestHasher, BOB, bob, 0, 0, EXPIRY_MS).names(&cell));
    assert_eq!(
        CrossingSite::claim_on(&TestHasher, BOB, &cell).key(),
        CrossingSite::claim(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS, Kind::Escrowed).key()
    );

    // Round trip: the cell reads back as itself, and bytes that are not
    // one read back as nothing.
    assert_eq!(CrossingCell::from_bytes(&cell.to_bytes()), Some(cell));
    assert_eq!(CrossingCell::from_bytes(b"not a cell"), None);

    // The claim's value: which transaction took it, on this edge. An
    // escrowed crossing's answer is a marker, which names no record —
    // the window it is read in is what bounds it, and the producer that
    // reads it holds the record already.
    let claimed = Marker::from_bytes(&consumer.claimed_by(tx, site.key()))
        .expect("an escrowed claim is a marker");
    assert_eq!(
        claimed,
        Marker {
            tx,
            expiry_ms: EXPIRY_MS,
            marks: Marked::Claimed {
                intent: bob,
                local: 1,
                output: 0,
            },
        }
    );
    assert_eq!(claimed.key(&TestHasher, ALICE), consumer.key());
    assert_eq!(Marker::from_bytes(&claimed.to_bytes()), Some(claimed));
}

/// An owed crossing's answer is its own family: unbucketed, carrying the
/// record it answers for, and reachable by no sweep.
///
/// The two halves of why. A delivery may be admitted for as long as the
/// record stands, and this cell is the only thing refusing a second one,
/// so a clock that swept it would license the second. And the consumer
/// that wrote it has to be able to ask the producer about the record —
/// which it could not derive, the record's owner being the producing
/// node's target — so the cell states it.
#[test]
fn an_owed_claim_names_its_record_and_no_sweep_reaches_it() {
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let tx = TxHash(Hash32([9; 32]));
    let record = CrossingSite::record(&TestHasher, BOB, bob, 1, 0, EXPIRY_MS);
    let owed = CrossingSite::claim(&TestHasher, ALICE, bob, 1, 0, EXPIRY_MS, Kind::Owed);
    let escrowed = CrossingSite::claim(&TestHasher, ALICE, bob, 1, 0, EXPIRY_MS, Kind::Escrowed);
    assert_ne!(
        owed.key(),
        escrowed.key(),
        "the two answers are two families, so one cell can never stand for the other",
    );

    let claim = OwedClaim::from_bytes(&owed.claimed_by(tx, record.key()))
        .expect("an owed claim is its own value");
    assert_eq!(
        claim,
        OwedClaim {
            tx,
            intent: bob,
            local: 1,
            output: 0,
            record: record.key(),
        }
    );
    assert_eq!(claim.key(&TestHasher, ALICE), owed.key());
    assert_eq!(OwedClaim::from_bytes(&claim.to_bytes()), Some(claim));
    assert_eq!(OwedClaim::from_bytes(b"not a claim"), None);
    assert!(
        claim.to_bytes().len() <= OWED_CLAIM_CELL_BYTES as usize,
        "an owed claim encodes under the width the declaration prices it at: {} bytes",
        claim.to_bytes().len(),
    );

    // Its key carries no expiry bucket, which is what keeps every sweep
    // off it — the record's own property, for the record's own reason.
    assert_eq!(
        owed.key(),
        owed_claim_key(&TestHasher, ALICE, bob, 1, 0),
        "unbucketed, so the expiry is not in the identity at all",
    );
    assert_eq!(
        CrossingSite::claim(&TestHasher, ALICE, bob, 1, 0, EXPIRY_MS + 1, Kind::Owed).key(),
        owed.key(),
        "and so a different expiry names the same cell",
    );
}

/// A cell's life is its family's, and a writer does not get to choose
/// it: one grace serves every family but the crossing, which is the one
/// a reshape reads across a cut and so the one that has to stay readable
/// for the whole terminal evidence span.
#[test]
fn a_marker_takes_the_life_its_family_has_and_no_other() {
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let tx = TxHash(Hash32([7; 32]));
    let end = TEST_HEADER.validity_end_ms;

    let spent = Marker::of(tx, end, Marked::Spent(bob));
    assert_eq!(spent.expiry_ms, end + ARTIFACT_GRACE_MS);
    assert_eq!(
        spent.key(&TestHasher, BOB),
        nullifier_key(&TestHasher, BOB, bob, end + ARTIFACT_GRACE_MS)
    );

    let committed = Marker::of(tx, end, Marked::Committed);
    assert_eq!(committed.expiry_ms, end + COMMITTED_GRACE_MS);

    let claimed = Marker::of(
        tx,
        end,
        Marked::Claimed {
            intent: bob,
            local: 1,
            output: 0,
        },
    );
    assert_eq!(claimed.expiry_ms, end + CROSSING_GRACE_MS);
    assert_eq!(
        claimed.key(&TestHasher, ALICE),
        escrow_claim_key(&TestHasher, ALICE, bob, 1, 0, end + CROSSING_GRACE_MS)
    );
    const {
        assert!(CROSSING_GRACE_MS > ARTIFACT_GRACE_MS);
        assert!(COMMITTED_GRACE_MS > ARTIFACT_GRACE_MS);
    }
}

#[test]
fn an_absurd_expiry_buckets_high_rather_than_wrapping() {
    let bob = composed_tree(100).root.members[0]
        .signed
        .intent
        .hash(&TestHasher);
    let key = nullifier_key(&TestHasher, BOB, bob, u64::MAX);
    assert_eq!(
        SweepBucket::claimed_by(key.local),
        SweepBucket::of(u64::MAX)
    );
    let spent = Marker::of(TxHash(Hash32([7; 32])), u64::MAX, Marked::Spent(bob));
    assert_eq!(spent.expiry_ms, u64::MAX, "saturating, never wrapping");
}

#[test]
fn the_intent_hash_covers_the_interface() {
    let decl = composed_tree(100).root.members[0].signed.intent.clone();
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
    let mut regiven = decl.clone();
    regiven.gives = Capped::new(vec![ValueRef::Edge(edge(0, 1))]).unwrap();
    assert_ne!(decl.hash(&TestHasher), regiven.hash(&TestHasher));
    let mut ungiven = decl.clone();
    ungiven.gives.clear();
    assert_ne!(decl.hash(&TestHasher), ungiven.hash(&TestHasher));
}

/// The accounts, the members and the wiring are signed content of the
/// intent that states them: moving any is another intent, and so
/// another nullifier.
#[test]
fn the_intent_hash_covers_accounts_members_and_wiring() {
    let root = composed_tree(100).root;
    let base = root.hash(&TestHasher);

    let mut reacted = root.clone();
    reacted.accounts.push(BOB).unwrap();
    assert_ne!(base, reacted.hash(&TestHasher));

    let mut recomposed = root.clone();
    recomposed.members[0].signed.intent.header.discriminator += 1;
    assert_ne!(base, recomposed.hash(&TestHasher));
    let mut widened = root.clone();
    let mut another = widened.members[0].clone();
    another.signed.intent.accounts = Capped::new(vec![CAROL]).unwrap();
    widened.members.push(another).unwrap();
    assert_ne!(base, widened.hash(&TestHasher));
    let mut uncomposed = root.clone();
    uncomposed.members.clear();
    assert_ne!(base, uncomposed.hash(&TestHasher));

    let mut rewired = root.clone();
    rewired.members[0].wiring[0] = Binding::Value(ValueRef::Edge(edge(1, 0)));
    assert_ne!(base, rewired.hash(&TestHasher));
    let mut resliced = root.clone();
    resliced.members[0].wiring[0] = Binding::Value(ValueRef::Edge(edge(0, 1)));
    assert_ne!(base, resliced.hash(&TestHasher));
    let mut regranted = root.clone();
    regranted.members[0].wiring[0] = Binding::Authority(ClaimRef::Account(ALICE));
    assert_ne!(base, regranted.hash(&TestHasher));
    let mut extended = root.clone();
    extended.members[0]
        .wiring
        .push(Binding::Value(ValueRef::Edge(edge(0, 0))))
        .unwrap();
    assert_ne!(base, extended.hash(&TestHasher));
    let mut unwired = root;
    unwired.members[0].wiring.clear();
    assert_ne!(base, unwired.hash(&TestHasher));
}

#[test]
fn the_intent_hash_covers_every_term_of_the_header() {
    let decl = composed_tree(100).root.members[0].signed.intent.clone();

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

/// The tree hash covers the records, and the root's hash covers the
/// order of its members.
#[test]
fn the_tree_hash_covers_the_records_and_the_order() {
    let tree = composed_tree(100);
    let plain = tree.hash(&TestHasher);
    let mut recorded = tree.clone();
    recorded
        .instances
        .push(InstanceMeta {
            package: pkg(),
            config: Capped::new(vec![Value::U64(1)]).unwrap(),
            salt: Hash32([9; 32]),
        })
        .unwrap();
    assert_ne!(recorded.hash(&TestHasher), plain);

    let mut second = tree.root.members[0].clone();
    second.signed.intent.accounts = Capped::new(vec![CAROL]).unwrap();
    let mut two = tree;
    two.root.members.push(second).unwrap();
    let mut reordered = two.clone();
    reordered.root.members.swap(0, 1);
    assert_ne!(reordered.hash(&TestHasher), two.hash(&TestHasher));
}

#[test]
fn mutual_sockets_with_no_order_are_a_cycle() {
    // Each intent's only node consumes what the other yields; neither
    // can produce first.
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.graph.nodes =
        Capped::new(vec![deposit_param(BOB, 0)]).unwrap();
    tree.root.graph.nodes = Capped::new(vec![deposit_give(ALICE, 0, 0, Vec::new())]).unwrap();
    assert_eq!(admit_composed(&tree), Err(AdmissionError::CyclicSockets));
}

#[test]
fn what_fills_a_socket_must_match_the_declared_resource() {
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.sockets[0] = Socket::Value {
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

/// The member's producer, yielding named instances instead of an
/// amount.
fn withdraw_nf(account: PrincipalAddr, resource: impl Into<Address>, id: u64) -> GraphNode {
    GraphNode::signed(
        account,
        account,
        "withdraw_nf",
        vec![
            GraphArg::Literal(Value::Address(resource.into())),
            GraphArg::Literal(Value::List(vec![Value::U64(id)])),
        ],
    )
}

#[test]
fn an_edge_filling_a_socket_is_judged_by_its_kind() {
    let nf_tree = |consumer: GraphNode| {
        let root = intent(
            ALICE,
            vec![withdraw(ALICE, RES_X, 100), consumer],
            Vec::new(),
            Vec::new(),
        );
        let bob = intent(
            BOB,
            vec![withdraw_nf(BOB, RES_Y, 7), deposit_param(BOB, 0)],
            vec![Socket::Value {
                resource: RES_X,
                constraints: vec![],
            }],
            vec![ValueRef::Edge(edge(0, 0))],
        );
        tree(compose(
            root,
            vec![(bob, vec![Binding::Value(ValueRef::Edge(edge(0, 0)))])],
        ))
    };

    // Named instances into the fungible `deposit`: refused by kind, the
    // same judgment a direct edge gets.
    let wrong = nf_tree(deposit_give(ALICE, 0, 0, Vec::new()));
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
        "deposit_nf",
        vec![GraphArg::give(give(0, 0), Vec::new())],
    ));
    admit_composed(&right).expect("an NF yield binds an NF parameter");

    // And a fungible yield into `deposit-nf` refuses the other way.
    let mut crossed = composed_tree(100);
    crossed.root.graph.nodes[1] = GraphNode::new(
        ALICE,
        "deposit_nf",
        vec![GraphArg::give(give(0, 0), Vec::new())],
    );
    assert!(matches!(
        admit_composed(&crossed),
        Err(AdmissionError::ResourceKindMismatch {
            found: ResourceKind::Fungible,
            ..
        })
    ));
}

#[test]
fn socket_consumption_is_exactly_once() {
    let mut unused = composed_tree(100);
    unused.root.members[0].signed.intent.graph.nodes[1] = withdraw(BOB, RES_Y, 1);
    assert_eq!(
        admit_composed(&unused),
        Err(AdmissionError::UnconsumedSocket {
            intent: 1,
            socket: 0
        })
    );

    let mut reused = composed_tree(100);
    reused.root.members[0]
        .signed
        .intent
        .graph
        .nodes
        .push(deposit_param(BOB, 0))
        .unwrap();
    assert_eq!(
        admit_composed(&reused),
        Err(AdmissionError::SocketReused {
            intent: 1,
            socket: 0
        })
    );
}

/// A give is consumed exactly once by the intent above it, whichever
/// way that intent takes it; the root's gives are consumed by nothing.
#[test]
fn give_consumption_is_exactly_once() {
    let mut unused = composed_tree(100);
    unused.root.graph.nodes[1] = deposit_edge(ALICE, 0);
    assert_eq!(
        admit_composed(&unused),
        Err(AdmissionError::UnconsumedGive {
            intent: 0,
            member: 0,
            give: 0
        })
    );

    let mut twice = composed_tree(100);
    twice
        .root
        .graph
        .nodes
        .push(deposit_give(ALICE, 0, 0, Vec::new()))
        .unwrap();
    assert_eq!(
        admit_composed(&twice),
        Err(AdmissionError::GiveReused {
            intent: 0,
            member: 0,
            give: 0
        })
    );

    let mut rooted = composed_tree(100);
    rooted.root.gives = Capped::new(vec![ValueRef::Edge(edge(0, 0))]).unwrap();
    assert_eq!(
        admit_composed(&rooted),
        Err(AdmissionError::RootGives { give: 0 })
    );
}

/// A give names an edge of its own graph or a give of its own member,
/// and nothing else; a give of an edge the graph consumes itself is two
/// consumers of one edge, judged at the flat level like any other.
#[test]
fn a_give_names_what_the_intent_holds() {
    let mut past_graph = composed_tree(100);
    past_graph.root.members[0].signed.intent.gives =
        Capped::new(vec![ValueRef::Edge(edge(7, 0))]).unwrap();
    assert_eq!(
        admit_composed(&past_graph),
        Err(AdmissionError::UnknownGive { intent: 1, give: 0 })
    );

    let mut past_members = composed_tree(100);
    past_members.root.members[0].signed.intent.gives =
        Capped::new(vec![ValueRef::Give(give(0, 0))]).unwrap();
    assert_eq!(
        admit_composed(&past_members),
        Err(AdmissionError::UnknownGive { intent: 1, give: 0 })
    );

    let mut internal = composed_tree(100);
    internal.root.members[0].signed.intent.graph.nodes[1] = deposit_edge(BOB, 0);
    internal.root.members[0].signed.intent.sockets.clear();
    internal.root.members[0].wiring.clear();
    internal
        .root
        .graph
        .nodes
        .push(deposit_edge(ALICE, 0))
        .unwrap();
    assert!(matches!(
        admit_composed(&internal),
        Err(AdmissionError::DoubleConsumption { .. })
    ));
}

#[test]
fn wiring_must_cover_the_declared_sockets() {
    let mut tree = composed_tree(100);
    tree.root.members[0].wiring.clear();
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::BindingArity {
            intent: 1,
            expected: 1,
            found: 0,
        })
    );

    // In the other direction too: wiring on a member that declares no
    // socket is signed content that binds nothing.
    let mut over = composed_tree(100);
    over.root.members[0].signed.intent.sockets.clear();
    over.root.members[0].signed.intent.graph.nodes[1] = deposit_edge(BOB, 0);
    assert_eq!(
        admit_composed(&over),
        Err(AdmissionError::BindingArity {
            intent: 1,
            expected: 0,
            found: 1,
        })
    );

    let mut dangling = composed_tree(100);
    dangling.root.members[0].wiring[0] = Binding::Value(ValueRef::Edge(edge(7, 0)));
    assert_eq!(
        admit_composed(&dangling),
        Err(AdmissionError::UnknownBinding {
            intent: 1,
            socket: 0
        })
    );

    let mut past_members = composed_tree(100);
    past_members.root.members[0].wiring[0] = Binding::Value(ValueRef::Give(give(3, 0)));
    assert_eq!(
        admit_composed(&past_members),
        Err(AdmissionError::UnknownBinding {
            intent: 1,
            socket: 0
        })
    );

    // The root has no sockets to pass through.
    let mut through_nothing = composed_tree(100);
    through_nothing.root.members[0].wiring[0] = Binding::Value(ValueRef::Socket(0));
    assert_eq!(
        admit_composed(&through_nothing),
        Err(AdmissionError::UnknownBinding {
            intent: 1,
            socket: 0
        })
    );
}

#[test]
fn two_wirings_cannot_consume_one_output() {
    // A second member is wired the same root output the first consumes.
    let mut second = bobs_offer();
    second.accounts = Capped::new(vec![CAROL]).unwrap();
    second.graph.nodes[0] = withdraw(CAROL, RES_Y, 10);
    second.graph.nodes[1] = deposit_param(CAROL, 0);
    let root = intent(
        ALICE,
        vec![
            withdraw(ALICE, RES_X, 100),
            deposit_give(ALICE, 0, 0, Vec::new()),
            deposit_give(ALICE, 1, 0, Vec::new()),
        ],
        Vec::new(),
        Vec::new(),
    );
    let tree = tree(compose(
        root,
        vec![
            (
                bobs_offer(),
                vec![Binding::Value(ValueRef::Edge(edge(0, 0)))],
            ),
            (second, vec![Binding::Value(ValueRef::Edge(edge(0, 0)))]),
        ],
    ));
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::DoubleConsumption {
            producer: 0,
            output: 0,
        })
    );
}

/// Two intents of one tree that hash alike are refused wherever they
/// sit: the hash names every escrow record and claim the tree derives,
/// so one intent composed in two places would derive one key for two
/// edges.
#[test]
fn duplicate_intents_reject() {
    let mut beside = composed_tree(100);
    let copy = beside.root.members[0].clone();
    beside.root.members.push(copy).unwrap();
    beside
        .root
        .graph
        .nodes
        .push(deposit_give(ALICE, 1, 0, Vec::new()))
        .unwrap();
    assert_eq!(
        admit_composed(&beside),
        Err(AdmissionError::DuplicateIntent { index: 2 })
    );

    // At two depths rather than beside: Bob beside Carol and Bob under
    // her is still one hash twice, at preorder positions one and three.
    let mut beneath = composed_tree(100);
    // Carol takes Bob's give and gives it on; the root takes hers.
    let mut carol = intent(
        CAROL,
        Vec::new(),
        Vec::new(),
        vec![ValueRef::Give(give(0, 0))],
    );
    carol.members = Capped::new(vec![beneath.root.members[0].clone()]).unwrap();
    beneath
        .root
        .members
        .push(Member {
            signed: SignedIntent::unsigned(carol),
            wiring: Capped::empty(),
        })
        .unwrap();
    beneath
        .root
        .graph
        .nodes
        .push(deposit_give(ALICE, 1, 0, Vec::new()))
        .unwrap();
    assert_eq!(
        admit_composed(&beneath),
        Err(AdmissionError::DuplicateIntent { index: 3 })
    );
}

#[test]
fn an_intent_cannot_declare_unbounded_sockets() {
    // The socket list holds its cap: it fills to the cap and refuses the
    // next, so an intent past it cannot be built, let alone admitted.
    let mut tree = composed_tree(100);
    let intent = &mut tree.root.members[0].signed.intent;
    let socket = intent.sockets[0].clone();
    while intent.sockets.len() < MAX_SOCKETS {
        intent.sockets.push(socket.clone()).unwrap();
    }
    assert!(intent.sockets.push(socket).is_err());
}

#[test]
fn a_socket_cannot_fill_a_value_parameter() {
    // `withdraw(resource, amount)` takes no bucket, so filling one of
    // its parameters from a socket is a parameter defect — not the edge
    // defect the shared arity check would otherwise report.
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.graph.nodes[1] = GraphNode::signed(
        BOB,
        BOB,
        "withdraw",
        vec![GraphArg::socket(0), GraphArg::Literal(Value::U128(1))],
    );
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::SocketForValueParam { node: 3, param: 0 })
    );

    // And a give the same way.
    let mut given = composed_tree(100);
    given.root.graph.nodes[1] = GraphNode::signed(
        ALICE,
        ALICE,
        "withdraw",
        vec![
            GraphArg::give(give(0, 0), Vec::new()),
            GraphArg::Literal(Value::U128(1)),
        ],
    );
    assert_eq!(
        admit_composed(&given),
        Err(AdmissionError::EdgeForValueParam { node: 2, param: 0 })
    );
}

/// An authority socket passed where an argument goes is its own refusal.
#[test]
fn an_authority_socket_is_presented_not_passed() {
    let mut tree = composed_tree(100);
    tree.root.members[0].signed.intent.sockets =
        Capped::new(vec![Socket::Authority(Claim::of_subject(ALICE.address()))]).unwrap();
    tree.root.members[0].wiring =
        Capped::new(vec![Binding::Authority(ClaimRef::Account(ALICE))]).unwrap();
    // Bob's deposit is the last node emitted: both withdrawals and the
    // root's deposit, which takes Bob's give, come before it.
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::SocketKindMismatch {
            intent: 1,
            socket: 0,
            declared: "authority",
            offered: "an edge",
        })
    );
}

/// Bob's offer: a withdrawal from Alice's vault, gated on an authority
/// his own intent declares and never supplies, given up whole.
fn delegated_offer(wants: Claim) -> Intent {
    intent(
        BOB,
        vec![GraphNode {
            evidence: Capped::new(BTreeSet::from([ClaimRef::Socket(0)])).unwrap(),
            ..GraphNode::new(
                ALICE,
                "withdraw",
                vec![
                    GraphArg::Literal(Value::Address(RES_X.into())),
                    GraphArg::Literal(Value::U128(100)),
                ],
            )
        }],
        vec![Socket::Authority(wants)],
        vec![ValueRef::Edge(edge(0, 0))],
    )
}

/// A root acting as `composer` composing Bob's delegated offer, banking
/// what it withdraws, and granting `source` into its socket.
fn granted_tree(composer: PrincipalAddr, source: ClaimRef, wants: Claim) -> IntentTree {
    let root = intent(
        composer,
        vec![deposit_give(
            composer,
            0,
            0,
            vec![Constraint::MinAmount(100)],
        )],
        Vec::new(),
        Vec::new(),
    );
    tree(compose(
        root,
        vec![(delegated_offer(wants), vec![Binding::Authority(source)])],
    ))
}

/// The root grants the account it acts as, and the offer's gate is
/// answered by it — no node proves anything, and nothing in either
/// graph signs in.
///
/// The ordering is the other half of what this pins. The root's own
/// node waits on the offer's withdrawal, so a grant that carried a
/// dependency on the granting intent's graph would close a cycle and
/// this tree would not admit at all. An account's authority stands
/// before any node runs, which is what leaves the interleave free.
#[test]
fn a_root_grants_the_account_it_acts_as() {
    let tree = granted_tree(ALICE, ClaimRef::Account(ALICE), Claim::of_subject(ALICE));
    let admitted = admit_composed(&tree).expect("the root grants its own account");
    assert_eq!(
        shape(&admitted),
        vec![
            (ALICE.address(), "withdraw".into()),
            (ALICE.address(), "deposit".into()),
        ]
    );
    assert!(
        admitted.manifest().nodes[0]
            .evidence
            .contains(&Claim::of_subject(ALICE))
    );
}

/// The reproduction: an intent Alice signed, bound into a call she never
/// saw, refuses.
///
/// A thief composes Alice's leaf — a transfer she signed, presenting her
/// own signature — beside Bob's offer, which asks for her claim. Nothing
/// the thief can write reaches her authority: a grant of her account is
/// refused because the thief's intent does not act as her, a grant from
/// the thief's own node presents what that node proved and never her
/// claim, and no wiring can name a node of her leaf at all.
#[test]
fn an_intent_alice_signed_grants_nothing_into_a_call_she_never_saw() {
    let alices_transfer = intent(
        ALICE,
        vec![withdraw(ALICE, RES_Y, 1), deposit_edge(ALICE, 0)],
        Vec::new(),
        Vec::new(),
    );
    let thief = |source: ClaimRef| {
        let root = intent(
            THIEF,
            vec![
                withdraw(THIEF, RES_Y, 1),
                deposit_edge(THIEF, 0),
                deposit_give(THIEF, 1, 0, vec![Constraint::MinAmount(100)]),
            ],
            Vec::new(),
            Vec::new(),
        );
        tree(compose(
            root,
            vec![
                (alices_transfer.clone(), Vec::new()),
                (
                    delegated_offer(Claim::of_subject(ALICE)),
                    vec![Binding::Authority(source)],
                ),
            ],
        ))
    };

    assert_eq!(
        admit_composed(&thief(ClaimRef::Account(ALICE))),
        Err(AdmissionError::GrantNotHeld {
            intent: 2,
            socket: 0,
            account: ALICE,
        })
    );
    // The thief's own withdrawal presents the thief's signature and
    // proves nothing about Alice.
    assert_eq!(
        admit_composed(&thief(ClaimRef::Node(0))),
        Err(AdmissionError::SocketClaimMismatch {
            intent: 2,
            node: 0,
            socket: 0,
        })
    );
    // And the thief's intent has no socket of its own to pass through.
    assert_eq!(
        admit_composed(&thief(ClaimRef::Socket(0))),
        Err(AdmissionError::UnknownBinding {
            intent: 2,
            socket: 0
        })
    );
}

/// A grant of an account the granting intent does not act as is refused.
#[test]
fn a_grant_of_an_account_the_granter_is_not_is_refused() {
    let tree = granted_tree(ALICE, ClaimRef::Account(BOB), Claim::of_subject(BOB));
    assert_eq!(
        admit_composed(&tree).expect_err("the root acts as Alice, not Bob"),
        AdmissionError::GrantNotHeld {
            intent: 1,
            socket: 0,
            account: BOB,
        }
    );
}

/// A grant of some other claim than the socket asked for is refused, and
/// a socket asking for a badge is refused the same way.
#[test]
fn a_grant_answers_only_the_claim_the_socket_named() {
    let mismatch = AdmissionError::GrantClaimMismatch {
        intent: 1,
        socket: 0,
    };
    let tree = granted_tree(ALICE, ClaimRef::Account(ALICE), Claim::of_subject(BOB));
    assert_eq!(
        admit_composed(&tree).expect_err("the socket asked for Bob"),
        mismatch
    );
    let tree = granted_tree(ALICE, ClaimRef::Account(ALICE), Claim::of_subject(RES_X));
    assert_eq!(
        admit_composed(&tree).expect_err("no signature carries a badge"),
        mismatch
    );
}

/// A value socket granted a claim is the channel mismatch, not a grant
/// refusal: a grant is authority, and authority does not fill an
/// argument.
#[test]
fn a_value_socket_granted_a_claim_names_the_mismatch() {
    let mut tree = composed_tree(100);
    tree.root.members[0].wiring[0] = Binding::Authority(ClaimRef::Account(ALICE));
    assert_eq!(
        admit_composed(&tree).expect_err("a grant does not fill a value socket"),
        AdmissionError::SocketKindMismatch {
            intent: 1,
            socket: 0,
            declared: "value",
            offered: "a proof",
        }
    );
}

/// A group in the middle: Carol composes Bob's offer and presents its
/// interface as her own, a socket for the X Bob wants and a give of the
/// Y he produces; the root composes Carol and never sees Bob.
fn grouped_tree(
    carol_wires: Vec<Binding>,
    carol_gives: Vec<ValueRef>,
    carol_sockets: Vec<Socket>,
) -> IntentTree {
    let carol = intent(CAROL, Vec::new(), carol_sockets, carol_gives);
    let root = intent(
        ALICE,
        vec![
            withdraw(ALICE, RES_X, 100),
            deposit_give(ALICE, 0, 0, vec![Constraint::MinAmount(10)]),
        ],
        Vec::new(),
        Vec::new(),
    );
    tree(compose(
        root,
        vec![(
            compose(carol, vec![(bobs_offer(), carol_wires)]),
            vec![Binding::Value(ValueRef::Edge(edge(0, 0)))],
        )],
    ))
}

/// A two-level tree admits and nullifies every intent, and a give
/// re-exported through the group resolves to the leaf's node while a
/// socket passed through it resolves to the root's, under the
/// constraints of every socket along the way.
#[test]
fn a_two_level_tree_admits_and_nullifies_every_intent() {
    let tree = grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_X,
            constraints: vec![Constraint::MaxAmount(500)],
        }],
    );
    let admitted = admit_composed(&tree).expect("the group resolves");
    assert_eq!(admitted.intents().len(), 3);
    assert_eq!(
        admitted
            .intents()
            .iter()
            .flat_map(IntentRecord::accounts)
            .collect::<Vec<_>>(),
        [ALICE, CAROL, BOB]
    );
    // Carol calls nothing, so the flattening is the one-level tree's.
    assert_eq!(
        shape(&admitted),
        shape(&admit_composed(&composed_tree(100)).unwrap())
    );
    // Bob's deposit takes the root's edge, bounded by his own socket
    // and by Carol's.
    let manifest = admitted.manifest();
    assert_eq!(
        manifest.nodes[3].inputs,
        vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: RES_X,
            content: EdgeContent::Fungible,
            bounds: Bounds {
                min: Some(100),
                max: Some(500),
            },
        }]
    );
}

/// A sealed group is indistinguishable from a leaf: the same root over a
/// leaf and over a group presenting the leaf's interface produces the
/// same flattening.
#[test]
fn a_sealed_group_is_indistinguishable_from_a_leaf() {
    let leaf = admit_composed(&composed_tree(100)).unwrap();
    let group = admit_composed(&grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_X,
            constraints: Vec::new(),
        }],
    ))
    .unwrap();
    assert_eq!(leaf.manifest(), group.manifest());
}

/// A group whose interface does not agree with what it passes through
/// refuses at the seam.
#[test]
fn a_group_interface_must_agree_with_what_it_passes_through() {
    // The group's socket names another resource than the member's.
    let tree = grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_Y,
            constraints: Vec::new(),
        }],
    );
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::SocketResourceMismatch {
            intent: 2,
            socket: 0
        })
    );

    // The group's constraints and the member's contradict.
    let tree = grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_X,
            constraints: vec![Constraint::MaxAmount(1)],
        }],
    );
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::UnsatisfiableConstraint { node: 3, param: 0 })
    );

    // The group routes Bob's own give back into his socket and leaves
    // its own socket unreached: the give is then consumed twice, once
    // by the wiring and once by the group's own give of it.
    let mut tree = grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0)), ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_X,
            constraints: Vec::new(),
        }],
    );
    tree.root
        .graph
        .nodes
        .push(deposit_give(ALICE, 0, 1, Vec::new()))
        .unwrap();
    assert_eq!(
        admit_composed(&tree),
        Err(AdmissionError::GiveReused {
            intent: 1,
            member: 0,
            give: 0
        })
    );
}

/// A claim granted two levels deep resolves only when every level
/// re-granted it: the root grants Alice's claim into Carol's socket, and
/// Carol grants her socket on into Bob's.
#[test]
fn a_claim_granted_two_levels_deep_resolves_only_where_every_level_regranted_it() {
    let deep = |carol_wires: Vec<Binding>, root_wires: Vec<Binding>| {
        let carol = intent(
            CAROL,
            Vec::new(),
            vec![Socket::Authority(Claim::of_subject(ALICE))],
            vec![ValueRef::Give(give(0, 0))],
        );
        let root = intent(
            ALICE,
            vec![deposit_give(ALICE, 0, 0, vec![Constraint::MinAmount(100)])],
            Vec::new(),
            Vec::new(),
        );
        tree(compose(
            root,
            vec![(
                compose(
                    carol,
                    vec![(delegated_offer(Claim::of_subject(ALICE)), carol_wires)],
                ),
                root_wires,
            )],
        ))
    };

    let admitted = admit_composed(&deep(
        vec![Binding::Authority(ClaimRef::Socket(0))],
        vec![Binding::Authority(ClaimRef::Account(ALICE))],
    ))
    .expect("re-granted at every level");
    assert!(
        admitted.manifest().nodes[0]
            .evidence
            .contains(&Claim::of_subject(ALICE))
    );

    // Carol grants her own account instead of what she received. She
    // presents what she received herself, so her socket is reached and
    // what is judged is the grant.
    let mut mismatched = deep(
        vec![Binding::Authority(ClaimRef::Account(CAROL))],
        vec![Binding::Authority(ClaimRef::Account(ALICE))],
    );
    let carol = &mut mismatched.root.members[0].signed.intent;
    let mut presenting = withdraw(CAROL, RES_Y, 1);
    presenting.evidence.insert(ClaimRef::Socket(0)).unwrap();
    carol.graph.nodes = Capped::new(vec![presenting, deposit_edge(CAROL, 0)]).unwrap();
    assert_eq!(
        admit_composed(&mismatched),
        Err(AdmissionError::GrantClaimMismatch {
            intent: 2,
            socket: 0
        })
    );
    // Carol grants Alice's account, which she does not act as.
    let mut unheld = deep(
        vec![Binding::Authority(ClaimRef::Account(ALICE))],
        vec![Binding::Authority(ClaimRef::Account(ALICE))],
    );
    let carol = &mut unheld.root.members[0].signed.intent;
    let mut presenting = withdraw(CAROL, RES_Y, 1);
    presenting.evidence.insert(ClaimRef::Socket(0)).unwrap();
    carol.graph.nodes = Capped::new(vec![presenting, deposit_edge(CAROL, 0)]).unwrap();
    assert_eq!(
        admit_composed(&unheld),
        Err(AdmissionError::GrantNotHeld {
            intent: 2,
            socket: 0,
            account: ALICE,
        })
    );
    // The root fills Carol's socket with the wrong account.
    let mut root_as_bob = deep(
        vec![Binding::Authority(ClaimRef::Socket(0))],
        vec![Binding::Authority(ClaimRef::Account(BOB))],
    );
    root_as_bob.root.accounts = Capped::new(vec![BOB]).unwrap();
    assert_eq!(
        admit_composed(&root_as_bob),
        Err(AdmissionError::GrantClaimMismatch {
            intent: 1,
            socket: 0
        })
    );
}

/// A composer contains its members, so there is no order to keep, no
/// member to reach and no cycle to close: what is left to refuse is a
/// tree nested past the bound.
#[test]
fn a_tree_is_bounded_in_depth() {
    // A chain of intents, each composing the next: `depth` deep, the
    // leaf giving Y up through every level and the root banking it.
    let chain = |depth: usize| {
        let leaf = intent(
            BOB,
            vec![withdraw(BOB, RES_Y, 10)],
            Vec::new(),
            vec![ValueRef::Edge(edge(0, 0))],
        );
        let mut below = leaf;
        for level in 1..depth - 1 {
            let mut group = intent(
                PrincipalAddr::new([0x40 + u8::try_from(level).expect("a small level"); 31]),
                Vec::new(),
                Vec::new(),
                vec![ValueRef::Give(give(0, 0))],
            );
            group.members = Capped::new(vec![Member {
                signed: SignedIntent::unsigned(below),
                wiring: Capped::empty(),
            }])
            .unwrap();
            below = group;
        }
        let mut root = intent(
            ALICE,
            vec![deposit_give(ALICE, 0, 0, Vec::new())],
            Vec::new(),
            Vec::new(),
        );
        root.members = Capped::new(vec![Member {
            signed: SignedIntent::unsigned(below),
            wiring: Capped::empty(),
        }])
        .unwrap();
        tree(root)
    };
    let deepest = chain(MAX_TREE_DEPTH);
    assert_eq!(deepest.root.depth(), MAX_TREE_DEPTH);
    admit_composed(&deepest).expect("a tree at the bound admits");
    let bytes = encode_tree(&deepest);
    assert_eq!(decode_tree(&bytes).as_ref(), Ok(&deepest));

    let too_deep = chain(MAX_TREE_DEPTH + 1);
    assert_eq!(
        admit_composed(&too_deep),
        Err(AdmissionError::TreeTooDeep {
            intent: as_u32(MAX_TREE_DEPTH)
        })
    );
}

/// The wire depth is exactly what the deepest admissible tree costs: a
/// tree at the depth bound carrying a literal at the value depth bound
/// encodes under it, and nothing shallower than that cap would hold it.
#[test]
fn the_wire_depth_is_pinned_to_the_deepest_admissible_tree() {
    let mut literal = Value::U64(0);
    for _ in 1..MAX_VALUE_DEPTH {
        literal = Value::Tuple(vec![literal]);
    }
    assert_eq!(literal.depth(), MAX_VALUE_DEPTH);
    let leaf = intent(
        BOB,
        vec![GraphNode::new(
            BOB,
            "note",
            vec![GraphArg::Literal(literal)],
        )],
        Vec::new(),
        Vec::new(),
    );
    let mut below = leaf;
    for level in 1..MAX_TREE_DEPTH {
        let mut group = intent(
            PrincipalAddr::new([0x40 + u8::try_from(level).expect("a small level"); 31]),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        group.members = Capped::new(vec![Member {
            signed: SignedIntent::unsigned(below),
            wiring: Capped::empty(),
        }])
        .unwrap();
        below = group;
    }
    let deepest = tree(below);
    assert_eq!(deepest.root.depth(), MAX_TREE_DEPTH);
    let bytes = encode_tree(&deepest);
    assert!(
        from_slice_with_depth::<IntentTree>(&bytes, TREE_WIRE_DEPTH - 1).is_err(),
        "one level under the cap does not hold the deepest tree"
    );
    assert_eq!(decode_tree(&bytes).as_ref(), Ok(&deepest));
}

fn as_u32(index: usize) -> u32 {
    u32::try_from(index).expect("a test index fits")
}

#[test]
fn a_bare_graph_admits_no_sockets_or_gives() {
    let chain = world();
    let graph = ManifestGraph {
        nodes: Capped::new(vec![deposit_param(ALICE, 0)]).unwrap(),
    };
    assert_eq!(
        admit_leaf(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::UnknownSocket {
            intent: 0,
            node: 0,
            socket: 0
        })
    );
    let graph = ManifestGraph {
        nodes: Capped::new(vec![deposit_give(ALICE, 0, 0, Vec::new())]).unwrap(),
    };
    assert_eq!(
        admit_leaf(&graph, ALICE, &chain, &TestHasher),
        Err(AdmissionError::UnknownGive { intent: 0, give: 0 })
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
        .map(|identity| admit_tree(&tree, *identity, &chain, &TestHasher).unwrap())
        .collect();
    assert_eq!(
        admitted[0].manifest(),
        admitted[1].manifest(),
        "the corpus graph mints no fresh keys, so the manifests agree"
    );
    assert_ne!(admitted[0].identity(), admitted[1].identity());
}

#[test]
fn the_intent_cap_is_checked_before_anything_else() {
    // At the cap the count check passes and ordinary rules take over —
    // here the duplicate scan. One past it, the count is the verdict.
    let mut at_cap = composed_tree(100);
    let copy = at_cap.root.members[0].clone();
    at_cap.root.members = Capped::new(vec![copy.clone(); MAX_INTENTS - 1]).unwrap();
    // Every copy's give taken, so the shape holds and the duplicate
    // scan is what speaks.
    for member in 1..as_u32(MAX_INTENTS - 1) {
        at_cap
            .root
            .graph
            .nodes
            .push(deposit_give(ALICE, member, 0, Vec::new()))
            .unwrap();
    }
    assert_eq!(
        admit_composed(&at_cap),
        Err(AdmissionError::DuplicateIntent { index: 2 })
    );

    let mut past_cap = at_cap;
    past_cap.root.members.push(copy).unwrap();
    assert_eq!(
        admit_composed(&past_cap),
        Err(AdmissionError::TooManyIntents)
    );
    // And at decode, before anything walks or hashes the tree.
    assert_eq!(
        decode_tree(&encode_tree(&past_cap)),
        Err(TreeDecodeError::Shape(AdmissionError::TooManyIntents))
    );
}

/// The node cap is over the whole tree, and a tree past it is refused
/// at decode: no graph is at its own cap, and nothing downstream sees
/// the sum.
#[test]
fn the_node_cap_is_over_the_tree_and_checked_at_decode() {
    let mut wide = composed_tree(100);
    // Everything the member declares, the root now also deposits: the
    // member's give is taken once, so the padding consumes nothing.
    // The root's graph is padded to exactly its own cap, which the type
    // admits; the member's nodes are what carry the tree past it.
    let mut nodes = wide.root.graph.nodes.clone().into_inner();
    let padding = MAX_MANIFEST_NODES - nodes.len();
    nodes.extend((0..padding).map(|_| deposit_edge(ALICE, 0)));
    wide.root.graph.nodes = Capped::new(nodes).unwrap();
    assert!(wide.node_count() > MAX_MANIFEST_NODES);
    assert_eq!(
        decode_tree(&encode_tree(&wide)),
        Err(TreeDecodeError::Shape(AdmissionError::TooManyNodes))
    );
    assert_eq!(admit_composed(&wide), Err(AdmissionError::TooManyNodes));
}

/// The bottom-up walk computes what the recursive definition does, for
/// every intent, in tree order.
#[test]
fn the_tree_hashes_bottom_up_as_each_intent_hashes_itself() {
    let mut inner = composed_tree(100).root;
    inner.accounts = Capped::new(vec![CAROL]).unwrap();
    inner.attested_by = Capped::new(vec![CAROL]).unwrap();
    let mut tree = composed_tree(100);
    tree.root
        .members
        .push(Member {
            signed: SignedIntent::unsigned(inner),
            wiring: Capped::empty(),
        })
        .unwrap();
    let expected: Vec<IntentHash> = tree
        .intents()
        .iter()
        .map(|intent| intent.hash(&TestHasher))
        .collect();
    assert_eq!(tree.hashes(&TestHasher), expected);
    assert_eq!(expected.len(), 4);
}

proptest! {
    /// Point any wiring anywhere: tree admission either accepts a
    /// composition or rejects it deterministically — it never panics and
    /// never disagrees with itself.
    #[test]
    fn arbitrary_rewirings_never_break_admission(
        producer in any::<u32>(),
        output in any::<u32>(),
        member in any::<u32>(),
        given in any::<u32>(),
        variant in 0u8..3,
    ) {
        let chain = world();
        let mut tree = composed_tree(100);
        let binding = match variant {
            0 => Binding::Value(ValueRef::Edge(EdgeRef { producer, output })),
            1 => Binding::Value(ValueRef::Give(GiveRef { member, give: given })),
            _ => Binding::Value(ValueRef::Socket(producer)),
        };
        tree.root.members[0].wiring[0] = binding;
        let identity = tree.hash(&TestHasher);
        let first = admit_tree(&tree, identity, &chain, &TestHasher);
        let second = admit_tree(&tree, identity, &chain, &TestHasher);
        assert_eq!(first, second);
    }
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
    tree.instances
        .push(InstanceMeta {
            package: pkg(),
            config: Capped::new(vec![value]).unwrap(),
            salt: Hash32([9; 32]),
        })
        .unwrap();
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
        config: Capped::empty(),
        salt: Hash32([5; 32]),
    };
    let round = meta.address(&TestHasher);
    let calling = |method: &str, args: Vec<GraphArg>, records: Vec<InstanceMeta>| IntentTree {
        root: Intent::leaf(
            TEST_HEADER,
            ALICE,
            ManifestGraph {
                nodes: Capped::new(vec![GraphNode {
                    target: round.into(),
                    method: method.into(),
                    args,
                    evidence: Capped::default(),
                }])
                .unwrap(),
            },
        ),
        instances: Capped::new(records).unwrap(),
        resources: Capped::empty(),
    };
    let admit_with = |tree: &IntentTree, chain: &dyn ChainRecords| {
        admit_tree(tree, tree.hash(&TestHasher), chain, &TestHasher)
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

/// The tree round-trips its own codec.
#[test]
fn a_tree_round_trips_its_encoding() {
    let tree = grouped_tree(
        vec![Binding::Value(ValueRef::Socket(0))],
        vec![ValueRef::Give(give(0, 0))],
        vec![Socket::Value {
            resource: RES_X,
            constraints: Vec::new(),
        }],
    );
    let bytes = encode_tree(&tree);
    let decoded = decode_tree(&bytes).expect("a tree round-trips");
    assert_eq!(decoded, tree);
}

/// The widths the declaration prices the kernel's own cells at bound
/// what the cells encode to, at their widest.
mod cell_widths {
    use hyperscale_hbor::Hash32;
    use hyperscale_vm_effects::{
        CROSSING_CELL_BYTES, CrossingCell, MARKER_CELL_BYTES, Marked, Marker, Terms,
    };
    use hyperscale_vm_types::{
        Address, AddressClass, IntentHash, LocalKey, ResourceAddr, SubstateKey, TxHash,
    };

    const fn hash32() -> Hash32 {
        Hash32([0xFF; 32])
    }

    const fn key() -> SubstateKey {
        SubstateKey {
            owner: Address::new([0xFF; 31], AddressClass::Component),
            local: LocalKey([0xFF; 16]),
        }
    }

    #[test]
    fn a_marker_encodes_under_its_width() {
        let widest = [
            Marked::Spent(IntentHash(hash32())),
            Marked::Committed,
            Marked::Claimed {
                intent: IntentHash(hash32()),
                local: u32::MAX,
                output: u32::MAX,
            },
        ];
        for marks in widest {
            let marker = Marker {
                tx: TxHash(hash32()),
                expiry_ms: u64::MAX,
                marks,
            };
            assert!(
                marker.to_bytes().len() <= MARKER_CELL_BYTES as usize,
                "{marker:?} encodes past the marker width"
            );
        }
    }

    #[test]
    fn a_crossing_cell_encodes_under_its_width() {
        let cell = CrossingCell {
            resource: ResourceAddr::new([0xFF; 31]),
            amount: u128::MAX,
            intent: IntentHash(hash32()),
            local: u32::MAX,
            output: u32::MAX,
            expiry_ms: u64::MAX,
            tx: TxHash(hash32()),
            consumer_claim: key(),
            terms: Terms::Escrowed { credit: key() },
        };
        assert!(
            cell.to_bytes().len() <= CROSSING_CELL_BYTES as usize,
            "a crossing cell encodes to {} bytes",
            cell.to_bytes().len()
        );
    }
}
