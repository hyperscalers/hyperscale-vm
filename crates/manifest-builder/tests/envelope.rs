//! The envelope tier's contract: any envelope it emits passes
//! [`admit_tree`], and the arithmetic over declarations that admission
//! judges is judged here first.
//!
//! The world is two accounts and the resources they trade, which is all a
//! composition needs: what fills a socket is an ordinary edge or an
//! ordinary proof, and what makes it a composition is which graph it
//! crosses.

use hyperscale_vm_effects::{
    AdmissionError, Claim, Constraint, EnvelopeTree, EvidenceRef, GrantedBehaviour, GraphArg,
    Hash32, Hasher, InstanceMeta, IntentDecl, IntentHeader, MAX_VALUE_DEPTH, PackageHash, Records,
    ResourceGrants, ResourceKind, ResourceMeta, RuleBytes, Socket, StoredRule, TestHasher, Value,
    admit_tree,
};
use hyperscale_vm_manifest_builder::{
    BuildError, EnvelopeBuilder, EnvelopeError, IntentBuilder, TypedError,
};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{Address, AddressClass, NetworkId, PrincipalAddr, ResourceAddr};
use proptest::prelude::{prop, proptest};

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

fn admits(tree: &EnvelopeTree) {
    let chain = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, ALICE, identity, &chain, &TestHasher).expect("a composed envelope admits");
}

/// The two-sided trade: each signer withdraws what they pay, exports it,
/// and deposits what the other side yields. Neither graph mentions the
/// other; the envelope is the two edges between them.
fn swap(pay_x: u128, pay_y: u128) -> Result<EnvelopeTree, EnvelopeError> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);

    let taken_y = root.declare(RES_Y, [Constraint::MinAmount(pay_y)]);
    let funds = account::withdraw(&mut root, ALICE, RES_X, pay_x)?;
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken_y)?;

    let mut sub = env.subintent(BOB, TEST_HEADER);
    let taken_x = sub.declare(RES_X, [Constraint::MinAmount(pay_x)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, pay_y)?;
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken_x)?;

    let wants_y = env.seal(root)?.one()?;
    let wants_x = env.seal(sub)?.one()?;
    env.bind(wants_y, paid_y)?;
    env.bind(wants_x, paid_x)?;
    env.build()
}

#[test]
fn a_composed_swap_admits() {
    let tree = swap(100, 10).unwrap();
    assert_eq!(tree.subintents.len(), 1);
    assert_eq!(tree.subintents[0].signer, BOB);
    // The wiring the author never wrote: each side's socket names the other
    // intent's exported edge.
    assert_eq!(tree.root_bindings[0].intent(), 1);
    assert_eq!(tree.subintents[0].bindings[0].intent(), 0);
    admits(&tree);
}

/// The request a counterparty signs before any composer exists: whoever
/// hands them at least `amount` of X, they will bank it.
fn payment_request(amount: u128) -> IntentDecl {
    let chain = world();
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, ALICE, TEST_HEADER);
    let incoming = decl.declare(RES_X, [Constraint::MinAmount(amount)]);
    account::deposit(&mut decl, BOB, incoming).unwrap();
    decl.into_decl()
        .expect("the request consumes its own socket")
}

#[test]
fn a_presented_declaration_is_carried_verbatim() {
    let request = payment_request(100);
    // What the signer signed. Nothing the composition does may move it.
    let signed = request.hash(&TestHasher);

    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    let paid = root.export(funds);
    let wants = env.adopt(BOB, request).unwrap().one().unwrap();
    env.seal(root).unwrap().none().unwrap();
    env.bind(wants, paid).unwrap();
    let tree = env.build().unwrap();

    assert_eq!(tree.subintents[0].decl.hash(&TestHasher), signed);
    assert_eq!(tree.subintents[0].signer, BOB);
    assert_eq!(tree.subintents[0].bindings[0].intent(), 0);
    admits(&tree);
}

#[test]
fn a_presented_hole_the_composition_never_bound_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    // The composer took the request and then routed nothing to it.
    let _wants = env.adopt(BOB, payment_request(100)).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    env.seal(root).unwrap().none().unwrap();
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnfilledSocket {
            intent: 1,
            socket: 0
        })
    );
}

/// Acting as another party is a scope holding their proof — here from a
/// socket, filled by whoever proves it. The call names its target
/// itself, so there is no proof-as-actor spelling left to hand a badge
/// to.
#[test]
fn a_socket_proof_in_scope_acts_for_a_self_gated_call() {
    let chain = world();
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, ALICE, TEST_HEADER);

    let bob = decl.declare_proof(Claim::of_subject(BOB));
    let _funds = decl
        .presenting(bob, |decl| account::withdraw(decl, BOB, RES_X, 100))
        .expect("an identity's socket proof rides the gate in scope");
}

/// A socket consumed from the wrong channel is refused at `adopt` — the
/// same verdict admission reaches, still in the declaring intent's own
/// coordinates. The tier's own tokens cannot spell either shape, so the
/// declarations are bent by hand.
#[test]
fn an_adopted_socket_consumed_from_the_other_channel_is_refused() {
    let chain = world();

    // A value socket, presented as evidence by the consuming node.
    let mut request = payment_request(100);
    request.graph.nodes[0]
        .evidence
        .insert(EvidenceRef::Socket(0));
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert_eq!(
        env.adopt(BOB, request).map(|_| ()),
        Err(EnvelopeError::SocketChannelMismatch {
            intent: 1,
            socket: 0
        })
    );

    // An authority socket, filled into an argument position.
    let mut request = payment_request(100);
    request.sockets[0] = Socket::Authority(Claim::of_subject(ALICE));
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert_eq!(
        env.adopt(BOB, request).map(|_| ()),
        Err(EnvelopeError::SocketChannelMismatch {
            intent: 1,
            socket: 0
        })
    );
}

/// A presented record whose configuration nests past the vocabulary is
/// refused at build. The natural order computes the tree's identity
/// before any admission gate runs, and hashing takes the depth bound as
/// given — so the builder is where a too-deep record must stop.
#[test]
fn a_presented_record_too_deep_to_encode_refuses_at_build() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 5).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    let mut nested = Value::U64(0);
    for _ in 0..=MAX_VALUE_DEPTH {
        nested = Value::List(vec![nested]);
    }
    env.register_instance(InstanceMeta {
        package: pkg(),
        config: vec![nested],
        salt: Hash32([3; 32]),
    });
    env.seal(root).unwrap().none().unwrap();
    let refused = env
        .build()
        .expect_err("a record the wire could not carry never becomes a tree");
    assert_eq!(refused, EnvelopeError::InstanceValueTooDeep { instance: 0 });
}

#[test]
fn sockets_unpacked_at_the_wrong_arity_are_refused() {
    let chain = world();
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let wants = env.adopt(BOB, payment_request(100)).unwrap();
    // The composer expected an intent declaring nothing; the count is the
    // declaration's answer, not theirs.
    assert_eq!(
        wants.none(),
        Err(EnvelopeError::SocketArity {
            intent: 1,
            declared: 1,
            claimed: 0
        })
    );
}

#[test]
fn a_proof_offered_to_a_value_socket_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let offered = root
        .offer(alice_proof)
        .expect("the root's own proof offers");
    let wants = env.adopt(BOB, payment_request(100)).unwrap().one().unwrap();
    // The socket asks for funds; authority is not funds, however the
    // composer wired it.
    let refused = env
        .bind(wants, offered)
        .expect_err("a proof does not fill a value socket");
    assert_eq!(
        refused.cause,
        EnvelopeError::ProofForValueSocket {
            intent: 1,
            socket: 0
        }
    );
    // Both handles came back: route the right half through the same
    // socket and the composition completes.
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    let paid = root.export(funds);
    env.bind(refused.socket, paid).unwrap();
    env.seal(root).unwrap().none().unwrap();
    env.build().expect("the recovered socket was still open");
}

#[test]
fn a_presented_declaration_that_discharges_nothing_is_refused() {
    let chain = world();
    // A declaration carrying a socket its own graph never consumes. Its
    // signer cannot be made to have signed something else, so the only
    // place left to decline it is here, before a composer signs an
    // envelope around it.
    let mut malformed = payment_request(100);
    malformed
        .sockets
        .push(payment_request(50).sockets.remove(0));
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        env.adopt(BOB, malformed),
        Err(EnvelopeError::UnconsumedSocket {
            intent: 1,
            socket: 1
        })
    ));
}

#[test]
fn a_hole_the_graph_never_consumes_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    // Declared and then dropped: the yielded bucket would arrive with
    // nothing to receive it.
    let _taken = root.declare(RES_Y, []);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    assert!(matches!(
        env.seal(root),
        Err(EnvelopeError::UnconsumedSocket {
            intent: 0,
            socket: 0
        })
    ));
}

#[test]
fn a_hole_two_arguments_consume_is_refused() {
    let chain = world();
    // One yielded edge cannot be two deposits. The builder's own tokens
    // cannot spell the second consumption, so the reference arrives in a
    // declaration assembled elsewhere.
    let mut malformed = payment_request(100);
    let again = malformed.graph.nodes[0].clone();
    malformed.graph.nodes.push(again);
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        env.adopt(BOB, malformed),
        Err(EnvelopeError::SocketReused {
            intent: 1,
            socket: 0
        })
    ));
}

#[test]
fn a_parameter_the_intent_never_declared_is_refused() {
    let chain = world();
    let mut malformed = payment_request(100);
    for arg in &mut malformed.graph.nodes[0].args {
        if let GraphArg::Socket(socket) = arg {
            *socket = 3;
        }
    }
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        env.adopt(BOB, malformed),
        Err(EnvelopeError::UnknownSocket {
            intent: 1,
            socket: 3
        })
    ));
}

#[test]
fn a_hole_the_composition_never_bound_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let taken = root.declare(RES_Y, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    let _wants = env.seal(root).unwrap();
    // The graph discharged its side of the declaration; the composition
    // never discharged its own.
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnfilledSocket {
            intent: 0,
            socket: 0
        })
    );
}

#[test]
fn an_intent_still_under_construction_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, BOB, funds).unwrap();
    let _sub = env.subintent(BOB, TEST_HEADER);
    env.seal(root).unwrap().none().unwrap();
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnsealedIntent { intent: 1 })
    );
}

#[test]
fn a_handle_from_another_envelope_is_refused() {
    let chain = world();
    let (mut mine, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let taken = root.declare(RES_X, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    let wants = mine.seal(root).unwrap().one().unwrap();

    let (_theirs, mut other) = EnvelopeBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let funds = account::withdraw(&mut other, BOB, RES_X, 100).unwrap();
    let elsewhere = other.export(funds);
    let refused = mine
        .bind(wants, elsewhere)
        .expect_err("a handle from another envelope");
    assert_eq!(refused.cause, EnvelopeError::ForeignBinding);
}

/// An intent filling its own socket is a cycle admission names in
/// flattened-tree coordinates. The wiring refuses it against the intent
/// the author wrote — with the handles handed back, like every other
/// wiring refusal.
#[test]
fn an_intent_filling_its_own_socket_is_refused_at_the_wiring() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let taken = root.declare(RES_X, []);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 5).unwrap();
    let paid = root.export(funds);
    account::deposit(&mut root, ALICE, taken).unwrap();
    let wants = env.seal(root).unwrap().one().unwrap();
    let refused = env
        .bind(wants, paid)
        .expect_err("an intent cannot fill its own socket");
    assert_eq!(
        refused.cause,
        EnvelopeError::SelfFilledSocket {
            intent: 0,
            socket: 0
        }
    );
}

/// A proof's node index means nothing in another intent's graph. The
/// handle remembers its builder, so the mistake stops at the compose
/// site rather than reaching admission as a claim mismatch in
/// flattened-tree coordinates.
#[test]
fn a_proof_proved_by_another_intent_cannot_be_offered() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let sub = env.subintent(BOB, TEST_HEADER);
    assert_eq!(
        sub.offer(alice_proof).expect_err("a foreign proof"),
        EnvelopeError::ForeignProof,
    );
}

/// The same fence for the socket token: a position indexes the
/// declaration of the intent that declared it, and nothing else's. The
/// call itself survives — the refusal rides the graph and comes back at
/// the seal.
#[test]
fn a_socket_token_from_another_intent_cannot_be_consumed() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let theirs = {
        let mut sub = env.subintent(BOB, TEST_HEADER);
        sub.declare(RES_X, [])
    };
    account::deposit(&mut root, ALICE, theirs).unwrap();
    assert_eq!(
        env.seal(root).expect_err("a foreign socket"),
        EnvelopeError::Intent(TypedError::Build(BuildError::ForeignSocket)),
    );
}

proptest! {
    /// The tier's whole contract, over compositions of growing width: a
    /// composer paying each of several counterparties, every side's socket
    /// bound to the other's export.
    #[test]
    fn composed_envelopes_admit(
        legs in prop::collection::vec((100..1000u128, 1..100u128), 1..6),
    ) {
        let chain = world();
        let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);

        let mut paid = Vec::with_capacity(legs.len());
        for (pay, _) in &legs {
            let taken = root.declare(RES_Y, [Constraint::MinAmount(1)]);
    let funds = account::withdraw(&mut root, ALICE, RES_X, *pay).unwrap();
            paid.push(root.export(funds));
            account::deposit(&mut root, ALICE, taken).unwrap();
        }
        let mut wiring = env.seal(root).unwrap().into_vec();

        for (index, (_, receive)) in legs.iter().enumerate() {
            let signer = PrincipalAddr::new([u8::try_from(index).unwrap() + 1; 31]);
            let mut leg = env.subintent(signer, TEST_HEADER);
            let taken = leg.declare(RES_X, [Constraint::MinAmount(1)]);
    let funds = account::withdraw(&mut leg, signer, RES_Y, *receive).unwrap();
            let yielded = leg.export(funds);
            account::deposit(&mut leg, signer, taken).unwrap();
            let wants = env.seal(leg).unwrap().one().unwrap();
            env.bind(wiring.remove(0), yielded).unwrap();
            env.bind(wants, paid.remove(0)).unwrap();
        }

        let tree = env.build().expect("every socket is bound");
        admits(&tree);
    }
}

/// The party whose approval the note's own entry names.
const DESK: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
/// Whose namespace the note sits in — an issuer whose code never runs
/// here, because nothing about a movement involves the minter.
const MINTER: Address = Address::new([0x6A; 31], AddressClass::Component);

/// A note that moves only in a transaction the desk signed.
fn note_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Withdraw,
        RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(DESK)))
            .expect("a rule within the caps encodes"),
    );
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"note".to_vec()],
        rules,
    }
}

/// A holder's request, signed before any composer exists: whoever brings
/// the desk's approval may have the note moved.
///
/// The socket is the whole of what the holder undertakes. They name the
/// *claim* — the desk's — and leave whose node supplies it to whoever
/// composes, so the declaration means one thing however it is later
/// carried and the signer never has to have met the composer.
fn note_request(approver: Claim) -> IntentDecl {
    let chain = world();
    let note = note_meta().address(&TestHasher);
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, BOB, TEST_HEADER);
    let approval = decl.declare_proof(approver);
    let bob = account::authorize(&mut decl, BOB).unwrap();
    // Two proofs at one node: the holder's own gate takes theirs, and
    // the note's injected entry takes the desk's.
    let funds = decl
        .call_presenting([bob, approval], BOB, "withdraw", (note, 40u128))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut decl, BOB, funds).unwrap();
    decl.into_decl()
        .expect("the request presents its own socket")
}

/// The composition that fills it: the desk signs in and offers the claim
/// its own node mints.
fn approved(request: IntentDecl) -> Result<EnvelopeTree, EnvelopeError> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let desk = account::authorize(&mut root, DESK)?;
    let offered = root.offer(desk)?;
    let wants = env.adopt(BOB, request)?.one()?;
    env.seal(root)?.none()?;
    env.bind(wants, offered)?;
    env.register_resource(note_meta());
    env.build()
}

/// A proof crosses an intent boundary the only way one can: through a
/// socket the declaration typed and the composition filled.
///
/// Which is what makes the posture composable at all. The note's entry
/// asks about the transaction rather than about the holder, so somebody
/// has to present the desk's claim at the node that debits — and that
/// node is inside an intent the desk did not write and cannot touch.
/// The holder signs the shape of the authority they are asking for; the
/// desk answers for finding it, and pays.
#[test]
fn a_declared_hole_carries_a_proof_across_an_intent_boundary() {
    let request = note_request(Claim::of_subject(DESK));
    let signed = request.hash(&TestHasher);
    let tree = approved(request).expect("the desk composes the approval");

    assert_eq!(
        tree.subintents[0].decl.hash(&TestHasher),
        signed,
        "nothing the composition did moved what the holder signed",
    );
    let chain = world();
    let admitted = admit_tree(&tree, DESK, tree.hash(&TestHasher), &chain, &TestHasher)
        .expect("the approval satisfies the note's own entry");
    // The withdrawing node carries both claims: the holder's own, and
    // the desk's — which reached it from another intent entirely.
    let withdrawing = admitted
        .admitted
        .manifest()
        .nodes
        .iter()
        .find(|node| node.method == "withdraw")
        .expect("the request withdraws");
    assert!(withdrawing.evidence.contains(&Claim::of_subject(DESK)));
    assert!(withdrawing.evidence.contains(&Claim::of_subject(BOB)));
}

/// And a composition that binds a node minting some other claim is
/// refused, rather than quietly presenting it.
///
/// The declaration is what makes the socket worth signing: the holder
/// asked for the desk's approval, so a claim on anybody else is not the
/// authority they undertook to accept — however the composer wired it.
///
/// The one case in the corpus where the two numberings differ, so it is
/// what says the coordinates are the composer's. A socket belongs to the
/// intent that declared it; naming the node in the flattened manifest
/// beside it — node 2, socket 0 — put two numberings in one sentence and
/// read as correct, because for a bare graph they coincide. Intent 1's
/// node 1 is what the composer wrote.
#[test]
fn a_hole_bound_to_the_wrong_claim_is_refused() {
    let request = note_request(Claim::of_subject(ALICE));
    let tree = approved(request).expect("the composition still builds");
    let chain = world();
    assert_eq!(
        admit_tree(&tree, DESK, tree.hash(&TestHasher), &chain, &TestHasher),
        Err(AdmissionError::SocketClaimMismatch {
            intent: 1,
            node: 1,
            socket: 0
        }),
    );
}

/// The other half of the same wiring check: the socket asks for the
/// desk's approval, and an exported edge is not authority.
#[test]
fn an_edge_offered_to_an_authority_socket_is_refused() {
    let request = note_request(Claim::of_subject(DESK));
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let funds = account::withdraw(&mut root, DESK, RES_X, 5).unwrap();
    let paid = root.export(funds);
    let wants = env.adopt(BOB, request).unwrap().one().unwrap();
    let refused = env
        .bind(wants, paid)
        .expect_err("an edge does not fill an authority socket");
    assert_eq!(
        refused.cause,
        EnvelopeError::EdgeForAuthoritySocket {
            intent: 1,
            socket: 0
        }
    );
}
