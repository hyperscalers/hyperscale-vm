//! The envelope tier's contract: any envelope it emits passes
//! [`admit_tree`], and the arithmetic over declarations that admission
//! judges is judged here first.
//!
//! The world is two accounts and the resources they trade, which is all a
//! composition needs: what fills a socket is an ordinary edge or an
//! ordinary proof, and what makes it a composition is which graph it
//! crosses.

use hyperscale_vm_effects::{
    AdmissionError, Claim, Constraint, EnvelopeTree, GrantedBehaviour, Hasher, IntentDecl,
    PackageHash, Records, ResourceGrants, ResourceKind, ResourceMeta, RuleBytes, StoredRule,
    TestHasher, admit_tree,
};
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, EnvelopeError, IntentBuilder, SocketRef};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{Address, AddressClass, PrincipalAddr, ResourceAddr};
use proptest::prelude::{prop, proptest};

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
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);

    let taken_y = root.declare(RES_Y, [Constraint::MinAmount(pay_y)]);
    let alice_proof = account::authorize(&mut root, ALICE)?;
    let funds = account::withdraw(&mut root, alice_proof, RES_X, pay_x)?;
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken_y)?;

    let mut sub = env.subintent(BOB);
    let taken_x = sub.declare(RES_X, [Constraint::MinAmount(pay_x)]);
    let bob_proof = account::authorize(&mut sub, BOB)?;
    let funds = account::withdraw(&mut sub, bob_proof, RES_Y, pay_y)?;
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken_x)?;

    let wants_y = env.seal(root)?.one()?;
    let wants_x = env.seal(sub)?.one()?;
    env.bind(wants_y, paid_y);
    env.bind(wants_x, paid_x);
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
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, ALICE);
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
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, 100).unwrap();
    let paid = root.export(funds);
    let wants = env.present(BOB, request).unwrap().one().unwrap();
    env.seal(root).unwrap().none().unwrap();
    env.bind(wants, paid);
    let tree = env.build().unwrap();

    assert_eq!(tree.subintents[0].decl.hash(&TestHasher), signed);
    assert_eq!(tree.subintents[0].signer, BOB);
    assert_eq!(tree.subintents[0].bindings[0].intent(), 0);
    admits(&tree);
}

#[test]
fn a_presented_hole_the_composition_never_bound_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    // The composer took the request and then routed nothing to it.
    let _wants = env.present(BOB, payment_request(100)).unwrap();
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, 100).unwrap();
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

#[test]
fn sockets_unpacked_at_the_wrong_arity_are_refused() {
    let chain = world();
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let wants = env.present(BOB, payment_request(100)).unwrap();
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
    let (mut env, _root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    assert!(matches!(
        env.present(BOB, malformed),
        Err(EnvelopeError::UnconsumedSocket {
            intent: 1,
            socket: 1
        })
    ));
}

#[test]
fn a_hole_the_graph_never_consumes_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    // Declared and then dropped: the yielded bucket would arrive with
    // nothing to receive it.
    let _taken = root.declare(RES_Y, []);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, 100).unwrap();
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
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let taken = root.declare(RES_Y, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    // One yielded edge cannot be two deposits; the second reference is a
    // `Socket` the tier did not mint.
    account::deposit(&mut root, ALICE, SocketRef(0)).unwrap();
    assert!(matches!(
        env.seal(root),
        Err(EnvelopeError::SocketReused {
            intent: 0,
            socket: 0
        })
    ));
}

#[test]
fn a_parameter_the_intent_never_declared_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    account::deposit(&mut root, ALICE, SocketRef(3)).unwrap();
    assert!(matches!(
        env.seal(root),
        Err(EnvelopeError::UnknownSocket {
            intent: 0,
            socket: 3
        })
    ));
}

#[test]
fn a_hole_the_composition_never_bound_is_refused() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
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
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, 100).unwrap();
    account::deposit(&mut root, BOB, funds).unwrap();
    let _sub = env.subintent(BOB);
    env.seal(root).unwrap().none().unwrap();
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnsealedIntent { intent: 1 })
    );
}

#[test]
#[should_panic(expected = "filled within the envelope that opened it")]
fn a_handle_from_another_envelope_is_refused() {
    let chain = world();
    let (mut mine, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, BOB);
    let taken = root.declare(RES_X, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    let wants = mine.seal(root).unwrap().one().unwrap();

    let (_theirs, mut other) = EnvelopeBuilder::new(&chain, &TestHasher, BOB);
    let bob_proof = account::authorize(&mut other, BOB).unwrap();
    let funds = account::withdraw(&mut other, bob_proof, RES_X, 100).unwrap();
    let elsewhere = other.export(funds);
    mine.bind(wants, elsewhere);
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
        let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);

        let mut paid = Vec::with_capacity(legs.len());
        for (pay, _) in &legs {
            let taken = root.declare(RES_Y, [Constraint::MinAmount(1)]);
            let alice_proof = account::authorize(&mut root, ALICE).unwrap();
    let funds = account::withdraw(&mut root, alice_proof, RES_X, *pay).unwrap();
            paid.push(root.export(funds));
            account::deposit(&mut root, ALICE, taken).unwrap();
        }
        let mut wiring = env.seal(root).unwrap().into_vec();

        for (index, (_, receive)) in legs.iter().enumerate() {
            let signer = PrincipalAddr::new([u8::try_from(index).unwrap() + 1; 31]);
            let mut leg = env.subintent(signer);
            let taken = leg.declare(RES_X, [Constraint::MinAmount(1)]);
            let signer_proof = account::authorize(&mut leg, signer).unwrap();
    let funds = account::withdraw(&mut leg, signer_proof, RES_Y, *receive).unwrap();
            let yielded = leg.export(funds);
            account::deposit(&mut leg, signer, taken).unwrap();
            let wants = env.seal(leg).unwrap().one().unwrap();
            env.bind(wiring.remove(0), yielded);
            env.bind(wants, paid.remove(0));
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
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, BOB);
    let approval = decl.declare_proof(approver);
    let bob = account::authorize(&mut decl, BOB).unwrap();
    // Two proofs at one node: the holder's own gate takes theirs, and
    // the note's injected entry takes the desk's.
    let funds = decl
        .call_presenting(&[bob, approval], BOB, "withdraw", (note, 40u128))
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
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, DESK);
    let desk = account::authorize(&mut root, DESK)?;
    let offered = root.offer(desk);
    let wants = env.present(BOB, request)?.one()?;
    env.seal(root)?.none()?;
    env.bind(wants, offered);
    env.resource(note_meta());
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
