//! The intent tier's contract: any tree it emits passes [`admit_tree`],
//! and the arithmetic over declarations that admission judges is judged
//! here first.
//!
//! The world is a few accounts and the resources they trade, which is
//! all a composition needs: what fills a socket is an ordinary edge or an
//! ordinary claim, and what makes it a composition is which declaration
//! it crosses.

use hyperscale_hbor::{Bytes, Capped};
use hyperscale_vm_effects::{
    AdmissionError, Binding, Claim, ClaimRef, Constraint, EdgeRef, GiveRef, GrantedBehaviour,
    GraphArg, Hash32, Hasher, InstanceMeta, Intent, IntentHeader, IntentRecord, IntentTree,
    MAX_VALUE_DEPTH, PackageHash, Records, ResourceGrants, ResourceKind, ResourceMeta, RuleBytes,
    Socket, StoredRule, TestHasher, Value, ValueRef, admit_tree,
};
use hyperscale_vm_manifest_builder::{
    BuildError, IntentBuilder, IntentError, Interface, Offered, TypedError,
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
const CAROL: PrincipalAddr = PrincipalAddr::new([0x40; 31]);
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

fn admits(tree: &IntentTree) {
    let chain = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, identity, &chain, &TestHasher).expect("a composed tree admits");
}

/// Bob's side of a trade, written before any composer exists: whoever
/// hands him at least `pay_x` of X gets the `pay_y` of Y he gives.
fn quote(pay_x: u128, pay_y: u128) -> Result<Intent, IntentError> {
    let chain = world();
    let mut bob = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let taken_x = bob.declare(RES_X, [Constraint::MinAmount(pay_x)]);
    let funds = account::withdraw(&mut bob, BOB, RES_Y, pay_y)?;
    bob.give(funds);
    account::deposit(&mut bob, BOB, taken_x)?;
    bob.into_decl()
}

/// The two-sided trade: Alice composes Bob's quote, withdraws what she
/// pays into his socket, and banks what he gives. Neither graph mentions
/// the other; the tree is the two edges between them.
fn swap(pay_x: u128, pay_y: u128) -> Result<IntentTree, IntentError> {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(quote(pay_x, pay_y)?)?;
    let wants_x = sockets.one()?;
    let paid_y = gives.one()?;
    let funds = account::withdraw(&mut root, ALICE, RES_X, pay_x)?;
    root.bind(wants_x, funds)?;
    account::deposit(&mut root, ALICE, paid_y.min(pay_y))?;
    root.build()
}

#[test]
fn a_composed_swap_admits() {
    let tree = swap(100, 10).unwrap();
    assert_eq!(tree.intents().len(), 2);
    let root = &tree.root;
    let [bob] = root.members.as_slice() else {
        panic!("the root composes Bob alone");
    };
    assert_eq!(bob.signed.intent.accounts, [BOB]);
    // The root declares nothing: it takes Bob's give as an argument of
    // its own deposit, under the constraint the author asserted, and
    // wires its own withdrawn edge into his socket.
    assert!(root.sockets.is_empty());
    assert!(root.gives.is_empty());
    assert!(root.graph.nodes.iter().any(|node| {
        node.args.iter().any(|arg| {
            *arg == GraphArg::give(
                GiveRef { member: 0, give: 0 },
                vec![Constraint::MinAmount(10)],
            )
        })
    }));
    assert_eq!(
        bob.wiring,
        [Binding::Value(ValueRef::Edge(EdgeRef {
            producer: 0,
            output: 0,
        }))]
    );
    assert_eq!(
        bob.signed.intent.gives,
        [ValueRef::Edge(EdgeRef {
            producer: 0,
            output: 0
        })]
    );
    admits(&tree);
}

/// The request a counterparty signs before any composer exists: whoever
/// hands them at least `amount` of X, they will bank it.
fn payment_request(amount: u128) -> Intent {
    let chain = world();
    let mut decl = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let incoming = decl.declare(RES_X, [Constraint::MinAmount(amount)]);
    account::deposit(&mut decl, BOB, incoming).unwrap();
    decl.into_decl()
        .expect("the request consumes its own socket")
}

/// Bob's offer: a withdrawal from Alice's vault, gated on an authority
/// he asks for by claim and cannot supply himself.
fn delegated_request() -> Intent {
    let chain = world();
    let mut decl = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let alice = decl.declare_proof(Claim::of_subject(ALICE));
    let funds = decl
        .presenting(alice, |decl| account::withdraw(decl, ALICE, RES_X, 100))
        .expect("the socket proof rides the gate in scope");
    account::deposit(&mut decl, BOB, funds).expect("the deposit types");
    decl.into_decl()
        .expect("the request consumes its own socket")
}

/// The composition grants the account it acts as, and the offer it
/// adopted is answered by it.
///
/// The offer was signed before the composition existed — it says which
/// authority it needs and never who supplies it. Nothing in either graph
/// proves the claim: what stands behind it is the sign-in Alice's own
/// shard judges over the keys that attested this composition.
#[test]
fn a_composition_grants_the_account_it_acts_as() {
    let request = delegated_request();
    // What Bob signed. Nothing the composition does may move it.
    let signed = request.hash(&TestHasher);

    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let wants = root
        .adopt(request)
        .expect("the request adopts")
        .sockets
        .one()
        .expect("the request declares one socket");
    root.bind(wants, ALICE)
        .expect("the composition grants its own account");
    let tree = root.build().expect("every socket is filled");
    assert_eq!(
        tree.root.members[0].signed.intent.hash(&TestHasher),
        signed,
        "nothing the composition did moved what Bob signed",
    );
    assert_eq!(
        tree.root.members[0].wiring,
        [Binding::Authority(ClaimRef::Account(ALICE))]
    );
    admits(&tree);
}

/// A grant of an account the composer does not act as is refused at the
/// wiring: the only signatures an intent holds are those of the accounts
/// it declares.
#[test]
fn a_grant_of_an_account_the_composer_is_not_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, CAROL, TEST_HEADER);
    let wants = root
        .adopt(delegated_request())
        .unwrap()
        .sockets
        .one()
        .unwrap();
    let refusal = root
        .bind(wants, ALICE)
        .expect_err("Carol's intent does not act as Alice");
    assert_eq!(
        refusal.cause,
        IntentError::GrantNotHeld {
            intent: 1,
            socket: 0,
            account: ALICE,
        }
    );
}

/// A grant routed to a value socket is refused at the wiring, with both
/// handles handed back: a grant is authority, and authority does not
/// fill an argument.
#[test]
fn a_grant_does_not_fill_a_value_socket() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let wants = root
        .adopt(payment_request(100))
        .expect("the request adopts")
        .sockets
        .one()
        .expect("the request declares one socket");
    let refusal = root
        .bind(wants, ALICE)
        .expect_err("a value socket takes an edge");
    assert_eq!(
        refusal.cause,
        IntentError::ProofForValueSocket {
            intent: 1,
            socket: 0
        }
    );
    // Both handles came back: route the right half through the same
    // socket and the composition completes.
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    root.bind(refusal.socket, funds).unwrap();
    root.build().expect("the recovered socket was still open");
}

/// A bucket refused at the wiring is handed back unspent, so the graph
/// still has it to consume.
#[test]
fn a_refused_edge_comes_back_unspent() {
    let request = delegated_request();
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let wants = root.adopt(request).unwrap().sockets.one().unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_Y, 5).unwrap();
    let refusal = root
        .bind(wants, funds)
        .expect_err("an authority socket takes no edge");
    assert_eq!(
        refusal.cause,
        IntentError::EdgeForAuthoritySocket {
            intent: 1,
            socket: 0
        }
    );
    let Offered::Edge(funds) = refusal.offered else {
        panic!("the edge came back");
    };
    account::deposit(&mut root, ALICE, funds).unwrap();
    root.bind(refusal.socket, ALICE).unwrap();
    admits(
        &root
            .build()
            .expect("the edge was spent once, by the deposit"),
    );
}

#[test]
fn a_presented_declaration_is_carried_verbatim() {
    let request = payment_request(100);
    // What the signer signed. Nothing the composition does may move it.
    let signed = request.hash(&TestHasher);

    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    let wants = root.adopt(request).unwrap().sockets.one().unwrap();
    root.bind(wants, funds).unwrap();
    let tree = root.build().unwrap();

    let [bob] = tree.root.members.as_slice() else {
        panic!("the root composes Bob alone");
    };
    assert_eq!(bob.signed.intent.hash(&TestHasher), signed);
    assert_eq!(bob.signed.intent.accounts, [BOB]);
    assert_eq!(
        bob.wiring,
        [Binding::Value(ValueRef::Edge(EdgeRef {
            producer: 0,
            output: 0,
        }))]
    );
    admits(&tree);
}

#[test]
fn a_presented_hole_the_composition_never_bound_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    // The composer took the request and then routed nothing to it.
    let _wants = root.adopt(payment_request(100)).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    assert_eq!(
        root.build(),
        Err(IntentError::UnfilledSocket {
            intent: 1,
            socket: 0
        })
    );
}

/// A member's give the composer never took is refused: value is
/// conserved, and a give nobody takes is an edge nobody consumes.
#[test]
fn a_give_the_composition_never_took_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives: _ } = root.adopt(quote(100, 10).unwrap()).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    root.bind(sockets.one().unwrap(), funds).unwrap();
    assert_eq!(
        root.build(),
        Err(IntentError::Structure(AdmissionError::UnconsumedGive {
            intent: 0,
            member: 0,
            give: 0
        }))
    );
}

/// Acting as another party is a scope holding their proof — here from a
/// socket, filled by whoever proves it. The call names its target
/// itself, so there is no proof-as-actor spelling left to hand a badge
/// to.
#[test]
fn a_socket_proof_in_scope_acts_for_a_self_gated_call() {
    let chain = world();
    let mut decl = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);

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
        .insert(ClaimRef::Socket(0))
        .unwrap();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert_eq!(
        root.adopt(request).map(|_| ()),
        Err(IntentError::Structure(AdmissionError::SocketKindMismatch {
            intent: 1,
            socket: 0,
            declared: "value",
            offered: "a proof",
        }))
    );

    // An authority socket, filled into an argument position.
    let mut request = payment_request(100);
    request.sockets[0] = Socket::Authority(Claim::of_subject(ALICE));
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert_eq!(
        root.adopt(request).map(|_| ()),
        Err(IntentError::Structure(AdmissionError::SocketKindMismatch {
            intent: 1,
            socket: 0,
            declared: "authority",
            offered: "an edge",
        }))
    );
}

/// A presented record whose configuration nests past the vocabulary is
/// refused at build. The natural order computes the tree's identity
/// before any admission gate runs, and hashing takes the depth bound as
/// given — so the builder is where a too-deep record must stop.
#[test]
fn a_presented_record_too_deep_to_encode_refuses_at_build() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 5).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    let mut nested = Value::U64(0);
    for _ in 0..=MAX_VALUE_DEPTH {
        nested = Value::List(vec![nested]);
    }
    let refused = root
        .build_presenting(
            vec![InstanceMeta {
                package: pkg(),
                config: Capped::new(vec![nested]).unwrap(),
                salt: Hash32([3; 32]),
            }],
            Vec::new(),
        )
        .expect_err("a record the wire could not carry never becomes a tree");
    assert_eq!(
        refused,
        IntentError::Structure(AdmissionError::InstanceValueTooDeep { instance: 0 })
    );
}

#[test]
fn handles_unpacked_at_the_wrong_arity_are_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(quote(100, 10).unwrap()).unwrap();
    // The composer expected an intent declaring nothing; the count is the
    // declaration's answer, not theirs.
    assert_eq!(
        sockets.none(),
        Err(IntentError::SocketArity {
            intent: 1,
            declared: 1,
            claimed: 0
        })
    );
    assert_eq!(
        gives.into_array::<2>().map(|_| ()),
        Err(IntentError::GiveArity {
            intent: 1,
            declared: 1,
            claimed: 2
        })
    );
}

#[test]
fn a_presented_declaration_that_discharges_nothing_is_refused() {
    let chain = world();
    // A declaration carrying a socket its own graph never consumes. Its
    // signer cannot be made to have signed something else, so the only
    // place left to decline it is here, before a composer signs a tree
    // around it.
    let mut malformed = payment_request(100);
    malformed
        .sockets
        .push(payment_request(50).sockets.remove(0))
        .unwrap();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        root.adopt(malformed),
        Err(IntentError::Structure(AdmissionError::UnconsumedSocket {
            intent: 1,
            socket: 1
        }))
    ));
}

/// A declaration giving an edge its graph does not produce is refused
/// at `adopt`, as admission would refuse the tree.
#[test]
fn a_presented_declaration_giving_what_it_does_not_hold_is_refused() {
    let chain = world();
    let mut malformed = quote(100, 10).unwrap();
    malformed.gives[0] = ValueRef::Edge(EdgeRef {
        producer: 7,
        output: 0,
    });
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        root.adopt(malformed),
        Err(IntentError::Structure(AdmissionError::UnknownGive {
            intent: 1,
            give: 0
        }))
    ));
}

#[test]
fn a_hole_the_graph_never_consumes_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    // Declared and then dropped: the yielded bucket would arrive with
    // nothing to receive it.
    let _taken = root.declare(RES_Y, []);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    assert!(matches!(
        root.into_decl(),
        Err(IntentError::Structure(AdmissionError::UnconsumedSocket {
            intent: 0,
            socket: 0
        }))
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
    malformed.graph.nodes.push(again).unwrap();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        root.adopt(malformed),
        Err(IntentError::Structure(AdmissionError::SocketReused {
            intent: 1,
            socket: 0
        }))
    ));
}

#[test]
fn a_parameter_the_intent_never_declared_is_refused() {
    let chain = world();
    let mut malformed = payment_request(100);
    for arg in &mut malformed.graph.nodes[0].args {
        if let GraphArg::Value {
            source: ValueRef::Socket(socket),
            ..
        } = arg
        {
            *socket = 3;
        }
    }
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    assert!(matches!(
        root.adopt(malformed),
        Err(IntentError::Structure(AdmissionError::UnknownSocket {
            intent: 1,
            node: 0,
            socket: 3
        }))
    ));
}

/// The root has nobody above it: a socket it declares is filled by
/// nothing, and a give it declares is taken by nothing.
#[test]
fn a_root_declaring_an_interface_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let taken = root.declare(RES_Y, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    assert_eq!(
        root.build(),
        Err(IntentError::Structure(AdmissionError::RootSockets {
            socket: 0
        }))
    );

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 5).unwrap();
    root.give(funds);
    assert_eq!(
        root.build(),
        Err(IntentError::Structure(AdmissionError::RootGives {
            give: 0
        }))
    );
}

/// Every handle names the builder that minted it, and a wiring refuses
/// one minted elsewhere: a socket, an edge, a give, or a proof of some
/// other intent reaches nothing here.
#[test]
fn a_handle_from_another_builder_is_refused() {
    let chain = world();
    let mut mine = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = mine.adopt(quote(100, 10).unwrap()).unwrap();
    let wants = sockets.one().unwrap();
    let given = gives.one().unwrap();

    let mut other = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let elsewhere = account::withdraw(&mut other, BOB, RES_X, 100).unwrap();
    let refused = mine
        .bind(wants, elsewhere)
        .expect_err("an edge from another builder");
    assert_eq!(refused.cause, IntentError::ForeignBinding);

    let mut theirs = IntentBuilder::new(&chain, &TestHasher, CAROL, TEST_HEADER);
    let Interface { sockets, gives } = theirs.adopt(delegated_request()).unwrap();
    gives.none().unwrap();
    let held = account::present_badge(&mut mine, ALICE, RES_X).unwrap();
    let refused = theirs
        .bind(sockets.one().unwrap(), held)
        .expect_err("a proof from another builder");
    assert_eq!(refused.cause, IntentError::ForeignBinding);
    assert_eq!(theirs.give_on(given), Err(IntentError::ForeignBinding));
}

/// The same fence for the tokens a graph consumes: a socket position
/// indexes the declaration of the intent that declared it, and a give
/// the members of the intent that composes it. The call itself survives
/// — the refusal rides the graph and comes back at the finish.
#[test]
fn a_token_from_another_intent_cannot_be_consumed() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let theirs = {
        let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
        sub.declare(RES_X, [])
    };
    account::deposit(&mut root, ALICE, theirs).unwrap();
    assert_eq!(
        root.into_decl().expect_err("a foreign socket"),
        IntentError::Intent(TypedError::Build(BuildError::ForeignSocket)),
    );

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let theirs = {
        let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
        let Interface { sockets: _, gives } = sub.adopt(quote(100, 10).unwrap()).unwrap();
        gives.one().unwrap()
    };
    account::deposit(&mut root, ALICE, theirs).unwrap();
    assert_eq!(
        root.into_decl().expect_err("a foreign give"),
        IntentError::Intent(TypedError::Build(BuildError::ForeignGive)),
    );
}

/// A member fed from its own give waits on itself: a cycle admission
/// names in tree coordinates, refused at the wiring against the member
/// the author placed — with the handles handed back, like every other
/// wiring refusal.
#[test]
fn a_member_filled_from_its_own_give_is_refused_at_the_wiring() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(quote(100, 10).unwrap()).unwrap();
    let refused = root
        .bind(sockets.one().unwrap(), gives.one().unwrap())
        .expect_err("a member cannot fill its own socket");
    assert_eq!(
        refused.cause,
        IntentError::SelfFilledSocket {
            intent: 1,
            socket: 0
        }
    );
}

/// What fills a socket is bounded by the socket's own declaration, so a
/// handle wired in carrying constraints of its own is refused rather
/// than silently stripped.
#[test]
fn a_constrained_handle_is_not_wired_into_a_socket() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let wants = root
        .adopt(payment_request(100))
        .unwrap()
        .sockets
        .one()
        .unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    let refused = root
        .bind(wants, funds.min(100))
        .expect_err("the socket bounds what fills it");
    assert_eq!(
        refused.cause,
        IntentError::ConstrainedOffering {
            intent: 1,
            socket: 0
        }
    );
}

proptest! {
    /// The tier's whole contract, over compositions of growing width: a
    /// composer paying each of several counterparties, every quote's
    /// socket filled from the composer's own withdrawal and every give
    /// banked.
    #[test]
    fn composed_trees_admit(
        legs in prop::collection::vec((100..1000u128, 1..100u128), 1..6),
    ) {
        let chain = world();
        let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
        for (index, (pay, receive)) in legs.iter().enumerate() {
            let signer = PrincipalAddr::new([u8::try_from(index).unwrap() + 1; 31]);
            let mut leg = IntentBuilder::new(&chain, &TestHasher, signer, TEST_HEADER);
            let taken = leg.declare(RES_X, [Constraint::MinAmount(1)]);
            let funds = account::withdraw(&mut leg, signer, RES_Y, *receive).unwrap();
            leg.give(funds);
            account::deposit(&mut leg, signer, taken).unwrap();
            let Interface { sockets, gives } = root
                .adopt(leg.into_decl().unwrap())
                .unwrap();
            let funds = account::withdraw(&mut root, ALICE, RES_X, *pay).unwrap();
            root.bind(sockets.one().unwrap(), funds).unwrap();
            account::deposit(&mut root, ALICE, gives.one().unwrap().min(1)).unwrap();
        }
        let tree = root.build().expect("every socket is bound");
        admits(&tree);
    }
}

/// A user across two accounts: one intent acting as both, each
/// withdrawal gated on its own account and answered by the one attesting
/// set, one nullifier per account.
#[test]
fn a_user_composes_across_two_accounts() {
    let chain = world();
    let mut root = IntentBuilder::acting_as(&chain, &TestHasher, &[ALICE, BOB], TEST_HEADER)
        .expect("two accounts");
    let x = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, BOB, x).unwrap();
    let y = account::withdraw(&mut root, BOB, RES_Y, 10).unwrap();
    account::deposit(&mut root, ALICE, y).unwrap();
    let tree = root.build().expect("one intent, two accounts");

    assert_eq!(tree.intents().len(), 1);
    assert_eq!(tree.root.accounts, [ALICE, BOB]);
    assert_eq!(tree.root.attested_by, [ALICE, BOB]);
    let admitted = admit_tree(&tree, tree.hash(&TestHasher), &chain, &TestHasher)
        .expect("both sign-ins are the intent's own");
    let [record] = admitted.intents() else {
        panic!("one intent");
    };
    assert_eq!(record.accounts().collect::<Vec<_>>(), [ALICE, BOB]);
    // Each withdrawal presents the account it draws from and no other:
    // its gate names one account, read whole, so the node places on
    // that account's shard alone.
    let manifest = admitted.manifest();
    assert_eq!(manifest.nodes[0].evidence, [Claim::of_subject(ALICE)]);
    assert_eq!(manifest.nodes[2].evidence, [Claim::of_subject(BOB)]);
}

/// The attesting set is the builder's to declare: left alone it is the
/// accounts' own keys, declared it is whatever the accounts' rules have
/// to admit — and either way it is signed content the intent hash
/// covers.
#[test]
fn an_intent_declares_who_attests_it() {
    let chain = world();
    let mut own = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let funds = account::withdraw(&mut own, ALICE, RES_X, 1).unwrap();
    account::deposit(&mut own, BOB, funds).unwrap();
    let own = own.into_decl().expect("a leaf");
    assert_eq!(own.attested_by, [ALICE]);

    let mut delegated = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    delegated.attested_by([CAROL]);
    let funds = account::withdraw(&mut delegated, ALICE, RES_X, 1).unwrap();
    account::deposit(&mut delegated, BOB, funds).unwrap();
    let delegated = delegated.into_decl().expect("a delegate's leaf");
    assert_eq!(delegated.accounts, [ALICE]);
    assert_eq!(delegated.attested_by, [CAROL]);
    assert_ne!(own.hash(&TestHasher), delegated.hash(&TestHasher));
}

/// A quote assembled into a basket and sold on: Carol composes Bob's
/// quote and presents its interface as her own — a socket for the X Bob
/// wants, passed through, and a give of the Y he produces, given on —
/// and Alice composes Carol's basket without ever seeing Bob.
fn basket(pay_x: u128, pay_y: u128) -> Result<IntentTree, IntentError> {
    let chain = world();
    let mut carol = IntentBuilder::new(&chain, &TestHasher, CAROL, TEST_HEADER);
    let Interface { sockets, gives } = carol.adopt(quote(pay_x, pay_y)?)?;
    let incoming = carol.declare(RES_X, []);
    carol.bind(sockets.one()?, incoming)?;
    carol.give_on(gives.one()?)?;
    let carol = carol.into_decl()?;

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(carol)?;
    let funds = account::withdraw(&mut root, ALICE, RES_X, pay_x)?;
    root.bind(sockets.one()?, funds)?;
    account::deposit(&mut root, ALICE, gives.one()?.min(pay_y))?;
    root.build()
}

/// A sealed group is indistinguishable from a leaf: the same composing
/// intent over the basket and over the bare quote produces the same
/// flattening, and the basket's own interface is the wire's pass-through
/// and re-give.
#[test]
fn a_quote_grouped_into_a_basket_flattens_as_the_quote_does() {
    let tree = basket(100, 10).expect("the basket composes");
    let [carol] = tree.root.members.as_slice() else {
        panic!("the root composes Carol alone");
    };
    assert_eq!(carol.signed.intent.accounts, [CAROL]);
    assert_eq!(
        carol.signed.intent.sockets,
        [Socket::Value {
            resource: RES_X,
            constraints: Vec::new(),
        }]
    );
    assert_eq!(
        carol.signed.intent.gives,
        [ValueRef::Give(GiveRef { member: 0, give: 0 })]
    );
    let [bob] = carol.signed.intent.members.as_slice() else {
        panic!("Carol composes Bob alone");
    };
    assert_eq!(bob.wiring, [Binding::Value(ValueRef::Socket(0))]);
    assert!(carol.signed.intent.graph.nodes.is_empty());

    let chain = world();
    let grouped =
        admit_tree(&tree, tree.hash(&TestHasher), &chain, &TestHasher).expect("the group resolves");
    let flat = swap(100, 10).unwrap();
    let leaf = admit_tree(&flat, flat.hash(&TestHasher), &chain, &TestHasher).unwrap();
    assert_eq!(grouped.manifest(), leaf.manifest());
    assert_eq!(
        grouped
            .intents()
            .iter()
            .flat_map(IntentRecord::accounts)
            .collect::<Vec<_>>(),
        [ALICE, CAROL, BOB]
    );
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
        material: Capped::new(vec![Bytes::new(b"note".to_vec()).unwrap()]).unwrap(),
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
fn note_request(approver: Claim) -> Intent {
    let chain = world();
    let note = note_meta().address(&TestHasher);
    let mut decl = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let approval = decl.declare_proof(approver);
    // The socket is there for the note's injected entry, whose claim is
    // the desk's; the holder's own gate is answered by the signature
    // their intent carries.
    let funds = decl
        .presenting(approval, |b| b.call(BOB, "withdraw", (note, 40u128)))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut decl, BOB, funds).unwrap();
    decl.into_decl()
        .expect("the request presents its own socket")
}

/// The composition that fills it: the desk grants the account its own
/// intent acts as.
fn approved(request: Intent) -> Result<IntentTree, IntentError> {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root.adopt(request)?.sockets.one()?;
    root.bind(wants, DESK)?;
    root.build_presenting(Vec::new(), vec![note_meta()])
}

/// A transfer whose regulated leg is granted by the composer: a proof
/// crosses an intent boundary the only way one can, through a socket
/// the declaration typed and the composition filled.
///
/// Which is what makes the posture composable at all. The note's entry
/// asks about the transaction rather than about the holder, so somebody
/// has to present the desk's claim at the node that debits — and that
/// node is inside an intent the desk did not write and cannot touch.
/// The holder signs the shape of the authority they are asking for; the
/// desk answers for finding it, and pays.
#[test]
fn a_regulated_leg_is_granted_by_the_composer() {
    let request = note_request(Claim::of_subject(DESK));
    let signed = request.hash(&TestHasher);
    let tree = approved(request).expect("the desk composes the approval");

    assert_eq!(
        tree.root.members[0].signed.intent.hash(&TestHasher),
        signed,
        "nothing the composition did moved what the holder signed",
    );
    let chain = world();
    let admitted = admit_tree(&tree, tree.hash(&TestHasher), &chain, &TestHasher)
        .expect("the approval satisfies the note's own entry");
    // The withdrawing node carries both claims: the holder's own, and
    // the desk's — which reached it from another intent entirely.
    let withdrawing = admitted
        .manifest()
        .nodes
        .iter()
        .find(|node| node.method == "withdraw")
        .expect("the request withdraws");
    assert!(withdrawing.evidence.contains(&Claim::of_subject(DESK)));
    assert!(withdrawing.evidence.contains(&Claim::of_subject(BOB)));
}

/// A claim granted two levels deep is re-granted at every level: Carol
/// declares a socket for the desk's approval, grants that socket on into
/// the holder's request, and the desk grants its account into Carol's.
/// Carol cannot grant the desk's account herself — she does not act as
/// it — and nothing else she holds carries the claim.
#[test]
fn a_claim_granted_two_levels_deep_is_regranted_at_every_level() {
    let chain = world();
    let mut carol = IntentBuilder::new(&chain, &TestHasher, CAROL, TEST_HEADER);
    let wants = carol
        .adopt(note_request(Claim::of_subject(DESK)))
        .unwrap()
        .sockets
        .one()
        .unwrap();
    let refused = carol
        .bind(wants, DESK)
        .expect_err("Carol does not act as the desk");
    assert_eq!(
        refused.cause,
        IntentError::GrantNotHeld {
            intent: 1,
            socket: 0,
            account: DESK,
        }
    );
    let approval = carol.declare_proof(Claim::of_subject(DESK));
    carol
        .bind(refused.socket, approval)
        .expect("a socket of her own carrying the claim");
    let carol = carol.into_decl().expect("the group's socket is passed on");
    assert_eq!(
        carol.members[0].wiring,
        [Binding::Authority(ClaimRef::Socket(0))]
    );

    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root.adopt(carol).unwrap().sockets.one().unwrap();
    root.bind(wants, DESK).unwrap();
    let tree = root
        .build_presenting(Vec::new(), vec![note_meta()])
        .unwrap();
    let admitted = admit_tree(&tree, tree.hash(&TestHasher), &chain, &TestHasher)
        .expect("re-granted at every level");
    let withdrawing = admitted
        .manifest()
        .nodes
        .iter()
        .find(|node| node.method == "withdraw")
        .expect("the request withdraws");
    assert!(withdrawing.evidence.contains(&Claim::of_subject(DESK)));
}

/// A proof one of the composer's own nodes minted is granted the same
/// way an account is: the node stands where it stood, and what crosses
/// is the claim it proves.
#[test]
fn a_node_proof_is_granted_into_a_member() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root
        .adopt(note_request(Claim::of_subject(RES_Y)))
        .unwrap()
        .sockets
        .one()
        .unwrap();
    let held = account::present_badge(&mut root, DESK, RES_Y).unwrap();
    root.bind(wants, held).unwrap();
    let tree = root.build().unwrap();
    assert_eq!(
        tree.root.members[0].wiring,
        [Binding::Authority(ClaimRef::Node(0))]
    );
}

/// And a composition granting some other claim is refused, rather than
/// quietly presenting it.
///
/// The declaration is what makes the socket worth signing: the holder
/// asked for the desk's approval, so a claim on anybody else is not the
/// authority they undertook to accept — however the composer wired it.
/// The socket's coordinates are the composer's, and a socket belongs to
/// the intent that declared it: intent 1's socket 0 is what they wrote.
#[test]
fn a_hole_bound_to_the_wrong_claim_is_refused() {
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root
        .adopt(note_request(Claim::of_subject(ALICE)))
        .unwrap()
        .sockets
        .one()
        .unwrap();
    root.bind(wants, DESK).unwrap();
    let tree = root
        .build_presenting(Vec::new(), vec![note_meta()])
        .expect("the composition still builds");
    assert_eq!(
        admit_tree(&tree, tree.hash(&TestHasher), &chain, &TestHasher),
        Err(AdmissionError::GrantClaimMismatch {
            intent: 1,
            socket: 0
        }),
    );
}

/// The other half of the same wiring check: the socket asks for the
/// desk's approval, and an edge is not authority.
#[test]
fn an_edge_offered_to_an_authority_socket_is_refused() {
    let request = note_request(Claim::of_subject(DESK));
    let chain = world();
    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let funds = account::withdraw(&mut root, DESK, RES_X, 5).unwrap();
    let wants = root.adopt(request).unwrap().sockets.one().unwrap();
    let refused = root
        .bind(wants, funds)
        .expect_err("an edge does not fill an authority socket");
    assert_eq!(
        refused.cause,
        IntentError::EdgeForAuthoritySocket {
            intent: 1,
            socket: 0
        }
    );
}
