//! A resource authored to grant restrictions, and what its address says.
//!
//! `guests/security` writes the rule down through the macro's own
//! spelling — `grants(withdraw = issued(Registered), deposit =
//! issued(Registered))` — where every other fixture here builds a
//! [`ResourceMeta`] by hand. What that
//! separates is the derivation from the enforcement: a hand-built record
//! proves admission judges the entry it is given, and this proves the
//! entry an author wrote is the entry admission judges.
//!
//! The two claims below are the ones nothing else can make. **The class
//! byte follows what the entries do**, which is load-bearing rather than
//! tidy: the rules are absent from the record, so the tag is the one
//! thing a reader gets without resolving anything, and there is no second
//! source to cross-check it against. And **a badge carries its own rules
//! into the leaf that names it**, without which a soulbound credential —
//! the shape a register wants, since one that can be handed on is a
//! register anybody may join — would name an address nothing is ever
//! minted at.

mod common;

use std::collections::BTreeSet;

use common::{ALICE, BOB, pkg, world};
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_vm_effects::{
    AdmissionError, Binding, Claim, ClaimRef, EdgeRef, GrantedBehaviour, GraphArg, GraphNode,
    Hash32, InstanceMeta, Intent, IntentHeader, IntentTree, Issuance, JudgedLeaf, LegRole,
    ManifestGraph, Member, PrefixShardResolver, Records, ResourceMeta, Rule, ShardResolver,
    SignedIntent, Socket, TestHasher, Value, admit_tree, granting_issued_resource,
    holdings_collection, legs_of, star_at,
};
use hyperscale_vm_fixtures::security;
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Effect, EffectTarget, Mode, NetworkId, Presence,
    PrincipalAddr, ResourceAddr,
};

/// Any network; these tests only need every intent to name the same one.
const TEST_NETWORK: NetworkId = NetworkId(242);

/// Any window; these tests never validate one against a clock.
const TEST_HEADER: IntentHeader = IntentHeader {
    network: TEST_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

/// Who keeps the register: the identity the issuer's configuration names.
const REGISTRAR: PrincipalAddr = PrincipalAddr::new([0x71; 31]);

/// What the issuer's instance address folds.
fn config() -> Vec<Value> {
    vec![Value::Address(REGISTRAR.into())]
}

/// The issuer, published and instantiated.
fn issuer() -> (Records, ComponentAddr) {
    let mut chain = world();
    chain
        .packages
        .publish_unchecked(pkg("security"), security::metadata());
    let meta = InstanceMeta {
        package: pkg("security"),
        config: Capped::new(config()).unwrap(),
        salt: Hash32([0x5E; 32]),
    };
    let address: ComponentAddr = meta.address(&TestHasher);
    chain.instances.create(&TestHasher, meta);
    (chain, address)
}

/// The issuance the guest declares for `mark`, read off its own
/// declaration rather than restated here.
fn issuance(mark: &[u8]) -> Issuance {
    security::metadata()
        .methods
        .into_values()
        .flat_map(|signature| signature.issues)
        .find(|issuance| issuance.mark == mark)
        .expect("the guest issues this mark")
}

/// The address `mark` derives under `issuer`, folding the rules the
/// guest's declaration grants it.
fn issued(issuer: ComponentAddr, mark: &[u8]) -> ResourceAddr {
    let issuance = issuance(mark);
    let rules = issuance
        .grants
        .resolve(&TestHasher, issuer.into(), &config())
        .expect("the declared grants resolve against the instance");
    granting_issued_resource(&TestHasher, issuer, issuance.kind, &rules, mark)
}

/// The record an envelope presents for `mark`: the address preimage, as
/// a composer builds it from the package and the configuration.
fn record(issuer: ComponentAddr, mark: &[u8]) -> ResourceMeta {
    let issuance = issuance(mark);
    ResourceMeta {
        namespace: issuer.into(),
        kind: issuance.kind,
        material: Capped::new(vec![
            Bytes::new(Value::Bytes(mark.to_vec()).canonical_bytes()).unwrap(),
        ])
        .unwrap(),
        rules: issuance
            .grants
            .resolve(&TestHasher, issuer.into(), &config())
            .expect("the declared grants resolve against the instance"),
    }
}

/// What answers whether `owner` holds `badge`: their own interval for
/// it, holding anything at all.
///
/// An interval rather than a leaf because the register is non-fungible,
/// and an instance's id is its order key — so the interval that can hold
/// one is the whole `u64` space, capped at the single entry that answers
/// the question.
fn credential(owner: impl Into<Address>, badge: ResourceAddr) -> EffectTarget {
    let owner = owner.into();
    EffectTarget::Range {
        owner,
        collection: holdings_collection(&TestHasher, owner, badge),
        lo: 0,
        hi: u128::from(u64::MAX),
        cap: 1,
    }
}

/// A withdrawal of `resource` from [`ALICE`]'s own account, banked back
/// into it — an ordinary transfer declaring nothing about any rule.
fn transfer(resource: ResourceAddr) -> IntentTree {
    transfer_to(resource, ALICE)
}

/// The same transfer, landing under `recipient`.
fn transfer_to(resource: ResourceAddr, recipient: PrincipalAddr) -> IntentTree {
    IntentTree {
        root: Intent::leaf(
            TEST_HEADER,
            ALICE,
            ManifestGraph {
                nodes: Capped::new(vec![
                    GraphNode {
                        target: ALICE.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(resource.address())),
                            GraphArg::Literal(Value::U128(40)),
                        ],
                        evidence: Capped::new(BTreeSet::from([ClaimRef::Account(ALICE)])).unwrap(),
                    },
                    GraphNode {
                        target: recipient.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::edge(
                            EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            Vec::new(),
                        )],
                        evidence: Capped::new(BTreeSet::default()).unwrap(),
                    },
                ])
                .unwrap(),
            },
        ),
        instances: Capped::empty(),
        resources: Capped::empty(),
    }
}

/// The class byte follows what a resource's entries *do*, not whether it
/// grants anything.
///
/// Three marks from one issuer. Two carry a movement entry and take
/// `Restricted`; the third grants an authority and stays plain, because
/// an authority answers for itself — an absent record withholds a
/// capability, where it would let a movement proceed. So a capped,
/// burnable, recallable resource costs a holder nothing on the transfer
/// path, and the tag never over-warns.
#[test]
fn the_class_follows_what_the_entries_do() {
    let (_, issuer) = issuer();
    let share = issued(issuer, b"Share");
    let registered = issued(issuer, b"Registered");
    let bearer = issued(issuer, b"Bearer");

    assert_eq!(
        share.address().class(),
        AddressClass::Restricted,
        "a withdraw entry is a movement its absence would permit",
    );
    assert_eq!(
        registered.address().class(),
        AddressClass::Restricted,
        "so is refusing every withdrawal of the credential itself",
    );
    assert_eq!(
        bearer.address().class(),
        AddressClass::Resource,
        "a recall entry answers for itself, so it costs the transfer path nothing",
    );
    assert_ne!(share, bearer, "and they are different resources");
}

/// The rule an author wrote is the rule admission injects, against a
/// holder the package never named.
///
/// Nothing in [`transfer`] mentions a credential, a register, or the
/// issuer. What binds the movement is the resource's own address, and the
/// leaf it resolves to is the one the issuer's `register` mints into — so
/// the register a transfer agent maintains and the cell the seam reads
/// are one fact rather than two that agree by inspection.
#[test]
fn an_authored_rule_governs_a_holder_the_package_never_named() {
    let (chain, issuer) = issuer();
    let share = issued(issuer, b"Share");
    let registered = issued(issuer, b"Registered");

    let mut env = transfer(share);
    env.resources = Capped::new(vec![record(issuer, b"Share")]).unwrap();
    let admitted =
        admit_tree(&env, env.hash(&TestHasher), &chain, &TestHasher).expect("the transfer admits");
    let declaration = admitted.declaration();

    let held = credential(ALICE, registered);
    assert!(
        declaration.required().any(|rule| *rule
            == Rule::Require(JudgedLeaf::Presence {
                target: held,
                expect: Presence::Present,
            })),
        "the withdrawal is judged against the mover's own register entry",
    );
    assert!(
        declaration.set.contains(&Effect {
            target: held,
            mode: Mode::Read,
        }),
        "and the interval is provisioned by the declaration that reads it",
    );

    // What the non-fungible kind costs, stated where it is paid. The
    // question is the same one a balance answered — is this party on the
    // register — and one seek answers it either way; what changed is that
    // an interval is priced by the span it declares, and this one spans
    // the id space. Every transfer of the share class pays it.
    assert!(
        declaration.required().any(|rule| matches!(
            rule,
            Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Range { lo: 0, hi, cap: 1, .. },
                ..
            }) if *hi == u128::from(u64::MAX)
        )),
        "the register is read as an interval over the whole id space: {:?}",
        declaration.conditions,
    );
}

/// Each side of an edge answers for its own vault, at the frame where
/// that vault moves.
///
/// The two entries are independent authorizations rather than a relation
/// between the parties: the debit asks the sender's register entry and
/// the credit asks the recipient's, and neither names the other. So a
/// register is a set of holders rather than a table of permitted pairs,
/// which is what makes it the thing a transfer agent already maintains.
#[test]
fn each_side_of_a_transfer_answers_for_its_own_register_entry() {
    let (chain, issuer) = issuer();
    let share = issued(issuer, b"Share");
    let registered = issued(issuer, b"Registered");

    let mut env = transfer_to(share, BOB);
    env.resources = Capped::new(vec![record(issuer, b"Share")]).unwrap();
    let admitted =
        admit_tree(&env, env.hash(&TestHasher), &chain, &TestHasher).expect("the transfer admits");
    let conditions: Vec<_> = admitted.declaration().required().cloned().collect();

    for holder in [Address::from(ALICE), Address::from(BOB)] {
        assert!(
            conditions.contains(&Rule::Require(JudgedLeaf::Presence {
                target: credential(holder, registered),
                expect: Presence::Present,
            })),
            "{holder:?} is asked for their own entry: {conditions:?}",
        );
    }
}

/// A credit of the same resource is asked nothing, because the entry
/// governs withdrawals alone.
#[test]
fn the_unrestricted_class_is_asked_nothing() {
    let (chain, issuer) = issuer();
    let env = transfer(issued(issuer, b"Bearer"));
    let admitted = admit_tree(&env, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the transfer admits with no record presented at all");
    assert!(
        !admitted
            .declaration()
            .required()
            .any(|rule| matches!(rule, Rule::Require(JudgedLeaf::Presence { .. }))),
        "a resource binding no movement provisions nothing and asks nothing",
    );
}

/// The register entry cannot leave the holder it was issued to.
///
/// A credential somebody can hand on is a register somebody else can
/// join without the registrar, so the badge turns the vocabulary on
/// itself: `withdraw = nobody` is decidable from the entry, without
/// state and without a body, and the graph is refused before it routes.
#[test]
fn the_register_entry_is_soulbound() {
    let (chain, issuer) = issuer();

    let mut env = transfer(issued(issuer, b"Registered"));
    env.resources = Capped::new(vec![record(issuer, b"Registered")]).unwrap();
    let refusal = admit_tree(&env, env.hash(&TestHasher), &chain, &TestHasher)
        .expect_err("no holder may debit their own register entry");
    // The sentence itself — "grants Withdraw to nobody", per direction —
    // is resource_grants' pin; what this adds is that the macro-derived
    // entry reaches the same verdict.
    assert!(
        matches!(
            refusal,
            AdmissionError::MovementForbidden {
                behaviour: GrantedBehaviour::Withdraw,
                ..
            }
        ),
        "the entry forbids the debit: {refusal:?}",
    );
}

/// A member's body presenting a claim it received in a socket ran on a
/// sign-in the granting account's shard judges, so off that shard the
/// body is the core's: a leg's verdict is its own, and only the core's
/// waits on the shard the judgment lands on.
///
/// Bob registers himself on the registrar's authority, which the
/// registrar's own intent grants into Bob's socket. The registration
/// targets the issuer, whose shard is not the registrar's.
#[test]
fn a_member_presenting_a_granted_claim_is_the_cores_off_the_granters_shard() {
    let (chain, issuer) = issuer();
    let resolver = PrefixShardResolver { bits: 8 };
    assert_ne!(
        resolver.shard_of(issuer.into()),
        resolver.shard_of(REGISTRAR.into()),
        "the fixture has to straddle, or the verdict below proves nothing",
    );

    let bobs = Intent {
        sockets: Capped::new(vec![Socket::Authority(Claim::of_subject(REGISTRAR))]).unwrap(),
        ..Intent::leaf(
            TEST_HEADER,
            BOB,
            ManifestGraph {
                nodes: Capped::new(vec![
                    GraphNode {
                        target: issuer.into(),
                        method: "register".into(),
                        args: vec![GraphArg::Literal(Value::U64(7))],
                        evidence: Capped::new(BTreeSet::from([ClaimRef::Socket(0)])).unwrap(),
                    },
                    GraphNode {
                        target: BOB.into(),
                        method: "deposit_nf".into(),
                        args: vec![GraphArg::edge(
                            EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            Vec::new(),
                        )],
                        evidence: Capped::new(BTreeSet::default()).unwrap(),
                    },
                ])
                .unwrap(),
            },
        )
    };
    let mut root = Intent::leaf(
        TEST_HEADER,
        REGISTRAR,
        ManifestGraph {
            nodes: Capped::empty(),
        },
    );
    root.members = Capped::new(vec![Member {
        signed: SignedIntent::unsigned(bobs),
        wiring: Capped::new(vec![Binding::Authority(ClaimRef::Account(REGISTRAR))]).unwrap(),
    }])
    .unwrap();
    let mut env = IntentTree::of_one(root);
    env.resources = Capped::new(vec![record(issuer, b"Registered")]).unwrap();
    let admitted = admit_tree(&env, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the registrar grants what Bob's socket asks");

    let legs = legs_of(&admitted);
    let star = star_at(
        &legs,
        REGISTRAR.address(),
        &[REGISTRAR.address(), BOB.address()],
        &resolver,
        &TestHasher,
    );
    assert_eq!(legs[0].presents, vec![REGISTRAR.address()]);
    assert_eq!(
        star.roles[0],
        LegRole::Core,
        "the registration ran on the registrar's claim off the registrar's shard",
    );
}

/// The behaviours the guest's own declaration grants, so the fixture
/// above cannot pass against a declaration that stopped granting them.
///
/// `Mint` is here because every resource that is minted carries one:
/// absence withholds, so a share class nobody could issue is spelled by
/// leaving it out. `Halt` is here because granting it is what puts the
/// halt read on every movement of the share — and what puts the share in
/// the class whose record cannot be withheld, so the read fails closed.
#[test]
fn the_guest_grants_what_these_cases_are_about() {
    let granted: BTreeSet<GrantedBehaviour> = security::metadata()
        .methods
        .values()
        .flat_map(|signature| &signature.issues)
        .flat_map(|issuance| issuance.grants.iter().map(|(behaviour, _)| behaviour))
        .collect();
    assert_eq!(
        granted,
        BTreeSet::from([
            GrantedBehaviour::Mint,
            GrantedBehaviour::Withdraw,
            GrantedBehaviour::Deposit,
            GrantedBehaviour::Halt,
            GrantedBehaviour::Recall,
        ]),
        "both movement entries to enforce, the halt that binds a component, and the two \
         authority entries that stay plain beside them",
    );
}
