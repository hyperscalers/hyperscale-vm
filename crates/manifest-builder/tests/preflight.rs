//! What a holder can know before signing, and that it agrees with what
//! the chain derives afterwards.
//!
//! The report composes functions the chain already runs, so the test that
//! matters is that composing them changed nothing: every quantity here is
//! checked against the same call made directly.

use hyperscale_vm_effects::{
    Claim, Clause, Constraint, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, PackageHash, PackageMetadata, PrefixShardResolver, Records, ResourceGrants,
    ResourceKind, ResourceMeta, RuleBytes, StoredRule, TestHasher, Totality, Value, admit,
    footprint, route,
};
use hyperscale_vm_manifest_builder::{
    Authority, EnvelopeBuilder, IntentBuilder, PreflightError, TypedBuilder, preflight,
    preflight_tree,
};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{
    Address, AddressClass, PrincipalAddr, ResourceAddr, SchemeId, TextError, declared_work,
    signature_work,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("staking"),
        config: vec![
            Value::Address(RES_X.address()),
            Value::Address(OPERATOR.address()),
        ],
        salt: Hash32([2; 32]),
    }
}

fn pool() -> staking::Staking {
    staking::Staking::at(pool_meta().address(&TestHasher))
}

/// The pool's owner badge — the identity its operator surface admits.
///
/// Through the package's own derivation rather than a restatement of
/// it: the address folds the rules the mark grants, so a copy here would
/// name a vacant sibling the moment the badge grants anything.
fn badge() -> ResourceAddr {
    pool().issued_owner_badge(&TestHasher)
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("staking"), staking::metadata());
    chain.instances.serve_principals(pkg("account"));
    chain.instances.create(&TestHasher, pool_meta());
    chain
}

const SHARDS: PrefixShardResolver = PrefixShardResolver { bits: 2 };

#[test]
fn a_report_is_what_the_chain_derives() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();

    let report = preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();

    // Nothing new is computed here, so everything must equal the direct
    // call it composes.
    let admitted = admit(&graph, ALICE, &chain, &TestHasher).unwrap();
    let routing = route(&admitted, &SHARDS);
    assert_eq!(report.identity(), admitted.identity());
    assert_eq!(report.manifest(), admitted.manifest());
    assert_eq!(report.routing, routing);
    assert_eq!(
        report.footprint(),
        routing
            .per_shard
            .values()
            .fold(0u64, |total, set| total + footprint(set)),
        "the reservation is taken once against every shard's declaration"
    );
    assert_eq!(
        report.declared_work(7_000, &[SchemeId::ED25519]),
        declared_work(report.footprint(), 7_000, signature_work(SchemeId::ED25519)),
    );
    assert!(
        report.declared_work(7_000, &[SchemeId::ED25519, SchemeId::ED25519])
            > report.declared_work(7_000, &[SchemeId::ED25519]),
        "a second signature is a second verification to pay for"
    );
    assert_eq!(report.shards().count(), routing.per_shard.len());
}

#[test]
fn a_withdrawal_names_its_own_signer_and_a_deposit_names_nobody() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();

    // Spending is the sender's; being paid is nobody's to refuse, so a
    // transfer composes under one signature — presented once, at the
    // sign-in, judged by the account's stored primary rule, and carried
    // to the withdrawal as its proof.
    assert_eq!(report.authority[0].authority, Authority::StoredRule);
    assert_eq!(report.authority[1].authority, Authority::Signature(ALICE));
    assert_eq!(report.authority[2].authority, Authority::Anyone);
    assert_eq!(report.signers(), std::iter::once(ALICE).collect());
    assert_eq!(report.unsatisfiable().count(), 0);
}

#[test]
fn the_operator_surface_is_the_badge_holders_custody() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, OPERATOR);
    let operator = account::present_badge(&mut b, OPERATOR, badge()).unwrap();
    b.presenting(operator, |b| pool().unjail(b, 42)).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();

    // A pool is owned by nobody, so its operator surface admits whoever
    // presents the pool's own badge: custody at the presentation, and
    // the badge itself at the surface — reachable only through that
    // presentation, which is the point, and which the report says
    // rather than calling the surface unreachable.
    assert_eq!(report.authority[0].authority, Authority::StoredRule);
    assert_eq!(
        report.authority[1].authority,
        Authority::Badge {
            resource: badge(),
            instance: None,
        }
    );
    assert_eq!(report.signers(), std::iter::once(OPERATOR).collect());
    assert_eq!(report.unsatisfiable().count(), 0);
    // The report names the badge it just handed the caller, so a wallet
    // can render the credential the surface asks for.
    assert_eq!(
        report.text(badge()),
        report.named.get(&badge().address()).map(String::as_str)
    );
    assert!(report.text(badge()).is_some());
}

#[test]
fn every_address_the_report_names_is_named_for_the_network() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let report = preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();

    for (address, text) in &report.named {
        assert_eq!(*text, address.to_text(NETWORK).unwrap());
        assert!(text.contains(NETWORK), "the word is in the text: {text}");
    }
    assert_eq!(
        report.text(ALICE),
        report.named.get(&ALICE.address()).map(String::as_str)
    );
    // A report on one network says nothing about another.
    let elsewhere = preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, "testnet").unwrap();
    assert_ne!(elsewhere.named, report.named);
}

#[test]
fn a_network_word_the_encoding_refuses_fails_once() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    assert!(matches!(
        preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, "Main Net"),
        Err(PreflightError::Network(TextError::InvalidCharacter(_)))
    ));
    assert!(matches!(
        preflight(&graph, ALICE, &chain, &TestHasher, &SHARDS, ""),
        Err(PreflightError::Network(TextError::IncompletePrefix))
    ));
}

#[test]
fn a_composition_names_every_signer_it_needs() {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);

    let taken = root.declare(RES_Y, [Constraint::MinAmount(10)]);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken).unwrap();

    let mut sub = env.subintent(BOB);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, 10).unwrap();
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken).unwrap();

    let wants_y = env.seal(root).unwrap().one().unwrap();
    let wants_x = env.seal(sub).unwrap().one().unwrap();
    env.bind(wants_y, paid_y).unwrap();
    env.bind(wants_x, paid_x).unwrap();
    let tree = env.build().unwrap();

    let report = preflight_tree(&tree, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();
    // Both withdrawals name their own account, and the subintent's signer
    // signs its declaration; here the two sets coincide.
    assert_eq!(report.signers(), [ALICE, BOB].into_iter().collect());
    assert_eq!(report.subintents.len(), 1);
    assert_eq!(report.subintents[0].signer, BOB);
    // The nullifier the composition would spend, named before signing.
    assert_eq!(report.identity(), tree.hash(&TestHasher));
}

/// The party whose approval the note's own entry names.
const DESK: PrincipalAddr = PrincipalAddr::new([0x40; 31]);
/// Whose namespace the note sits in; its code never runs here.
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

/// A note whose withdraw entry either the desk or Bob may approve.
fn either_note_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Withdraw,
        RuleBytes::try_from(&StoredRule::CountOf {
            count: 1,
            rules: vec![
                StoredRule::claim(Claim::of_subject(DESK)),
                StoredRule::claim(Claim::of_subject(BOB)),
            ],
        })
        .expect("a rule within the caps encodes"),
    );
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"either".to_vec()],
        rules,
    }
}

/// A disjunctive threshold reports every branch and commits to none:
/// which branch a holder satisfies is theirs to choose, so neither
/// branch signer is one the transaction certainly needs.
#[test]
fn a_disjunction_reports_its_branches_and_names_no_certain_signer() {
    let chain = world();
    let note = either_note_meta().address(&TestHasher);
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let approval = root.declare_proof(Claim::of_subject(DESK));
    let alice = account::authorize(&mut root, ALICE).unwrap();
    let funds = root
        .call_presenting([alice, approval], ALICE, "withdraw", (note, 5u128))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    let request = root;
    let mut sub = env.subintent(DESK);
    let desk = account::authorize(&mut sub, DESK).unwrap();
    let offered = sub.offer(desk);
    let wants = env.seal(request).unwrap().one().unwrap();
    env.seal(sub).unwrap().none().unwrap();
    env.bind(wants, offered).unwrap();
    env.register_resource(either_note_meta());
    let tree = env.build().unwrap();

    let report = preflight_tree(&tree, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();
    let withdrawing = report
        .authority
        .iter()
        .find(|required| required.method == "withdraw")
        .expect("the note is withdrawn");
    assert_eq!(
        withdrawing.authority,
        Authority::Threshold {
            count: 2,
            branches: vec![
                Authority::Signature(ALICE),
                Authority::Threshold {
                    count: 1,
                    branches: vec![Authority::Signature(DESK), Authority::Signature(BOB)],
                },
            ],
        }
    );
    // The choice of branch is the holder's, so neither branch signer is
    // certain — only the holder's own gate is.
    assert!(report.signers().contains(&ALICE));
    assert!(!report.signers().contains(&BOB));
    assert_eq!(report.unsatisfiable().count(), 0);
}

/// The satisfiability arithmetic over the one unsatisfiable leaf.
///
/// A shape that reaches the report with an unsatisfiable branch is one
/// admission's own refusals mostly stand in front of — a guarded call
/// presenting nothing refuses before any report exists — so the
/// arithmetic is pinned on the type: a threshold is satisfiable exactly
/// where enough of its branches are, and `unsatisfiable()` is its
/// complement.
#[test]
fn a_threshold_is_satisfiable_where_enough_branches_are() {
    assert!(!Authority::TargetHasNoKey.satisfiable());
    assert!(Authority::ProvenInTransaction.satisfiable());
    let one_of = |branches| Authority::Threshold { count: 1, branches };
    assert!(one_of(vec![Authority::TargetHasNoKey, Authority::Signature(ALICE)]).satisfiable());
    assert!(!one_of(vec![Authority::TargetHasNoKey]).satisfiable());
    let both = Authority::Threshold {
        count: 2,
        branches: vec![Authority::Signature(ALICE), Authority::TargetHasNoKey],
    };
    assert!(
        !both.satisfiable(),
        "a conjunction with a dead branch is dead"
    );
}

/// The venue whose approval the ticket's entry names: a component, so
/// nothing signs for it — its own method mints the proof instead.
fn venue_metadata() -> PackageMetadata {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "approve".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Proves {
                guard: None,
                claim: Expr::SelfAddr,
            }],
            ..MethodSignature::default()
        },
    );
    package
}

fn venue_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("venue"),
        config: Vec::new(),
        salt: Hash32([7; 32]),
    }
}

/// A ticket that moves only with the venue's approval in hand.
fn ticket_meta() -> ResourceMeta {
    let venue = venue_meta().address(&TestHasher);
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Withdraw,
        RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(venue.address())))
            .expect("a rule within the caps encodes"),
    );
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"ticket".to_vec()],
        rules,
    }
}

/// A claim on a component is satisfiable by the transaction that mints
/// it: the venue pattern. The report used to call the branch
/// satisfiable-by-nobody — a false alarm handed to the wallet over a
/// transaction that admits and completes — because the verdict never
/// consulted the evidence the node already carries.
#[test]
fn a_component_claim_the_transaction_mints_is_satisfiable() {
    let mut chain = world();
    chain
        .packages
        .publish_unchecked(pkg("venue"), venue_metadata());
    chain.instances.create(&TestHasher, venue_meta());
    let venue = venue_meta().address(&TestHasher);
    let ticket = ticket_meta().address(&TestHasher);

    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE);
    let approval = root.call_proving(venue, "approve", ()).unwrap();
    let alice = account::authorize(&mut root, ALICE).unwrap();
    let funds = root
        .call_presenting([alice, approval], ALICE, "withdraw", (ticket, 3u128))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut root, BOB, funds).unwrap();
    env.seal(root).unwrap().none().unwrap();
    env.register_resource(ticket_meta());
    let tree = env.build().unwrap();

    let report = preflight_tree(&tree, ALICE, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();
    let withdrawing = report
        .authority
        .iter()
        .find(|required| required.method == "withdraw")
        .expect("the ticket is withdrawn");
    assert_eq!(
        withdrawing.authority,
        Authority::Threshold {
            count: 2,
            branches: vec![Authority::Signature(ALICE), Authority::ProvenInTransaction,],
        }
    );
    assert_eq!(report.unsatisfiable().count(), 0);
}

/// A withdrawal of a governed note answers to its account's gate and to
/// the note's own entry at once, and the report says what each branch
/// asks — the branch contents are the case a preflight exists for.
#[test]
fn a_conjunction_reports_what_each_branch_asks() {
    let chain = world();
    let note = note_meta().address(&TestHasher);
    let mut request = IntentBuilder::declaration(&chain, &TestHasher, BOB);
    let approval = request.declare_proof(Claim::of_subject(DESK));
    let bob = account::authorize(&mut request, BOB).unwrap();
    let funds = request
        .call_presenting([bob, approval], BOB, "withdraw", (note, 40u128))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut request, BOB, funds).unwrap();
    let request = request.into_decl().unwrap();

    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, DESK);
    let desk = account::authorize(&mut root, DESK).unwrap();
    let offered = root.offer(desk);
    let wants = env.adopt(BOB, request).unwrap().one().unwrap();
    env.seal(root).unwrap().none().unwrap();
    env.bind(wants, offered).unwrap();
    env.register_resource(note_meta());
    let tree = env.build().unwrap();

    let report = preflight_tree(&tree, DESK, &chain, &TestHasher, &SHARDS, NETWORK).unwrap();

    let withdrawing = report
        .authority
        .iter()
        .find(|required| required.method == "withdraw")
        .expect("the request withdraws");
    assert_eq!(
        withdrawing.authority,
        Authority::Threshold {
            count: 2,
            branches: vec![Authority::Signature(BOB), Authority::Signature(DESK)],
        }
    );
    // A signer named inside a threshold is still an address the report
    // names, and a conjunction branch is a signature the transaction
    // certainly needs.
    assert!(report.text(DESK).is_some());
    assert!(report.signers().contains(&DESK));
    assert!(report.signers().contains(&BOB));
    assert_eq!(report.unsatisfiable().count(), 0);
}
