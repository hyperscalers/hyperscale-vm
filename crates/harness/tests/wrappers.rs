//! The wrappers, held to the signatures they mirror.
//!
//! A wrapper is a hand-written claim about a method: its parameter kinds,
//! their order, and how many edges it produces. Every claim here is made
//! against the authored metadata and then admitted, so drift is a failing
//! test rather than a client that builds graphs the chain refuses. What
//! that leaves is a method nobody wrapped, which the coverage check at the
//! bottom is for.
//!
//! Only `account` and `staking` have committed guests. The rest are
//! exercised against their metadata alone, which is all a wrapper can
//! drift from.

use std::collections::BTreeSet;

mod common;

use common::world::admit_here;
use hyperscale_vm_effects::{
    Claim, EvidenceRef, Hash32, Hasher, InstanceMeta, ManifestGraph, PackageHash, PackageMetadata,
    PrincipalRule, Records, ResourceKind, RuleBytes, StoredRule, TestHasher, Value, always,
    issued_resource,
};
use hyperscale_vm_fixtures::{HAND_AUTHORED, amm, book, lottery, nf, payouts, registry};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const BASE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const QUOTE: ResourceAddr = ResourceAddr::new([0xE2; 31]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// One instance per package that has any, each configured as its
/// signatures read their configuration.
fn instance(package: &str, config: Vec<Value>) -> InstanceMeta {
    InstanceMeta {
        package: pkg(package),
        config,
        salt: Hash32([7; 32]),
    }
}

fn address(package: &str, config: Vec<Value>) -> ComponentAddr {
    instance(package, config).address(&TestHasher)
}

fn pool_config() -> Vec<Value> {
    vec![
        Value::Address(BASE.address()),
        Value::Address(OPERATOR.address()),
    ]
}

/// A stored rate's slot value: the scaled integer in the width a rate
/// has.
fn scaled_rate(scaled: u128) -> Value {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&scaled.to_le_bytes());
    Value::U256(bytes)
}

/// One quote subunit per tick, which is the step a book prices in unless
/// it was created finer.
const ONE_PER_TICK: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

fn pair_config() -> Vec<Value> {
    vec![
        Value::Address(BASE.address()),
        Value::Address(QUOTE.address()),
        scaled_rate(ONE_PER_TICK),
    ]
}

/// The asset the splitter divides, and the three shares it divides by.
fn payouts_config() -> Vec<Value> {
    let quarter = 1_000_000_000_000_000_000 / 4;
    vec![
        Value::Address(BASE.address()),
        Value::U128(quarter),
        Value::U128(quarter),
        Value::U128(2 * quarter),
    ]
}

/// The pair plus the fee slot the amm's signatures read.
fn amm_config() -> Vec<Value> {
    vec![
        Value::Address(BASE.address()),
        Value::Address(QUOTE.address()),
        Value::U128(30 * (1_000_000_000_000_000_000 / 10_000)),
    ]
}

fn world() -> Records {
    let mut chain = Records::new();
    for (name, metadata) in stdlib() {
        chain.packages.publish_unchecked(pkg(name), metadata);
    }
    chain.instances.serve_principals(pkg("account"));
    for (name, config) in [
        ("staking", pool_config()),
        ("amm", amm_config()),
        ("book", pair_config()),
        ("nf", vec![]),
        ("nf", vec![Value::Address(BASE.address())]),
        ("registry", vec![]),
        ("payouts", payouts_config()),
        ("lottery", vec![]),
    ] {
        chain.instances.create(&TestHasher, instance(name, config));
    }
    chain
}

/// Every authored package, by the name its hash derives from.
fn stdlib() -> Vec<(&'static str, PackageMetadata)> {
    vec![
        ("account", account::metadata()),
        ("amm", amm::metadata()),
        ("book", book::metadata()),
        ("lottery", lottery::metadata()),
        ("nf", nf::metadata()),
        ("payouts", payouts::metadata()),
        ("registry", registry::metadata()),
        ("staking", staking::metadata()),
    ]
}

/// Build through `write` and admit the result, so a wrapper disagreeing
/// with its signature fails here rather than at a signer's node.
fn admits(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    write(&mut b).expect("every wrapper types against its own signature");
    let graph = b.build().expect("every output is consumed");
    admit_here(&graph, ALICE, &chain).expect("a wrapped graph admits");
    graph
}

#[test]
fn the_account_wrappers_match_their_signatures() {
    let graph = admits(|b| {
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        account::deposit(b, BOB, funds)?;
        account::securify_uniform(
            b,
            ALICE,
            &StoredRule::claim(Claim::of_subject(BOB)),
            86_400_000,
        )?;
        let stored = StoredRule::claim(Claim::of_subject(BOB));
        let rule = RuleBytes::try_from(&stored).expect("a rule within the vocabulary caps");
        let governing =
            PrincipalRule::try_from(&stored).expect("a rule over principal claims encodes");
        account::propose(b, ALICE, governing, rule.clone(), rule, 86_400_000)?;
        account::cancel(b, ALICE)?;
        account::confirm(b, ALICE)
    });
    assert_eq!(graph.nodes.len(), 6);
}

/// A rule literal is judged by decoding it as the vocabulary — the same
/// predicate admission runs — so a threshold its own branches can never
/// meet is refused at the call site that writes it.
#[test]
fn a_degenerate_rule_is_refused_where_it_is_written() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let degenerate = StoredRule::CountOf {
        count: 2,
        rules: vec![StoredRule::claim(Claim::of_subject(ALICE))],
    };
    // The governing cell's own kind, which `securify` takes first.
    assert!(matches!(
        account::securify_uniform(&mut b, ALICE, &degenerate, 86_400_000),
        Err(TypedError::ParamKind {
            expected: "principal-rule",
            ..
        })
    ));
    // And the wide kind the recovery surface takes, which decodes the
    // same vocabulary and refuses the same bytes.
    let stored = StoredRule::claim(Claim::of_subject(ALICE));
    let governing = PrincipalRule::try_from(&stored).expect("a rule over principal claims encodes");
    let broken = RuleBytes::try_from(&degenerate).expect("a degenerate rule still encodes");
    assert!(matches!(
        account::propose(&mut b, ALICE, governing, broken.clone(), broken, 86_400_000),
        Err(TypedError::ParamKind {
            expected: "rule",
            ..
        })
    ));
}

/// The governing cell takes a rule over principal claims and nothing
/// else, refused where it is written.
///
/// That cell is judged against the keys attesting an intent. A leaf
/// naming a resource is one no attesting set can meet and a holding is
/// one the judge cannot read at all, so either would store a rule that
/// leaves the account unopenable — and the recovery surface, judged
/// against presented claims instead, keeps both.
#[test]
fn the_governing_cell_takes_a_rule_over_principals_alone() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let badge = StoredRule::claim(Claim::of_subject(BASE));
    assert!(
        matches!(
            account::securify_uniform(&mut b, ALICE, &badge, 86_400_000),
            Err(TypedError::ParamKind {
                expected: "principal-rule",
                ..
            })
        ),
        "a badge cannot govern the cell keys are judged against"
    );

    // The same rule is a recovery surface the account keeps: a holder of
    // the badge may propose, and whoever presents it is what answers.
    let stored = StoredRule::claim(Claim::of_subject(ALICE));
    let governing = PrincipalRule::try_from(&stored).expect("a rule over principal claims encodes");
    let recovery = RuleBytes::try_from(&badge).expect("a rule within the vocabulary caps");
    account::propose(
        &mut b,
        ALICE,
        governing,
        recovery.clone(),
        recovery,
        86_400_000,
    )
    .expect("a badge may hold the recovery role");
}

/// The threshold over nothing is not degenerate — it is how the
/// vocabulary says "anyone" — so a rule spelling it reaches the account
/// rather than being refused at the builder.
///
/// Whether an account wants a rule anyone meets is the account's own
/// question, answered where its policy lives and not by the algebra
/// withholding a word.
#[test]
fn the_empty_threshold_reaches_the_account() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    account::securify_uniform(&mut b, ALICE, &always(), 86_400_000)
        .expect("anyone is a rule the vocabulary can carry");
}

/// A stored rule can be a threshold, so a gate can take a set of
/// proofs: a scope holding two carries both to the call, and the
/// judgment against the stored rule stays where it always is.
///
/// The intent's own signature rides beside them, as it rides every
/// gated call. It costs the graph nothing and names the account this
/// intent acts as, which is the claim a rule nobody here can read is
/// most likely to want.
#[test]
fn a_scope_holding_two_proofs_carries_both_to_the_gate() {
    let graph = admits(|b| {
        let base = account::present_badge(b, ALICE, BASE)?;
        let quote = account::present_badge(b, ALICE, QUOTE)?;
        let funds = b.presenting([base, quote], |b| account::withdraw(b, ALICE, BASE, 100))?;
        account::deposit(b, BOB, funds)
    });
    let gated = &graph.nodes[2].evidence;
    assert!(
        gated.contains(&EvidenceRef::Node(0)) && gated.contains(&EvidenceRef::Node(1)),
        "both proofs ride the gate: {gated:?}"
    );
    assert!(gated.contains(&EvidenceRef::IntentSignature), "{gated:?}");
}

/// A guarded call composed without a proof presents the intent's own
/// signature, where the gate names the account that intent acts as.
///
/// Nothing is written by hand and nothing is composed ahead of it: the
/// account's claim is its signature's, so the withdrawal is the whole
/// graph its author asked for.
#[test]
fn a_guarded_call_without_a_proof_presents_the_intents_signature() {
    let graph = admits(|b| {
        let funds = b.call(ALICE, "withdraw", (BASE, 100_u128))?.one()?;
        account::deposit(b, BOB, funds)
    });
    assert_eq!(graph.nodes.len(), 2, "the withdrawal and the deposit");
    assert_eq!(
        graph.nodes[0].evidence,
        BTreeSet::from([EvidenceRef::IntentSignature])
    );
}

/// A badge gate still takes a node: the composer reads the badge the
/// gate names off the declaration and presents it from the signer's
/// account — the present-badge node it proves, then the call citing it.
///
/// Possession is the question, and only a call that reads the vault
/// answers it. What a signature carries is an account's own claim, so
/// it rides along and settles nothing here.
#[test]
fn a_badge_gate_without_a_proof_is_answered_from_the_signers_account() {
    let gated = address("nf", vec![Value::Address(BASE.address())]);
    let graph = admits(|b| {
        b.call(gated, "operate", ())?.none()?;
        Ok(())
    });
    assert_eq!(
        graph.nodes[1].evidence,
        BTreeSet::from([EvidenceRef::IntentSignature, EvidenceRef::Node(0)])
    );
}

/// Misplaced evidence refuses at the call site, mirroring admission: a
/// proof to a method admitting anyone, a gate naming a party this intent
/// cannot speak for, a proof asked of a method that proves nothing.
#[test]
fn misplaced_evidence_is_refused_at_the_call_site() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let held = account::present_badge(&mut b, ALICE, BASE).unwrap();
    let funds = account::withdraw(&mut b, ALICE, BASE, 100).unwrap();
    assert!(matches!(
        b.call_presenting(held, BOB, "deposit", (funds,)),
        Err(TypedError::UnexpectedEvidence { .. })
    ));
    assert!(matches!(
        b.call(BOB, "withdraw", (BASE, 100_u128)),
        Err(TypedError::UncoveredGate { .. })
    ));
    assert!(matches!(
        b.call_proving(ALICE, "withdraw", ()),
        Err(TypedError::ProvesNothing { .. })
    ));
}

#[test]
fn the_staking_wrappers_match_their_signatures() {
    let pool = staking::Staking::at(address("staking", pool_config()));
    let graph = admits(|b| {
        // The delegation round trip: funds in, the pool's own units out
        // and into an account, then units back to the pool. The deposit
        // lands at BOB while the return draws from ALICE: one vault
        // created and drawn from in a single transaction would require
        // its leaf absent and present at once.
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        let units = pool.stake(b, funds)?;
        account::deposit(b, BOB, units)?;
        let returned = account::withdraw(b, ALICE, staking_units(pool), 40)?;
        pool.unstake(b, returned)?;

        // The operator surface, which supplies no funds and produces
        // none. Its gate names the pool's own owner badge rather than a
        // signer, so the proof it takes is the one presenting that badge
        // — a sign-in carries Alice's identity and opens nothing here.
        // Registration creates seat 7; the seat operated on is a
        // different one, since a seat created and deactivated in a single
        // transaction would require its leaf absent and present at once.
        let operator =
            account::present_instance(b, ALICE, pool.issued_owner_badge(&TestHasher), 0)?;
        b.presenting(operator, |b| {
            pool.register_validator(b, 7, [0xAA; 48], [0xBB; 96])?;
            pool.deactivate_validator(b, 8)?;
            pool.unjail(b, 8)?;
            pool.cast_param_vote(b, 9_000, 7_500, 30, 10_000, 10_000, 12)?;
            pool.clear_param_vote(b)
        })
    });
    assert_eq!(graph.nodes.len(), 11);
}

/// The resource a pool issues, which its `stake` output derives from the
/// pool's own address.
fn staking_units(pool: staking::Staking) -> ResourceAddr {
    pool.issued_stake_unit(&TestHasher)
}

#[test]
fn the_amm_wrapper_matches_its_signature() {
    let pool = amm::Amm::at(address("amm", amm_config()));
    admits(|b| {
        // The pool's output is typed by its second configured resource,
        // so what comes back is quote against a base input.
        let input = account::withdraw(b, ALICE, BASE, 100)?;
        let proceeds = pool.swap(b, input, 1)?;
        account::deposit(b, ALICE, proceeds)
    });
}

#[test]
fn the_book_wrappers_match_their_signatures() {
    let book = book::Book::at(address("book", pair_config()));
    admits(|b| {
        let offered = account::withdraw(b, ALICE, BASE, 100)?;
        book.place_ask(b, 10, offered)?;
        let payment = account::withdraw(b, ALICE, QUOTE, 50)?;
        let [bought, unspent] = book.fill_asks(b, 1, 20, payment)?;
        account::deposit(b, BOB, bought)?;
        account::deposit(b, BOB, unspent)
    });
}

#[test]
fn the_registry_wrappers_match_their_signatures() {
    let registry_addr = address("registry", vec![]);
    admits(|b| {
        registry::bind(b, registry_addr, 7, 700)?;
        registry::check(b, registry_addr, 7, 700)?;
        registry::drain(b, registry_addr, 0)
    });
}

#[test]
fn the_lottery_wrappers_match_their_signatures() {
    let lottery_addr = lottery::Lottery::at(address("lottery", vec![]));
    admits(|b| {
        let stake = account::withdraw(b, ALICE, BASE, 100)?;
        // Alice pays and Bob is entered: the entrant is named by the
        // composer, not by whoever the funds came from.
        lottery_addr.enter(b, BOB, stake)?;
        lottery_addr.close(b)
    });
}

/// A method yielding two edges of one resource projects both of them,
/// and a caller has to route each.
#[test]
fn the_payouts_wrappers_match_their_signatures() {
    let splitter = payouts::Payouts::at(address("payouts", payouts_config()));
    admits(|b| {
        let funds = account::withdraw(b, ALICE, BASE, 100)?;
        let [payable, change] = splitter.in_lots(b, funds, 30u128)?;
        account::deposit(b, BOB, payable)?;
        account::deposit(b, ALICE, change)
    });
}

#[test]
fn the_nf_wrappers_match_their_signatures() {
    let issuer = address("nf", vec![]);
    let resource = issued_resource(
        &TestHasher,
        issuer.address(),
        ResourceKind::NonFungible,
        nf::BADGE,
    );
    admits(|b| {
        let minted = nf::mint(b, issuer)?;
        nf::deposit(b, issuer, minted)?;
        let moved = nf::withdraw(b, issuer, resource, &[7, 9])?;
        nf::burn(b, issuer, moved)
    });
}

#[test]
fn the_custody_wrappers_match_their_signatures() {
    let issuer = address("nf", vec![]);
    let resource = issued_resource(
        &TestHasher,
        issuer.address(),
        ResourceKind::NonFungible,
        nf::BADGE,
    );
    let gated = address("nf", vec![Value::Address(BASE.address())]);
    admits(|b| {
        let minted = nf::mint(b, issuer)?;
        account::deposit_nf(b, ALICE, minted)?;
        let badge = account::present_badge(b, ALICE, BASE)?;
        nf::operate(b, gated, badge)?;
        // Alice's own gate takes Alice's own proof: the badge proof
        // carries the badge, and a claim on it opens what names the
        // badge and nothing else.
        let moved = account::withdraw_nf(b, ALICE, resource, &[7])?;
        account::deposit_nf(b, BOB, moved)
    });
}

#[test]
fn every_hand_written_method_has_a_wrapper() {
    // The one drift a call site cannot catch: a method added to a package
    // that no wrapper names. Only the hand-written packages can drift —
    // `#[blueprint]` emits a wrapper per method, so for a derived package
    // this list would be a second text saying what the first one already
    // says. Exhaustive over the three that are written by hand: adding a
    // method breaks this, which is the point.
    let wrapped: Vec<(&str, &[&str])> = vec![
        (
            "nf",
            &[
                "burn",
                "deposit",
                "mint",
                "operate",
                "operate-instance",
                "operate-quorum",
                "withdraw",
            ],
        ),
        ("registry", &["bind", "check", "drain"]),
    ];
    // Which packages are hand-written is the fixtures crate's own fact,
    // read rather than restated: a package added there and not here
    // would be one whose wrappers nothing holds to its signatures, and
    // the list saying so would be the text that fell behind.
    let hand_written: Vec<(&str, PackageMetadata)> = HAND_AUTHORED
        .iter()
        .map(|name| match *name {
            "nf" => ("nf", nf::metadata()),
            "registry" => ("registry", registry::metadata()),
            other => panic!("{other} is hand-authored and has no wrapper sweep"),
        })
        .collect();
    // Zipping would truncate silently, so the lists are held to one
    // length first: a package appended to one and not the other is the
    // same drift as a method, and would otherwise go unchecked.
    assert_eq!(hand_written.len(), wrapped.len());
    for ((package, metadata), (named, methods)) in hand_written.into_iter().zip(wrapped) {
        assert_eq!(package, named);
        let declared: BTreeSet<&str> = metadata.methods.keys().map(String::as_str).collect();
        let wrapped: BTreeSet<&str> = methods.iter().copied().collect();
        assert_eq!(declared, wrapped, "{package}");
    }
}
