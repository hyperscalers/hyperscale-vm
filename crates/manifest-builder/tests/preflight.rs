//! What a holder can know before signing, and that it agrees with what
//! the chain derives afterwards.
//!
//! The report composes functions the chain already runs, so the test that
//! matters is that composing them changed nothing: every quantity here is
//! checked against the same call made directly.

use std::collections::BTreeSet;

mod common;

use common::admit_leaf;
use hyperscale_vm_effects::{
    Claim, Clause, Constraint, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta, Intent,
    IntentHeader, IntentTree, ManifestGraph, MethodSignature, PackageHash, PackageMetadata,
    PrefixShardResolver, PrincipalRule, Records, ResourceGrants, ResourceKind, ResourceMeta,
    RuleBytes, ShardResolver, StoredRule, TestHasher, Totality, Value, admit_tree, footprint,
};
use hyperscale_vm_manifest_builder::{
    Authority, IntentBuilder, Interface, PreflightError, Report, TypedBuilder, preflight_tree,
};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{
    Address, AddressClass, DeclaredWork, MAX_GAS_LIMIT, NetworkId, PriceTable, PrincipalAddr,
    ResourceAddr, SchemeId, TermsRefusal, TextError, gas_limit_total,
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

/// The attesting set the report names for each intent, in tree order.
fn attesting(report: &Report) -> Vec<Vec<PrincipalAddr>> {
    report
        .signers()
        .map(|(_, attesting)| attesting.to_vec())
        .collect()
}

const SHARDS: PrefixShardResolver = PrefixShardResolver { bits: 2 };

/// The degenerate tree a plain transaction is: one intent under the test
/// header, no sockets, nothing bound.
fn one_intent(account: PrincipalAddr, graph: &ManifestGraph) -> IntentTree {
    IntentTree::of_one(Intent::leaf(TEST_HEADER, account, graph.clone()))
}

#[test]
fn a_report_is_what_the_chain_derives() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let tree = one_intent(ALICE, &graph);

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();

    // Nothing new is computed here, so everything must equal the direct
    // call it composes.
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(&tree, identity, &chain, &TestHasher).unwrap();
    assert_eq!(report.identity(), identity);
    assert_eq!(report.manifest(), admitted.manifest());
    assert_eq!(report.admitted, admitted);
    // A graph admitted through the leaf is the same graph admitted as a
    // tree of one intent, node for node and key for key.
    assert_eq!(
        admit_leaf(&graph, ALICE, &chain, &TestHasher).unwrap(),
        admitted
    );
    assert_eq!(
        report.footprint(),
        footprint(&admitted.declaration().set),
        "the reservation is taken once against the whole declaration"
    );
    let work = report.work(&[4_000, 3_000], &[SchemeId::ED25519], 500);
    let signature = DeclaredWork::signature(SchemeId::ED25519);
    assert_eq!(
        work.compute,
        7_000 + signature.compute,
        "the compute term is the sum over the nodes plus the verification"
    );
    assert_eq!(work.footprint, report.footprint());
    assert_eq!(
        work.read_bytes,
        admitted.declaration().set.read_bytes() + 500,
        "reads are the declaration's bytes plus the artifacts"
    );
    assert_eq!(
        work.retention,
        report.retained_bytes() + signature.retention + report.event_bytes,
        "retention keeps what the writes leave behind, the auth material and \
         what the calls may emit"
    );
    assert!(
        report.retained_bytes() < work.write_bytes,
        "and what a write leaves behind is not what it costs: the write \
         dimension carries the tree path each update reads, which a validator \
         retains none of. {} against {}",
        report.retained_bytes(),
        work.write_bytes
    );
    assert!(
        report.event_bytes > 0,
        "the fixture calls a method that emits, or this proves nothing"
    );
    let twice = report.work(
        &[4_000, 3_000],
        &[SchemeId::ED25519, SchemeId::ED25519],
        500,
    );
    assert!(
        twice.compute > work.compute && twice.retention > work.retention,
        "a second signature is a second verification and more material to keep"
    );
    assert_eq!(
        report.price(
            &PriceTable::GENESIS,
            &[4_000, 3_000],
            &[SchemeId::ED25519],
            500,
            0
        ),
        PriceTable::GENESIS.price(&work, 0)
    );
    // The shards a declaration touches, asked of the declaration: each
    // target's accesses all land on the one shard its owner resolves to.
    let touched: BTreeSet<_> = report
        .admitted
        .declaration()
        .ordered
        .iter()
        .map(|access| SHARDS.shard_of(access.effect.target.owner()))
        .collect();
    assert_eq!(touched.len(), 1, "one payer and one payee under two bits");
}

#[test]
fn a_withdrawal_names_its_own_signer_and_a_deposit_names_nobody() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut b, BOB, funds).unwrap();
    let graph = b.build().unwrap();
    let report = preflight_tree(&one_intent(ALICE, &graph), &chain, &TestHasher, NETWORK).unwrap();

    // Spending is the sender's; being paid is nobody's to refuse, so a
    // transfer is two nodes and one signature — the withdrawal gated on
    // the account it draws from, answered by the intent acting as that
    // account, with nothing composed ahead of it.
    assert_eq!(report.authority.len(), 2);
    assert_eq!(report.authority[0].authority, Authority::Signature(ALICE));
    assert_eq!(report.authority[1].authority, Authority::Anyone);
    assert_eq!(attesting(&report), [vec![ALICE]]);
    assert_eq!(report.unsatisfiable().count(), 0);
}

#[test]
fn the_operator_surface_is_the_badge_holders_custody() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, OPERATOR);
    let operator = account::present_badge(&mut b, OPERATOR, badge()).unwrap();
    b.presenting(operator, |b| pool().unjail(b, 42)).unwrap();
    let graph = b.build().unwrap();
    let report =
        preflight_tree(&one_intent(OPERATOR, &graph), &chain, &TestHasher, NETWORK).unwrap();

    // A pool is owned by nobody, so its operator surface admits whoever
    // presents the pool's own badge: the holder's own signature at the
    // presentation, and the badge itself at the surface — reachable only
    // through that presentation, which is the point, and which the
    // report says rather than calling the surface unreachable.
    assert_eq!(
        report.authority[0].authority,
        Authority::Signature(OPERATOR)
    );
    assert_eq!(
        report.authority[1].authority,
        Authority::Badge {
            resource: badge(),
            instance: None,
        }
    );
    assert_eq!(attesting(&report), [vec![OPERATOR]]);
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
    let report = preflight_tree(&one_intent(ALICE, &graph), &chain, &TestHasher, NETWORK).unwrap();

    for (address, text) in &report.named {
        assert_eq!(*text, address.to_text(NETWORK).unwrap());
        assert!(text.contains(NETWORK), "the word is in the text: {text}");
    }
    assert_eq!(
        report.text(ALICE),
        report.named.get(&ALICE.address()).map(String::as_str)
    );
    // A report on one network says nothing about another.
    let elsewhere =
        preflight_tree(&one_intent(ALICE, &graph), &chain, &TestHasher, "testnet").unwrap();
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
        preflight_tree(&one_intent(ALICE, &graph), &chain, &TestHasher, "Main Net"),
        Err(PreflightError::Network(TextError::InvalidCharacter(_)))
    ));
    assert!(matches!(
        preflight_tree(&one_intent(ALICE, &graph), &chain, &TestHasher, ""),
        Err(PreflightError::Network(TextError::IncompletePrefix))
    ));
}

#[test]
fn a_composition_names_every_signer_it_needs() {
    let chain = world();
    let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, 10).unwrap();
    sub.give(funds);
    account::deposit(&mut sub, BOB, taken).unwrap();

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(sub.into_decl().unwrap()).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    root.bind(sockets.one().unwrap(), funds).unwrap();
    account::deposit(&mut root, ALICE, gives.one().unwrap().min(10)).unwrap();
    let tree = root.build().unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
    // Each intent is attested by the account it acts as, the root first.
    assert_eq!(attesting(&report), [vec![ALICE], vec![BOB]]);
    assert_eq!(report.intents.len(), 2);
    assert_eq!(report.intents[1].accounts().collect::<Vec<_>>(), [BOB]);
    // The nullifier the composition would spend, named before signing.
    assert_eq!(report.identity(), tree.hash(&TestHasher));
}

/// A root that declares no nodes of its own is still an intent, and the
/// breakdown says so.
///
/// A composition can leave every call to its subintents — the root
/// carries the sockets and nothing else — and such a root appears in no
/// node's origin. Found by elimination it would vanish, and the
/// breakdown would report one intent where the tree binds two, quietly
/// dropping the composer who pays for all of it.
#[test]
fn a_root_that_calls_nothing_is_still_one_of_the_intents() {
    let chain = world();
    let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let funds = account::withdraw(&mut sub, BOB, RES_X, 10).unwrap();
    account::deposit(&mut sub, BOB, funds).unwrap();
    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(sub.into_decl().unwrap()).unwrap();
    sockets.none().unwrap();
    gives.none().unwrap();
    let tree = root.build().unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
    let nodes = report.manifest().nodes.len();
    let split = report.by_intent(&vec![1_000u64; nodes]).unwrap();

    assert_eq!(split.intents.len(), 2, "the empty root and Bob's subintent");
    assert_eq!(split.intents[0].intent, report.intents[0].intent);
    assert_eq!(split.intents[0].accounts, [ALICE]);
    assert_eq!(split.intents[0].nodes, 0, "the root calls nothing");
    assert_eq!(split.intents[1].accounts, [BOB]);
    assert_eq!(
        split.intents[1].exposure,
        std::iter::once((RES_X, 10)).collect(),
        "the withdrawal is Bob's, and so is the exposure"
    );
}

/// An intent's exposure is what leaves cells its own signer holds, not
/// everything its nodes touch.
///
/// A node's frame declares every cell the call reaches — a venue's
/// reserve as readily as the caller's vault — so folding a frame whole
/// would tell a signer they risk value that was never theirs. Here the
/// stake reaches the pool's own reserve and Alice's vault; only the
/// second is hers to lose.
#[test]
fn an_intent_is_exposed_only_by_the_cells_its_signer_holds() {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, RES_X, 100).unwrap();
    let units = pool().stake(&mut b, funds).unwrap();
    account::deposit(&mut b, ALICE, units).unwrap();
    let graph = b.build().unwrap();

    let tree = one_intent(ALICE, &graph);
    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
    let nodes = report.manifest().nodes.len();
    let gas_limits = vec![1_000u64; nodes];
    let split = report.by_intent(&gas_limits).unwrap();

    assert_eq!(split.intents.len(), 1, "one intent, no subintents");
    assert_eq!(split.intents[0].accounts, [ALICE]);
    assert_eq!(
        split.intents[0].exposure,
        std::iter::once((RES_X, 100)).collect(),
        "what the pool moves out of its own reserve is not Alice's to lose"
    );
}

/// The per-intent breakdown says what each intent owns and names what
/// no intent owns alone.
///
/// Both intents here move the same two vaults — the root withdraws from
/// Alice and pays Bob, the subintent withdraws from Bob and pays Alice —
/// so the cells they reach are shared. A breakdown that split those
/// bytes would hand a composer two figures summing past what the chain
/// charges, because the declaration is a set and the transaction pays
/// for a shared cell once. So the shared cells are listed, and what each
/// intent carries is what a node owns outright.
#[test]
fn a_shared_cell_is_named_rather_than_charged_to_either_intent() {
    let chain = world();
    let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_X, 10).unwrap();
    sub.give(funds);
    account::deposit(&mut sub, ALICE, taken).unwrap();

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(sub.into_decl().unwrap()).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    root.bind(sockets.one().unwrap(), funds).unwrap();
    account::deposit(&mut root, BOB, gives.one().unwrap().min(10)).unwrap();
    let tree = root.build().unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
    let nodes = report.manifest().nodes.len();
    let gas_limits: Vec<u64> = (1..=nodes as u64).map(|node| node * 1_000).collect();
    let split = report.by_intent(&gas_limits).unwrap();
    assert_eq!(split.intents.len(), 2, "the root and one subintent");

    // The root leads, then the subintents in envelope order — the order
    // `schemes` is given in, so each intent is paired with its own
    // signer's signature.
    let sub_hash = report.intents[1].intent;
    assert_ne!(split.intents[0].intent, sub_hash, "the root leads");
    assert_eq!(split.intents[1].intent, sub_hash);

    // What each intent owns outright sums to what the whole declares.
    assert_eq!(
        split.intents.iter().map(|cost| cost.compute).sum::<u64>(),
        gas_limit_total(&gas_limits),
    );
    assert_eq!(
        split
            .intents
            .iter()
            .map(|cost| cost.event_bytes)
            .sum::<u64>(),
        report.event_bytes,
    );
    assert_eq!(
        split.intents.iter().map(|cost| cost.nodes).sum::<u32>(),
        u32::try_from(nodes).unwrap(),
    );
    // Each intent names the account it acts as, rather than a weight
    // from a vector nothing guarantees is one per intent.
    assert_eq!(split.intents[0].accounts, [ALICE]);
    assert_eq!(split.intents[1].accounts, [BOB]);

    // And the cells both intents reach are named, which is the whole
    // reason the bytes are not split.
    assert!(
        !split.shared.is_empty(),
        "two intents moving one pair of vaults share cells"
    );

    // Each signer's exposure is what their own declaration reserves —
    // Alice signed a hundred out, Bob ten — and neither is charged with
    // the other's, whatever the composition does with the value.
    assert_eq!(
        split.intents[0].exposure,
        std::iter::once((RES_X, 100)).collect(),
    );
    assert_eq!(
        split.intents[1].exposure,
        std::iter::once((RES_X, 10)).collect(),
    );
    for cost in &split.intents {
        assert!(
            !cost.unbounded_outflow,
            "a withdrawal reserves its amount, so the bound is the whole of it"
        );
    }
}

/// The compute column indexes the lowered order, so a subintent's nodes
/// sit where the bound tree put them; the column sums to the terms'
/// total, and so does its fold per intent.
#[test]
fn the_compute_column_sums_to_the_terms_and_splits_per_intent() {
    let chain = world();
    let mut sub = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, 10).unwrap();
    sub.give(funds);
    account::deposit(&mut sub, BOB, taken).unwrap();

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let Interface { sockets, gives } = root.adopt(sub.into_decl().unwrap()).unwrap();
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    root.bind(sockets.one().unwrap(), funds).unwrap();
    account::deposit(&mut root, ALICE, gives.one().unwrap().min(10)).unwrap();
    let tree = root.build().unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
    let nodes = report.manifest().nodes.len();
    assert_eq!(nodes, tree.node_count());
    let gas_limits: Vec<u64> = (1..=nodes as u64).map(|node| node * 1_000).collect();

    let column = report.compute(&gas_limits).unwrap();
    assert_eq!(
        column.iter().map(|row| row.ceiling).collect::<Vec<_>>(),
        gas_limits,
        "the column is the terms, in node order"
    );
    let total = gas_limit_total(&gas_limits);
    assert_eq!(
        report.work(&gas_limits, &[SchemeId::ED25519], 0).compute,
        total + DeclaredWork::signature(SchemeId::ED25519).compute,
    );

    let by_intent = report.compute_by_intent(&gas_limits).unwrap();
    assert_eq!(by_intent.len(), 2, "the root and one subintent");
    assert_eq!(by_intent.values().sum::<u64>(), total);
    // The subintent's nodes are the ones whose intent is the bound
    // declaration's hash; their ceilings are the positions the lowered
    // order gave them, not a contiguous run at either end.
    let sub_hash = report.intents[1].intent;
    let sub_nodes: Vec<u32> = column
        .iter()
        .filter(|row| row.intent == sub_hash)
        .map(|row| row.node)
        .collect();
    assert_eq!(
        sub_nodes.len(),
        tree.root.members[0].signed.intent.graph.nodes.len()
    );
    assert!(
        sub_nodes.iter().any(|node| *node > 0),
        "the interleave puts a subintent node after a root node"
    );
    assert_eq!(
        by_intent[&sub_hash],
        sub_nodes
            .iter()
            .map(|node| gas_limits[*node as usize])
            .sum::<u64>()
    );

    // One ceiling short, or one over, is the derivation's refusal.
    assert_eq!(
        report.compute(&gas_limits[..nodes - 1]),
        Err(TermsRefusal::CeilingArity {
            nodes,
            ceilings: nodes - 1,
        })
    );
    let mut heavy = gas_limits;
    heavy[0] = MAX_GAS_LIMIT;
    assert!(matches!(
        report.compute(&heavy),
        Err(TermsRefusal::CeilingSum { .. })
    ));
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

/// A guardian composing a call gated on another account's stored rule:
/// the report names the rule as one it cannot read, and the signers are
/// the guardian alone — it never claims the guardian's signature answers
/// a rule only the chain holds.
#[test]
fn a_stored_rule_on_another_account_is_reported_unread() {
    let chain = world();
    let bob = StoredRule::claim(Claim::of_subject(BOB));
    let governing = PrincipalRule::try_from(&bob).expect("a rule over principal claims encodes");
    let graph = TypedBuilder::compose(&chain, &TestHasher, BOB, |b| {
        account::freeze(b, ALICE, governing.clone(), governing)?;
        Ok(())
    })
    .unwrap();
    let report = preflight_tree(&one_intent(BOB, &graph), &chain, &TestHasher, NETWORK).unwrap();
    let freezing = report
        .authority
        .iter()
        .find(|required| required.method == "freeze")
        .expect("the freeze is gated");
    assert_eq!(freezing.authority, Authority::StoredRule);
    assert_eq!(attesting(&report), [vec![BOB]]);
    assert_eq!(report.unsatisfiable().count(), 0);
}

/// A disjunctive threshold reports every branch and commits to none:
/// which branch a holder satisfies is theirs to choose, so neither
/// branch signer is one the transaction certainly needs.
#[test]
fn a_disjunction_reports_its_branches_and_names_no_certain_signer() {
    let chain = world();
    let note = either_note_meta().address(&TestHasher);
    // Alice's own request, signed before any composer exists, with a
    // socket where the desk's approval goes; the withdrawal's own gate
    // is answered by the signature this intent carries.
    let mut request = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let approval = request.declare_proof(Claim::of_subject(DESK));
    let funds = request
        .presenting(approval, |b| b.call(ALICE, "withdraw", (note, 5u128)))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut request, ALICE, funds).unwrap();
    let request = request.into_decl().unwrap();

    // The desk's composition grants the account its own intent acts as.
    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root.adopt(request).unwrap().sockets.one().unwrap();
    root.bind(wants, DESK).unwrap();
    let tree = root
        .build_presenting(Vec::new(), vec![either_note_meta()])
        .unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
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
    // certain — only the holder's own gate is. The desk attests its own
    // root and Alice her request; Bob attests nothing.
    assert_eq!(attesting(&report), [vec![DESK], vec![ALICE]]);
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

    let mut root = IntentBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);
    let approval = root.call_proving(venue, "approve", ()).unwrap();
    let funds = root
        .presenting(approval, |b| b.call(ALICE, "withdraw", (ticket, 3u128)))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut root, BOB, funds).unwrap();
    let tree = root
        .build_presenting(Vec::new(), vec![ticket_meta()])
        .unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();
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
    let mut request = IntentBuilder::new(&chain, &TestHasher, BOB, TEST_HEADER);
    let approval = request.declare_proof(Claim::of_subject(DESK));
    let funds = request
        .presenting(approval, |b| b.call(BOB, "withdraw", (note, 40u128)))
        .unwrap()
        .one()
        .unwrap();
    account::deposit(&mut request, BOB, funds).unwrap();
    let request = request.into_decl().unwrap();

    let mut root = IntentBuilder::new(&chain, &TestHasher, DESK, TEST_HEADER);
    let wants = root.adopt(request).unwrap().sockets.one().unwrap();
    root.bind(wants, DESK).unwrap();
    let tree = root
        .build_presenting(Vec::new(), vec![note_meta()])
        .unwrap();

    let report = preflight_tree(&tree, &chain, &TestHasher, NETWORK).unwrap();

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
    // certainly needs: the desk attests the root and Bob his request.
    assert!(report.text(DESK).is_some());
    assert_eq!(attesting(&report), [vec![DESK], vec![BOB]]);
    assert_eq!(report.unsatisfiable().count(), 0);
}
