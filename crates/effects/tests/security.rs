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
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    EdgeRef, EnvelopeTree, EvidenceRef, GrantedBehaviour, GraphArg, GraphNode, Hash32,
    InstanceMeta, IntentDecl, Issuance, JudgedLeaf, ManifestGraph, Records, ResourceMeta, Rule,
    TestHasher, Value, admit_tree, child_key, granting_issued_resource,
};
use hyperscale_vm_fixtures::security;
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Effect, EffectTarget, Mode, Presence, PrincipalAddr,
    ResourceAddr, SubstateKey,
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
        config: config(),
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
        .filter_map(|signature| signature.issues)
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
        material: vec![Value::Bytes(mark.to_vec()).canonical_bytes()],
        rules: issuance
            .grants
            .resolve(&TestHasher, issuer.into(), &config())
            .expect("the declared grants resolve against the instance"),
    }
}

/// The leaf that answers whether `owner` holds `badge`.
fn credential(owner: impl Into<Address>, badge: ResourceAddr) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(badge.address()).canonical_bytes()],
    )
}

/// A withdrawal of `resource` from [`ALICE`]'s own account, banked back
/// into it — an ordinary transfer declaring nothing about any rule.
fn transfer(resource: ResourceAddr) -> EnvelopeTree {
    transfer_to(resource, ALICE)
}

/// The same transfer, landing under `recipient`.
fn transfer_to(resource: ResourceAddr, recipient: PrincipalAddr) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: ALICE.into(),
                        method: "authorize".into(),
                        args: Vec::new(),
                        evidence: BTreeSet::from([EvidenceRef::IntentSignature]),
                    },
                    GraphNode {
                        target: ALICE.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(resource.address())),
                            GraphArg::Literal(Value::U128(40)),
                        ],
                        evidence: BTreeSet::from([EvidenceRef::Node(0)]),
                    },
                    GraphNode {
                        target: recipient.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 1,
                                output: 0,
                            },
                            constraints: Vec::new(),
                        }],
                        evidence: BTreeSet::default(),
                    },
                ],
            },
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
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
    let share = issued(issuer, b"share");
    let registered = issued(issuer, b"registered");
    let bearer = issued(issuer, b"bearer");

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
    let share = issued(issuer, b"share");
    let registered = issued(issuer, b"registered");

    let mut env = transfer(share);
    env.resources = vec![record(issuer, b"share")];
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the transfer admits");
    let declaration = admitted.admitted.declaration();

    let cell = credential(ALICE, registered);
    assert!(
        declaration
            .conditions
            .contains(&Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(cell),
                expect: Presence::Present,
            })),
        "the withdrawal is judged against the mover's own register entry",
    );
    assert!(
        declaration.set.contains(&Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Read,
        }),
        "and the leaf is provisioned by the declaration that reads it",
    );

    // One leaf, not an interval: a register entry is a balance, so every
    // injected presence read on this transfer path is a point.
    assert!(
        declaration.conditions.iter().all(|condition| matches!(
            condition,
            Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(_),
                ..
            })
        )),
        "a fungible credential is one leaf and never a scan: {:?}",
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
    let share = issued(issuer, b"share");
    let registered = issued(issuer, b"registered");

    let mut env = transfer_to(share, BOB);
    env.resources = vec![record(issuer, b"share")];
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the transfer admits");
    let conditions = &admitted.admitted.declaration().conditions;

    for holder in [Address::from(ALICE), Address::from(BOB)] {
        assert!(
            conditions.contains(&Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(credential(holder, registered)),
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
    let env = transfer(issued(issuer, b"bearer"));
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the transfer admits with no record presented at all");
    assert!(
        !admitted
            .admitted
            .declaration()
            .conditions
            .iter()
            .any(|condition| matches!(condition, Rule::Require(JudgedLeaf::Presence { .. }))),
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

    let mut env = transfer(issued(issuer, b"registered"));
    env.resources = vec![record(issuer, b"registered")];
    let refusal = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect_err("no holder may debit their own register entry");
    let said = refusal.to_string();
    assert!(
        said.contains("grants Withdraw to nobody"),
        "the refusal names the direction it refused: {said}",
    );
}

/// The behaviours the guest's own declaration grants, so the fixture
/// above cannot pass against a declaration that stopped granting them.
#[test]
fn the_guest_grants_what_these_cases_are_about() {
    let granted: BTreeSet<GrantedBehaviour> = security::metadata()
        .methods
        .values()
        .filter_map(|signature| signature.issues.as_ref())
        .flat_map(|issuance| issuance.grants.iter().map(|(behaviour, _)| behaviour))
        .collect();
    assert_eq!(
        granted,
        BTreeSet::from([
            GrantedBehaviour::Withdraw,
            GrantedBehaviour::Deposit,
            GrantedBehaviour::Recall,
        ]),
        "both movement entries to enforce and an authority entry to stay plain beside them",
    );
}
