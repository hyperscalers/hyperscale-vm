//! A component that declares no rule is bound anyway.
//!
//! The case a holder-side fence cannot reach. `guests/custodian` holds
//! value and cooperates with nothing: no gate, no halt leaf, and no
//! method anybody could call to make it behave. If a movement of a
//! governed resource through *that* is judged against the resource's
//! entry, it is judged everywhere — because there is nothing here an
//! author could have done differently, and every lending pool, book and
//! escrow already has these methods.
//!
//! What the cases below establish is the part that is novel: the
//! requirement is resolved against the **access owner**, so the vault
//! being moved is what answers for itself. A design that asked about the
//! caller would find a stranger at every one of these methods and bind
//! nothing.

mod common;

use std::collections::BTreeSet;

use common::{ALICE, BOB, pkg, world};
use hyperscale_vm_effects::vocabulary::{HALT, VAULT};
use hyperscale_vm_effects::{
    AdmissionError, Claim, EdgeRef, EnvelopeTree, EvidenceRef, GrantedBehaviour, GraphArg,
    GraphNode, Hash32, Holding, InstanceMeta, IntentDecl, JudgedLeaf, ManifestGraph, Records,
    ResourceGrants, ResourceKind, ResourceMeta, Rule, RuleBytes, SlotRef, StoredRule, TestHasher,
    Value, admit_tree, child_key,
};
use hyperscale_vm_fixtures::custodian;
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Effect, EffectTarget, Mode, Moves, Presence,
    PrincipalAddr, ResourceAddr, SubstateKey,
};

/// The badge the governed resource's withdraw entry names.
const BADGE: ResourceAddr = ResourceAddr::new([0x77; 31]);
/// Whose namespace the governed resource sits in.
const ISSUER: Address = Address::new([0x6A; 31], AddressClass::Component);

fn sealed(rule: &StoredRule) -> RuleBytes {
    RuleBytes::try_from(rule).expect("a rule within the caps encodes")
}

fn governed_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Withdraw,
        sealed(&StoredRule::held(BADGE, Holding::Balance)),
    );
    ResourceMeta {
        namespace: ISSUER,
        kind: ResourceKind::Fungible,
        material: vec![b"governed".to_vec()],
        rules,
    }
}

fn governed() -> ResourceAddr {
    governed_meta().address(&TestHasher)
}

/// The same shape from the other end: a resource whose entry governs who
/// may be credited rather than who may debit.
fn admitting_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Deposit,
        sealed(&StoredRule::held(BADGE, Holding::Balance)),
    );
    ResourceMeta {
        namespace: ISSUER,
        kind: ResourceKind::Fungible,
        material: vec![b"admitting".to_vec()],
        rules,
    }
}

/// The same again, granting a halt: an issuer who can stop a holder
/// moving it, and nothing else.
fn freezable_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Halt,
        sealed(&StoredRule::claim(Claim::of_subject(ISSUER))),
    );
    ResourceMeta {
        namespace: ISSUER,
        kind: ResourceKind::Fungible,
        material: vec![b"freezable".to_vec()],
        rules,
    }
}

fn freezable() -> ResourceAddr {
    freezable_meta().address(&TestHasher)
}

/// A custodian holding the governed resource, and a second asset beside
/// it so a movement can happen with no account in the transaction.
fn custody_world() -> (Records, ComponentAddr) {
    custody_world_over(governed())
}

/// The same, over whichever resource the case is about.
fn custody_world_over(asset: ResourceAddr) -> (Records, ComponentAddr) {
    let mut chain = world();
    chain
        .packages
        .publish_unchecked(pkg("custodian"), custodian::metadata());
    let meta = InstanceMeta {
        package: pkg("custodian"),
        config: vec![
            Value::Address(asset.address()),
            Value::Address(asset.address()),
            Value::Address(asset.address()),
        ],
        salt: Hash32([0x5C; 32]),
    };
    let custodian = meta.address(&TestHasher);
    chain.instances.create(&TestHasher, meta);
    (chain, custodian)
}

/// The leaf that answers whether `owner` holds the badge.
fn credential(owner: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(BADGE.address()).canonical_bytes()],
    )
}

/// The custodian paying `holder`, so the value lands in an account —
/// which keeps two families of vaults rather than one.
fn paid_out(custodian: ComponentAddr, holder: PrincipalAddr) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: custodian.into(),
                        method: "withdraw".into(),
                        args: vec![GraphArg::Literal(Value::U128(40))],
                        evidence: BTreeSet::default(),
                    },
                    GraphNode {
                        target: holder.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            constraints: Vec::new(),
                        }],
                        evidence: BTreeSet::default(),
                    },
                ],
            },
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    }
}

/// A round trip through the custodian's own vault and back into it.
///
/// Two nodes and no account: the value never leaves this component, so
/// whoever signed has no holding in the transaction at all. Value is
/// linear, so the withdrawal's edge has to land somewhere — and landing
/// it back here is what makes the whole movement the custodian's own.
fn round_trip(custodian: ComponentAddr) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: custodian.into(),
                        method: "withdraw".into(),
                        args: vec![GraphArg::Literal(Value::U128(40))],
                        evidence: BTreeSet::default(),
                    },
                    GraphNode {
                        target: custodian.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            constraints: Vec::new(),
                        }],
                        evidence: BTreeSet::default(),
                    },
                ],
            },
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: vec![governed_meta()],
    }
}

/// A withdrawal from a component's own vault is judged against what
/// **that component** holds, in a declaration that says nothing about
/// any of it.
#[test]
fn a_component_answers_for_its_own_vault() {
    let (chain, custodian) = custody_world();
    let env = round_trip(custodian);
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the custodian's own withdrawal admits");

    let cell = credential(custodian);
    assert!(
        admitted.admitted.declaration().required().any(|rule| *rule
            == Rule::Require(JudgedLeaf::Presence {
                target: EffectTarget::Point(cell),
                expect: Presence::Present,
            })),
        "the requirement is the custodian's own, not its caller's",
    );
    assert!(
        admitted.admitted.declaration().set.contains(&Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Read,
        }),
        "and the leaf it reads is provisioned by the declaration",
    );

    // Whoever signs, the question is the same and the cell is the same:
    // a design that asked about the caller would ask about ALICE here
    // and BOB below, and bind neither.
    let other = admit_tree(&env, BOB, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("a different signer admits the same way");
    assert_eq!(
        other.admitted.declaration().conditions,
        admitted.admitted.declaration().conditions,
        "the caller is not who the rule is about",
    );
    assert!(
        !admitted.admitted.declaration().set.contains(&Effect {
            target: EffectTarget::Point(credential(ALICE)),
            mode: Mode::Read,
        }),
        "and no signer's own credential is consulted",
    );
}

/// A halt on the custodian stops the custodian's own withdrawal, in a
/// declaration that neither reads a halt leaf nor could be made to.
///
/// This is the case a holder-side fence cannot reach, and the reason the
/// fence is injected rather than declared. A design where freezing meant
/// "the account checks a flag" binds accounts and stops at the first
/// deposit into any application — and the adversary picks where to
/// stand, so a negative capability with a gap is defeated rather than
/// partial. Here the read is admission's, keyed by the vault's own
/// owner, so the component holding the value answers for itself.
#[test]
fn a_halt_binds_the_component_holding_the_value() {
    let (chain, custodian) = custody_world_over(freezable());
    let env = round_trip(custodian);
    let mut env = env;
    env.resources = vec![freezable_meta()];
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the custodian's own withdrawal admits");

    let halted = EffectTarget::Point(child_key(
        &TestHasher,
        custodian,
        HALT,
        &[Value::Address(freezable().address()).canonical_bytes()],
    ));
    assert!(
        admitted.admitted.declaration().required().any(|rule| *rule
            == Rule::Require(JudgedLeaf::Presence {
                target: halted,
                expect: Presence::Absent,
            })),
        "every movement of a freezable resource requires the mover's flag absent",
    );
    assert!(
        admitted.admitted.declaration().set.contains(&Effect {
            target: halted,
            mode: Mode::Read,
        }),
        "and the leaf is provisioned by the same declaration that requires it",
    );
}

/// A halt is keyed by the holder and the resource, never by the slot —
/// so it covers every cell that holder keeps the resource in.
///
/// The property the fence rests on. If the flag were per-slot, a holder
/// would keep a second family of vaults at a second slot and carry on
/// moving. An account is exactly such a holder: its deposit reaches its
/// protocol vault and its own quarantine, two families at two slots, and
/// both answer to the one leaf.
#[test]
fn a_halt_covers_every_slot_the_holder_keeps_the_resource_in() {
    let (chain, custodian) = custody_world_over(freezable());
    let mut env = paid_out(custodian, ALICE);
    env.resources = vec![freezable_meta()];
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the payout admits");
    let declaration = admitted.admitted.declaration();

    // Two of the recipient's own cells take the value, at two different
    // slots — which is the shape that would defeat a per-slot flag.
    let landed: BTreeSet<EffectTarget> = declaration
        .ordered
        .iter()
        .filter(|access| {
            access.holds == Some(freezable()) && access.effect.target.owner() == ALICE.address()
        })
        .map(|access| access.effect.target)
        .collect();
    assert_eq!(
        landed.len(),
        2,
        "a deposit reaches the vault and the quarantine"
    );

    // And one leaf answers for all of them.
    let asked: BTreeSet<EffectTarget> = declaration
        .required()
        .flat_map(Rule::leaves)
        .filter_map(|leaf| match leaf {
            JudgedLeaf::Presence { target, .. } => Some(*target),
            _ => None,
        })
        .filter(|target| target.owner() == ALICE.address())
        .collect();
    assert_eq!(
        asked,
        BTreeSet::from([EffectTarget::Point(child_key(
            &TestHasher,
            ALICE,
            HALT,
            &[Value::Address(freezable().address()).canonical_bytes()],
        ))]),
        "one flag answers for the holder, whatever slot they keep it at",
    );
}

/// A resource whose issuer cannot halt anybody puts no read on the
/// transfer path.
///
/// The unrestricted path pays nothing, which is what keeps the fence
/// from being a tax on every holder of every resource: absence of the
/// entry is absence of the leaf, the read and the condition alike.
#[test]
fn a_resource_granting_no_freeze_reads_no_halt_leaf() {
    let (chain, custodian) = custody_world();
    let env = round_trip(custodian);
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the governed resource moves on its own terms");

    let would_be = EffectTarget::Point(child_key(
        &TestHasher,
        custodian,
        HALT,
        &[Value::Address(governed().address()).canonical_bytes()],
    ));
    assert!(
        !admitted.admitted.declaration().set.contains(&Effect {
            target: would_be,
            mode: Mode::Read,
        }),
        "a resource nobody can halt costs its holders no halt read",
    );
}

/// A declaration that carries its direction is judged on the movement it
/// makes, and not on the one it gave up.
///
/// This is what separates the two movement behaviours in practice. A
/// bidirectional access has to answer for both, so a resource governing
/// only withdrawals ends up governing deposits too and the two collapse
/// into one. A method that says it only receives is asked only what a
/// recipient is asked — which for a withdraw-governed resource is
/// nothing, and for a deposit-governed one is the recipient's own
/// credential.
#[test]
fn a_credit_is_asked_only_what_a_recipient_is_asked() {
    use hyperscale_vm_effects::vocabulary::VAULT;
    use hyperscale_vm_effects::{
        Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, TargetExpr, Totality,
    };

    let vault_of = |resource: Expr| {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(VAULT),
            material: vec![resource],
        })
    };
    let receiving = |asset: ResourceAddr, mode: ModeExpr| {
        let asset = || Expr::Literal(Value::Address(asset.address()));
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "receive".into(),
            MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: vault_of(asset()),
                    mode,
                    denomination: Some(Box::new(asset())),
                }],
                ..MethodSignature::default()
            },
        );
        package
    };

    let admitted = |meta: ResourceMeta, mode: ModeExpr, name: &str| {
        let mut chain = world();
        chain
            .packages
            .publish_unchecked(pkg(name), receiving(meta.address(&TestHasher), mode));
        let instance = InstanceMeta {
            package: pkg(name),
            config: Vec::new(),
            salt: Hash32([0x5D; 32]),
        };
        let target = instance.address(&TestHasher);
        chain.instances.create(&TestHasher, instance);
        let env = EnvelopeTree {
            root: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![GraphNode {
                        target: target.into(),
                        method: "receive".into(),
                        args: Vec::new(),
                        evidence: BTreeSet::default(),
                    }],
                },
                sockets: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
            instances: Vec::new(),
            resources: vec![meta],
        };
        let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
            .expect("the receiving method admits");
        let asked = admitted.admitted.declaration().required().cloned();
        (target, asked.collect::<Vec<_>>())
    };

    // Both declarations carry the instantiation fence, which is nobody's
    // movement — what is under test is the credential beside it.
    let wants_credential = |target, conditions: &[Rule<JudgedLeaf>]| {
        conditions.contains(&Rule::Require(JudgedLeaf::Presence {
            target: EffectTarget::Point(credential(target)),
            expect: Presence::Present,
        }))
    };

    // The governed resource grants `Withdraw` and nothing else, so a
    // credit earns no requirement from it at all.
    let (receiver, credited) = admitted(governed_meta(), ModeExpr::Credit, "receiver");
    assert!(
        !wants_credential(receiver, &credited),
        "a credit is not asked for a withdrawal credential: {credited:?}",
    );

    // The same cell, the same resource, one word different: a
    // bidirectional access has to answer for the debit it might make,
    // so a withdraw-only credential ends up gating the credit too.
    let (both_ways, both) = admitted(governed_meta(), ModeExpr::Delta, "bidirectional");
    assert!(
        wants_credential(both_ways, &both),
        "a delta answers for both directions, so it carries the withdrawal's: {both:?}",
    );

    // And the mirror. A resource governing who may *receive* asks the
    // credit and leaves the reservation alone, which is the same
    // sentence read from the other end: each direction answers for the
    // movement it makes.
    let (credited, asked) = admitted(admitting_meta(), ModeExpr::Credit, "recipient");
    assert!(
        wants_credential(credited, &asked),
        "a credit is asked for the deposit credential: {asked:?}",
    );
    let (debited, unasked) = admitted(
        admitting_meta(),
        ModeExpr::Reserve(Expr::Literal(Value::U128(1))),
        "sender",
    );
    assert!(
        !wants_credential(debited, &unasked),
        "and a reservation, which only debits, is not: {unasked:?}",
    );
}

/// A transfer between two accounts: sign in, reserve, credit.
///
/// The shape the case below needs and the custodian cannot give it. A
/// reservation debits and says so, so the withdrawing node earns the
/// `Withdraw` entry alone; the crediting node is `deposit`, which is
/// the one method in the corpus carrying the total mark.
fn transferred(from: PrincipalAddr, to: PrincipalAddr, resource: ResourceAddr) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: from.into(),
                        method: "authorize".into(),
                        args: vec![],
                        evidence: [EvidenceRef::IntentSignature].into(),
                    },
                    GraphNode {
                        target: from.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(resource.address())),
                            GraphArg::Literal(Value::U128(40)),
                        ],
                        evidence: [EvidenceRef::Node(0)].into(),
                    },
                    GraphNode {
                        target: to.into(),
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
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    }
}

/// A movement entry a total frame cannot be held to is refused where
/// the entry is read, not carried into the leg that would fail.
///
/// The mark says a caller may commit without waiting to hear back, so
/// every verdict the frame carries has to land before any leg does.
/// Admission answers an entry reading the call's own evidence and
/// materialization answers one reading committed state; an entry asking
/// *both* what the mover holds and what the call presented is
/// answerable in neither, so what would reach it is the declaring
/// node's own walk — after a caller may already have committed.
///
/// The one-sided forms are the contrast: each lands on the same total
/// deposit and neither is refused.
#[test]
fn a_total_frame_carries_no_entry_its_own_leg_would_answer() {
    let entry = |rule: StoredRule| ResourceMeta {
        namespace: ISSUER,
        kind: ResourceKind::Fungible,
        material: vec![b"approved".to_vec()],
        rules: {
            let mut rules = ResourceGrants::new();
            rules.set(GrantedBehaviour::Deposit, sealed(&rule));
            rules
        },
    };
    let approver = Claim::of_subject(Address::new([0x4A; 31], AddressClass::Principal));
    let holds = StoredRule::held(BADGE, Holding::Balance);
    let claims = StoredRule::claim(approver);
    let mixed = StoredRule::CountOf {
        count: 2,
        rules: vec![claims.clone(), holds.clone()],
    };

    let admitting = |rule: StoredRule| {
        let record = entry(rule);
        let chain = world();
        let mut env = transferred(ALICE, BOB, record.address(&TestHasher));
        env.resources = vec![record];
        admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
    };

    // A holding is materialization's, and a claim is admission's: both
    // land before any leg, so the deposit's mark stands beside either.
    // The claim goes unpresented here, which is a refusal about the
    // evidence rather than about the mark.
    assert!(admitting(holds).is_ok());
    assert!(matches!(
        admitting(claims),
        Err(AdmissionError::MissingEvidence { node: 2 })
    ));

    // Both at once is the one no earlier stage can answer.
    let resource = entry(mixed.clone()).address(&TestHasher);
    assert_eq!(
        admitting(mixed),
        Err(AdmissionError::MovementUnanswerable {
            node: 2,
            resource,
            behaviour: GrantedBehaviour::Deposit,
        }),
    );
}

/// And the read that answers it is declared once, however many
/// directions the access moves in.
///
/// A commutative movement earns a withdraw entry and a deposit entry, so
/// the injection runs twice over one holder and one resource — and the
/// flag they both read is one leaf. A second ordered entry for it would
/// be a second capability the kernel materializes and a second line in
/// what the sender is billed for, for a question already asked.
#[test]
fn one_flag_is_read_once_however_many_directions_the_access_moves_in() {
    let (chain, custodian) = custody_world_over(freezable());
    let mut env = round_trip(custodian);
    env.resources = vec![freezable_meta()];
    let admitted = admit_tree(&env, ALICE, env.hash(&TestHasher), &chain, &TestHasher)
        .expect("the custodian moves its own value on the resource's terms");
    // One frame's own view: two nodes each fence their own movement, and
    // two frames reading one flag is two reads that are each once.
    let ordered = &admitted.admitted.frames()[0].ordered;

    // The custodian's own vault takes the value both ways, which is what
    // earns both entries.
    let both_ways = ordered.iter().any(|access| {
        access.holds == Some(freezable())
            && access.effect.target.owner() == custodian.address()
            && access.effect.mode.moves() == Some(Moves::Both)
    });
    assert!(both_ways, "the fixture moves value in both directions");

    let flag = EffectTarget::Point(child_key(
        &TestHasher,
        custodian,
        HALT,
        &[Value::Address(freezable().address()).canonical_bytes()],
    ));
    let reads = ordered
        .iter()
        .filter(|access| {
            access.effect
                == Effect {
                    target: flag,
                    mode: Mode::Read,
                }
        })
        .count();
    assert_eq!(reads, 1, "one flag, one read of it");
}
