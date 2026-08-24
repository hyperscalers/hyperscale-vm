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
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    Condition, EdgeRef, EnvelopeTree, Grant, GrantedBehaviour, GraphArg, GraphNode, Hash32,
    InstanceMeta, IntentDecl, ManifestGraph, Records, ResourceGrants, ResourceKind, ResourceMeta,
    TestHasher, Value, admit_tree, child_key,
};
use hyperscale_vm_fixtures::custodian;
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Effect, EffectTarget, Mode, Presence, ResourceAddr,
    SubstateKey,
};

/// The badge the governed resource's withdraw entry names.
const BADGE: ResourceAddr = ResourceAddr::new([0x77; 31]);
/// Whose namespace the governed resource sits in.
const ISSUER: Address = Address::new([0x6A; 31], AddressClass::Component);

fn governed_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(GrantedBehaviour::Withdraw, Grant::Credential(BADGE));
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

/// A custodian holding the governed resource, and a second asset beside
/// it so a movement can happen with no account in the transaction.
fn custody_world() -> (Records, ComponentAddr) {
    let mut chain = world();
    chain
        .packages
        .publish_unchecked(pkg("custodian"), custodian::metadata());
    let meta = InstanceMeta {
        package: pkg("custodian"),
        config: vec![
            Value::Address(governed().address()),
            Value::Address(governed().address()),
            Value::Address(governed().address()),
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
            params: Vec::new(),
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
        admitted
            .admitted
            .declaration()
            .conditions
            .contains(&Condition::Holds {
                target: EffectTarget::Point(cell),
                presence: Presence::Present,
            }),
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
