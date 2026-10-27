//! A tree creates any one leaf at most once.
//!
//! A create's one-way door is judged once, against committed state,
//! before any body runs, so two nodes creating one leaf would both pass
//! it and the second would silently overwrite the first. Admission sees
//! every create's target, because a declaration depends on its inputs
//! alone, and refuses the second one there.

mod common;

use common::{ALICE, BOB};
use hyperscale_hbor::{Capped, Name, TypeShape};
use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::{
    AbiParam, AdmissionError, Admitted, Binding, ChainRecords, Expr, GraphArg, GraphNode, Hash32,
    Hasher, InstanceMeta, Intent, IntentHeader, IntentTree, ManifestGraph, Member, MethodSignature,
    PackageHash, PackageMetadata, ParamType, Records, RuleExpr, RuleLeaf, SignedIntent, SlotId,
    SlotKind, SlotRef, SlotShape, TestHasher, Value, admit_tree, package_slot,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{ComponentAddr, Moves, NetworkId, Presence, PrincipalAddr};

/// The claims package's one keyed family: a leaf per claimed name.
const CLAIMS: SlotId = package_slot(0);

fn account_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn claims_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"claims"]))
}

fn lottery_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"lottery"]))
}

/// The leaf a name is claimed at.
fn claimed() -> TargetExpr {
    TargetExpr::Point(Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(CLAIMS),
        material: vec![Expr::Arg(0)],
    })
}

/// `claim(name)` creates the name's leaf; `taken(name)` reads it,
/// expecting it absent.
fn claims() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    let element = metadata
        .types
        .push(TypeShape::U128)
        .expect("a scalar joins any table");
    metadata.state.insert(
        CLAIMS,
        SlotShape {
            name: Name::declared("claims"),
            kind: SlotKind::Keyed,
            element,
            width: 16,
            denomination: None,
        },
    );
    let absent = || Clause::Requires {
        guard: None,
        rule: RuleExpr::Require(RuleLeaf::Presence {
            target: Box::new(claimed()),
            expect: Presence::Absent,
        }),
    };
    for (method, mode) in [
        ("claim", ModeExpr::Write { moves: Moves::Both }),
        ("taken", ModeExpr::Read),
    ] {
        metadata.methods.insert(
            Name::declared(method),
            MethodSignature {
                declines: false,
                issues: Capped::empty(),
                params: vec![ParamType::U64],
                abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
                effects: vec![
                    Clause::Effect {
                        reach: None,
                        guard: None,
                        target: claimed(),
                        mode,
                        denomination: None,
                    },
                    absent(),
                ],
                ..MethodSignature::default()
            },
        );
    }
    metadata
}

/// Any window; these tests never validate one against a clock.
const HEADER: IntentHeader = IntentHeader {
    network: NetworkId(242),
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

/// The registry instance the claims are made at.
fn registry() -> InstanceMeta {
    InstanceMeta {
        package: claims_pkg(),
        config: Capped::empty(),
        salt: Hash32([3; 32]),
    }
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(account_pkg(), account::metadata());
    chain.packages.publish_unchecked(claims_pkg(), claims());
    chain
        .packages
        .publish_unchecked(lottery_pkg(), lottery::metadata());
    chain.instances.serve_principals(account_pkg());
    chain.instances.create(&TestHasher, registry());
    chain
}

fn call(target: ComponentAddr, method: &str, args: Vec<GraphArg>) -> GraphNode {
    GraphNode {
        target: target.into(),
        method: method.into(),
        args,
        evidence: Capped::default(),
    }
}

fn on_registry(method: &str, name: u64) -> GraphNode {
    call(
        registry().address(&TestHasher),
        method,
        vec![GraphArg::Literal(Value::U64(name))],
    )
}

fn intent(account: PrincipalAddr, nodes: Vec<GraphNode>) -> Intent {
    Intent::leaf(
        HEADER,
        account,
        ManifestGraph {
            nodes: Capped::new(nodes).unwrap(),
        },
    )
}

fn admit(tree: &IntentTree, chain: &dyn ChainRecords) -> Result<Admitted, AdmissionError> {
    admit_tree(tree, tree.hash(&TestHasher), chain, &TestHasher)
}

fn admit_one(nodes: Vec<GraphNode>) -> Result<Admitted, AdmissionError> {
    admit(&IntentTree::of_one(intent(ALICE, nodes)), &world())
}

#[test]
fn a_leaf_created_twice_in_one_intent_is_refused() {
    let refused = admit_one(vec![on_registry("claim", 7), on_registry("claim", 7)]);
    assert!(
        matches!(
            refused,
            Err(AdmissionError::LeafCreatedEarlier {
                node: 1,
                creator: 0
            })
        ),
        "{refused:?}"
    );
}

#[test]
fn a_composer_cannot_create_what_a_member_it_adopts_creates() {
    // Bob signed a claim and paid for it; Alice composes it and claims
    // the same name after it. Without the refusal her write lands last
    // and Bob's claim is silently gone.
    let mut root = intent(ALICE, vec![on_registry("claim", 7)]);
    root.members = vec![Member {
        signed: SignedIntent::unsigned(intent(BOB, vec![on_registry("claim", 7)])),
        wiring: Capped::new(Vec::<Binding>::new()).unwrap(),
    }]
    .try_into()
    .unwrap();
    let refused = admit(&IntentTree::of_one(root), &world());
    assert!(
        matches!(refused, Err(AdmissionError::LeafCreatedEarlier { .. })),
        "{refused:?}"
    );
}

#[test]
fn expecting_a_leaf_absent_after_the_tree_creates_it_is_refused() {
    let refused = admit_one(vec![on_registry("claim", 7), on_registry("taken", 7)]);
    assert!(
        matches!(
            refused,
            Err(AdmissionError::LeafCreatedEarlier {
                node: 1,
                creator: 0
            })
        ),
        "{refused:?}"
    );
}

#[test]
fn distinct_leaves_and_absent_reads_still_admit() {
    assert!(admit_one(vec![on_registry("claim", 7), on_registry("claim", 8)]).is_ok());
    assert!(admit_one(vec![on_registry("taken", 7), on_registry("taken", 7)]).is_ok());
    // Read before the create: its premise held when it ran.
    assert!(admit_one(vec![on_registry("taken", 7), on_registry("claim", 7)]).is_ok());
}

#[test]
fn two_seals_of_one_component_in_a_tree_are_refused() {
    let round = InstanceMeta {
        package: lottery_pkg(),
        config: Capped::empty(),
        salt: Hash32([5; 32]),
    };
    let address = round.address(&TestHasher);
    let tree = IntentTree {
        root: intent(
            ALICE,
            vec![
                call(address, "instantiate", Vec::new()),
                call(address, "instantiate", Vec::new()),
            ],
        ),
        instances: Capped::new(vec![round]).unwrap(),
        resources: Capped::empty(),
    };
    let refused = admit(&tree, &world());
    assert!(
        matches!(
            refused,
            Err(AdmissionError::LeafCreatedEarlier {
                node: 1,
                creator: 0
            })
        ),
        "{refused:?}"
    );
}
