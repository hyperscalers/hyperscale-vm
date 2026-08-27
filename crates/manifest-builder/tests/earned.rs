//! What a call's movements earn rides beside how the method signs in.
//!
//! A rule-reading method takes the intent's signature — whether the key
//! still holds its account's authority is the stored rule's question.
//! But a resource the same call moves asks its own question, and the
//! answer is the sign-in node the builder minted for it. Dropping that
//! reference would leave a dead node in the graph and the movement's
//! claim unpresented, so the signature and the earned proofs are one
//! evidence set.

use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::{AUTH, VAULT};
use hyperscale_vm_effects::{
    ChainRecords, Claim, Clause, EvidenceRef, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ResourceGrants, ResourceKind,
    ResourceMeta, RuleBytes, RuleExpr, RuleLeaf, SlotRef, StoredRule, TargetExpr, TestHasher,
    Totality, Value,
};
use hyperscale_vm_manifest_builder::TypedBuilder;
use hyperscale_vm_types::{CallTarget, Moves, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// A badge whose deposit rule asks for Alice, so a call moving it earns
/// a claim the builder mints a sign-in for.
const BADGE: ResourceAddr = ResourceAddr::new([0xBA; 31]);

struct Principals {
    principal: Arc<InstanceMeta>,
    account_hash: PackageHash,
    account: Arc<PackageMetadata>,
}

impl Principals {
    fn new() -> Self {
        let account_hash = PackageHash(TestHasher.hash(b"package", &[b"account"]));
        Self {
            principal: Arc::new(InstanceMeta {
                package: account_hash,
                config: Vec::new(),
                salt: Hash32([0; 32]),
            }),
            account_hash,
            account: Arc::new(account()),
        }
    }
}

impl ChainRecords for Principals {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        match target {
            CallTarget::Principal(_) => Some(self.principal.clone()),
            CallTarget::Component(_) => None,
        }
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        (hash == self.account_hash).then(|| self.account.clone())
    }

    fn resource(&self, resource: ResourceAddr, _hasher: &dyn Hasher) -> Option<ResourceMeta> {
        let mut rules = ResourceGrants::new();
        let asks_for_alice = RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(ALICE)))
            .expect("a rule encodes");
        rules.set(GrantedBehaviour::Deposit, asks_for_alice);
        (resource == BADGE).then_some(ResourceMeta {
            namespace: ALICE.address(),
            kind: ResourceKind::Fungible,
            material: Vec::new(),
            rules,
        })
    }
}

/// The moving clause `spend` declares: the caller's own vault of the
/// badge, either direction.
fn moves_the_badge() -> Clause {
    let badge = Expr::Literal(Value::Address(BADGE.address()));
    Clause::Effect {
        reach: None,
        guard: None,
        target: TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(VAULT),
            material: vec![badge.clone()],
        }),
        mode: ModeExpr::Delta { moves: Moves::Both },
        denomination: Some(Box::new(badge)),
    }
}

fn account() -> PackageMetadata {
    let auth_cell = Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: SlotRef::Fixed(AUTH),
        material: vec![],
    };
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "authorize".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Proves {
                guard: None,
                claim: Expr::SelfAddr,
            }],
            ..MethodSignature::default()
        },
    );
    // Reads a stored rule, and moves the badge: the shape whose evidence
    // holds both a sign-in and an earned proof at once.
    package.methods.insert(
        "spend".into(),
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![
                Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(auth_cell.clone()),
                    mode: ModeExpr::Read,
                    denomination: None,
                },
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Stored { cell: auth_cell }),
                },
                moves_the_badge(),
            ],
            ..MethodSignature::default()
        },
    );
    package
}

#[test]
fn a_rule_reading_call_still_presents_what_its_movements_earned() {
    let chain = Principals::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    b.call(ALICE, "spend", ())
        .expect("the sign-in composes")
        .none()
        .expect("spend produces nothing");
    let graph = b.build().expect("the graph builds");
    assert_eq!(graph.nodes.len(), 2, "one sign-in, then the call");
    assert_eq!(graph.nodes[0].method, "authorize");
    assert_eq!(
        graph.nodes[1].evidence,
        [EvidenceRef::IntentSignature, EvidenceRef::Node(0)].into(),
        "the signature answers the stored rule; the sign-in answers the badge"
    );
}
