//! What a call's movements earn rides beside the intent's signature.
//!
//! A rule-reading method takes the intent's signature — whether the
//! keys still hold the account's authority is its shard's question.
//! But a resource the same call moves asks its own question, and the
//! answer is the proof presented for it. Dropping that reference would
//! leave the movement's claim unpresented, so the signature and the
//! earned proofs are one evidence set.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_vm_effects::vocabulary::{AUTH, VAULT};
use hyperscale_vm_effects::{
    ChainRecords, Claim, ClaimRef, Clause, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ResourceGrants, ResourceKind,
    ResourceMeta, RuleBytes, RuleExpr, RuleLeaf, SlotRef, StoredRule, TargetExpr, TestHasher,
    Totality, Value,
};
use hyperscale_vm_manifest_builder::TypedBuilder;
use hyperscale_vm_types::{CallTarget, Moves, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// A badge whose deposit rule asks for Alice, so a call moving it earns
/// a claim the intent's signature answers.
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
                config: Capped::empty(),
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
            material: Capped::empty(),
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

/// A call reading its target's stored rule and moving a badge the
/// account's own claim governs answers both with the one signature, and
/// mints nothing to do it.
///
/// The two gates ask different questions — what the stored rule names,
/// and what the resource's entry demands of the mover — and both
/// answers are the account this intent acts as. No node proves that, so
/// the graph is the call alone.
#[test]
fn a_rule_reading_call_answers_both_gates_with_one_signature() {
    let chain = Principals::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    b.call(ALICE, "spend", ())
        .expect("the call composes")
        .none()
        .expect("spend produces nothing");
    let graph = b.build().expect("the graph builds");
    assert_eq!(graph.nodes.len(), 1, "the call alone");
    assert_eq!(
        graph.nodes[0].evidence,
        Capped::from_members([ClaimRef::Account(ALICE)]),
        "one signature answers the stored rule and the badge alike"
    );
}
