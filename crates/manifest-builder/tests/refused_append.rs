//! A refused call leaves the builder exactly as it was.
//!
//! The builder walks a call's gate and its movements before appending
//! anything, and a refusal discovered after an append would leave the
//! node in the graph — admission-valid, signed if the author recovers
//! and builds. So every refusal a call can reach is judged before
//! anything is appended, and these pin it: after a refusal, the graph
//! builds to exactly what it held before the call.

use std::sync::Arc;

use hyperscale_hbor::{Capped, Name};
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    ChainRecords, Claim, Clause, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ResourceGrants, ResourceKind,
    ResourceMeta, RuleBytes, RuleExpr, SlotRef, StoredRule, TargetExpr, TestHasher, Value,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_types::{CallTarget, Moves, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
/// A badge whose deposit rule asks for Alice, so a call moving it earns
/// a claim the builder can mint a sign-in for.
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

/// The moving clause `grab` and `stash` declare: the caller's own vault
/// of the badge, either direction.
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
    let mut package = PackageMetadata::default();
    package.methods.insert(
        Name::declared("authorize"),
        MethodSignature {
            declines: true,
            effects: vec![Clause::Proves {
                guard: None,
                claim: Expr::SelfAddr,
            }],
            ..MethodSignature::default()
        },
    );
    // Guarded on another party, and it moves the badge — so the walk
    // that answers a gate has both a claim to read and a movement to
    // price before it gives up.
    package.methods.insert(
        Name::declared("grab"),
        MethodSignature {
            declines: true,
            effects: vec![
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::claim(Expr::Literal(Value::Address(BOB.address()))),
                },
                moves_the_badge(),
            ],
            ..MethodSignature::default()
        },
    );
    // A minting method that also produces an edge: a proof of it cannot
    // be minted, because the output would dangle.
    package.methods.insert(
        Name::declared("stash"),
        MethodSignature {
            declines: true,
            effects: vec![
                Clause::Proves {
                    guard: None,
                    claim: Expr::SelfAddr,
                },
                moves_the_badge(),
            ],
            outputs: vec![Expr::Literal(Value::Address(BADGE.address()))],
            ..MethodSignature::default()
        },
    );
    package
}

/// A gate naming another party, with nothing presented and no scope: the
/// claim is named in the refusal and the graph is left exactly as it was.
///
/// An intent's signature names the account it acts as and no other, and
/// nothing it can compose speaks for a stranger — so the gate is read
/// whole, nothing answers it, and the refusal lands before the call is
/// appended.
#[test]
fn a_guarded_call_naming_another_party_appends_nothing() {
    let chain = Principals::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let refused = b
        .call(ALICE, "grab", ())
        .expect_err("guarded on Bob, and nothing was presented");
    assert!(matches!(refused, TypedError::UncoveredGate { .. }));
    let graph = b.build().expect("nothing dangles after a refusal");
    assert_eq!(graph.nodes.len(), 0, "the graph is exactly as it was");
}

#[test]
fn a_minting_call_whose_outputs_would_dangle_appends_nothing() {
    let chain = Principals::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let refused = b
        .call_proving(ALICE, "stash", ())
        .expect_err("a proof of a producing method would dangle its edge");
    assert!(matches!(refused, TypedError::OutputArity { .. }));
    let graph = b.build().expect("nothing dangles after a refusal");
    assert_eq!(graph.nodes.len(), 0, "the graph is exactly as it was");
}
