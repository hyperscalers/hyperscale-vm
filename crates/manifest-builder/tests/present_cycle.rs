//! A composer resolving metadata from an untrusted chain view must not
//! be driven into unbounded recursion by it.
//!
//! Presenting a claim mints a proof through the account blueprint, and
//! that mint earns claims of its own; the real account's minting methods
//! earn nothing, so the recursion terminates. Nothing in the type says
//! it must. A hostile account whose `authorize` earns the very claim it
//! is minting a proof for would recurse without end — and the metadata a
//! client resolves is the chain's, not its own.

use std::sync::Arc;

use hyperscale_vm_effects::{
    ChainRecords, Claim, Clause, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ResourceGrants, ResourceKind,
    ResourceMeta, RuleBytes, StoredRule, TargetExpr, TestHasher, Value,
};
use hyperscale_vm_manifest_builder::TypedBuilder;
use hyperscale_vm_types::{CallTarget, Moves, PrincipalAddr, ResourceAddr};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// The badge `authorize` is made to move, whose deposit rule asks for
/// Alice — the claim minting `authorize` starts from.
const BADGE: ResourceAddr = ResourceAddr::new([0xBA; 31]);

/// A chain that serves principals a hostile account and answers for one
/// self-referential badge.
struct HostileChain {
    principal: Arc<InstanceMeta>,
    account_hash: PackageHash,
    account: Arc<PackageMetadata>,
}

impl HostileChain {
    fn new() -> Self {
        let account_hash = PackageHash(TestHasher.hash(b"package", &[b"hostile-account"]));
        Self {
            principal: Arc::new(InstanceMeta {
                package: account_hash,
                config: Vec::new(),
                salt: Hash32([0; 32]),
            }),
            account_hash,
            account: Arc::new(hostile_account()),
        }
    }
}

impl ChainRecords for HostileChain {
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
        (resource == BADGE).then(badge_record)
    }
}

/// The badge's record: a deposit rule asking whoever moves it to be
/// Alice, so `authorize` — minted for Alice's own claim — earns that
/// same claim off the movement it declares.
fn badge_record() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    let asks_for_alice =
        RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(ALICE))).expect("a rule encodes");
    rules.set(GrantedBehaviour::Deposit, asks_for_alice);
    ResourceMeta {
        namespace: ALICE.address(),
        kind: ResourceKind::Fungible,
        material: Vec::new(),
        rules,
    }
}

/// An `authorize` that mints a proof and, on the way, declares a movement
/// of `BADGE` — so its own earned claim is the one it is minting for.
fn hostile_account() -> PackageMetadata {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "authorize".into(),
        MethodSignature {
            effects: vec![
                Clause::Mints {
                    guard: None,
                    claim: Expr::SelfAddr,
                },
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(Expr::SelfAddr),
                    mode: ModeExpr::Delta { moves: Moves::Both },
                    denomination: Some(Box::new(Expr::Literal(Value::Address(BADGE.address())))),
                    reach: None,
                },
            ],
            ..MethodSignature::default()
        },
    );
    package
}

/// The composer terminates rather than overflowing the stack: the claim
/// being minted is left to the ancestor already minting it, and the
/// graph it hands back is one admission decides on its own terms.
#[test]
fn a_self_earning_account_does_not_recurse_without_end() {
    let chain = HostileChain::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    // Without the cycle break this call recurses until the stack is
    // exhausted; the assertion is that it returns at all.
    let _ = b.call_minting(ALICE, "authorize", ());
}
