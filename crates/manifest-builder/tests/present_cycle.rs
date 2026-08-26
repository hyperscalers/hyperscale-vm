//! A composer resolving metadata from an untrusted chain view must not
//! be driven into unbounded recursion by it.
//!
//! Presenting a claim mints a proof through the account blueprint, and
//! that mint earns claims of its own; the real account's minting methods
//! earn nothing, so the recursion terminates. Nothing in the type says
//! it must. A hostile account whose `authorize` earns the very claim it
//! is minting a proof for would recurse without end — and the metadata a
//! client resolves is the chain's, not its own.
//!
//! Two shapes reach that, and they are stopped by different things. A
//! claim that comes back around is caught by the memo of what is being
//! minted; a chain of distinct claims never repeats and is caught only
//! by the depth the composer will chain to.

use std::sync::Arc;

use hyperscale_vm_effects::{
    ChainRecords, Claim, Clause, Expr, GrantedBehaviour, Hash32, Hasher, InstanceMeta,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ParamType, ResourceGrants,
    ResourceKind, ResourceMeta, RuleBytes, StoredRule, TargetExpr, TestHasher, Value,
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
                Clause::Proves {
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
    let _ = b.call_proving(ALICE, "authorize", ());
}

/// A chain view answering for every resource, each record naming a badge
/// no record has named before.
///
/// `present-badge` moves the badge it is handed, so what it earns is
/// whatever that badge's record demands of a deposit — and this one
/// demands a claim on the next badge, forever. No claim repeats, so the
/// memo never fires.
struct EndlessBadges {
    principal: Arc<InstanceMeta>,
    account_hash: PackageHash,
    account: Arc<PackageMetadata>,
}

impl EndlessBadges {
    fn new() -> Self {
        let account_hash = PackageHash(TestHasher.hash(b"package", &[b"endless-badges"]));
        Self {
            principal: Arc::new(InstanceMeta {
                package: account_hash,
                config: Vec::new(),
                salt: Hash32([0; 32]),
            }),
            account_hash,
            account: Arc::new(chaining_account()),
        }
    }
}

/// The badge after this one: distinct from every badge before it, and
/// answerable by the same record, so the walk has somewhere to go for as
/// long as it keeps going.
fn next_badge(badge: ResourceAddr) -> ResourceAddr {
    // The body counted through as one wide integer, so no two badges
    // this walk reaches are ever the same address.
    let mut body = badge.address().body();
    for byte in &mut body {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    ResourceAddr::new(body)
}

impl ChainRecords for EndlessBadges {
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
        let asks_for_the_next =
            RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(next_badge(resource))))
                .expect("a rule encodes");
        rules.set(GrantedBehaviour::Deposit, asks_for_the_next);
        Some(ResourceMeta {
            namespace: ALICE.address(),
            kind: ResourceKind::Fungible,
            material: Vec::new(),
            rules,
        })
    }
}

/// A `present-badge` that moves the badge it is handed, so each proof it
/// mints earns the claim the next badge's record asks for.
fn chaining_account() -> PackageMetadata {
    let mut package = PackageMetadata::default();
    package.methods.insert(
        "present-badge".into(),
        MethodSignature {
            params: vec![ParamType::Address],
            effects: vec![
                Clause::Proves {
                    guard: None,
                    claim: Expr::SelfAddr,
                },
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(Expr::SelfAddr),
                    mode: ModeExpr::Delta { moves: Moves::Both },
                    denomination: Some(Box::new(Expr::Arg(0))),
                    reach: None,
                },
            ],
            ..MethodSignature::default()
        },
    );
    package
}

/// A chain of claims that never repeats is bounded by the depth the
/// composer chains to, not by the memo: the walk stops, and what it
/// composed is the four proofs it will chain plus the call that wanted
/// the first of them.
#[test]
fn an_endless_chain_of_distinct_claims_stops_at_the_depth_bound() {
    let chain = EndlessBadges::new();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let first = ResourceAddr::new([0xB0; 31]);
    // Without the bound this recurses until the stack is exhausted: every
    // claim is a fresh badge, so nothing the memo holds is ever seen
    // twice.
    b.call(ALICE, "present-badge", (first,))
        .expect("the call types")
        .none()
        .expect("present-badge produces no edges");
    let graph = b.build().expect("a graph with nothing left unconsumed");
    assert_eq!(graph.nodes.len(), 5);
}
