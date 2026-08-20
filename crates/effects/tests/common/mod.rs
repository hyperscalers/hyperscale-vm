//! Shared fixtures: the packages the shape tests route against, and the
//! instance world they resolve in.
#![allow(dead_code, unused_imports)] // shared between test binaries; each uses a subset

pub use hyperscale_vm_effects::vocabulary::{AUTH, CLAIMS, CONFIG, VAULT};
use hyperscale_vm_effects::{
    Clause, Expr, Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestHash, MetadataCache,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ParamType, PrefixShardResolver,
    ShardId, ShardResolver, SlotId, TargetExpr, TestHasher, Totality, Value, child_key,
};
pub use hyperscale_vm_fixtures::book::{ASKS, FILL_CAP};
pub use hyperscale_vm_fixtures::{amm, book, splitter};
pub use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    Address, ComponentAddr, Effect, EffectSet, Presence, PrincipalAddr, ResourceAddr, SubstateKey,
};

/// Accounts are principals: their class is what resolves them to the
/// protocol's account blueprint, so a fixture names one without anything
/// having to be registered for it.
pub const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
pub const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
pub const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
pub const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);
pub const BASE: ResourceAddr = ResourceAddr::new([0xE3; 31]);
pub const QUOTE: ResourceAddr = ResourceAddr::new([0xE4; 31]);

fn self_child(slot: SlotId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot,
        material,
    }
}

#[must_use]
pub fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// A stand-in transaction identity for tests that route hand-built
/// manifests without going through admission.
#[must_use]
pub const fn identity() -> ManifestHash {
    ManifestHash(Hash32([0x1D; 32]))
}

/// The published world every shape test routes against.
#[must_use]
pub fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish_unchecked(pkg("account"), account::metadata());
    cache.publish_unchecked(pkg("amm"), amm::metadata());
    cache.publish_unchecked(pkg("book"), book::metadata());

    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, pool_meta());
    instances.create(&TestHasher, book_meta());
    (cache, instances)
}

/// The constant-product pool's record, and the address it derives.
#[must_use]
pub fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("amm"),
        // The pair, then the fee in basis points: a swap's guest reads
        // the fee as an evaluated slot, so it is configuration.
        config: vec![
            Value::Address(RES_X.address()),
            Value::Address(RES_Y.address()),
            Value::U128(30 * (1_000_000_000_000_000_000 / 10_000)),
        ],
        salt: Hash32([2; 32]),
    }
}

/// The pool instance every shape test names.
#[must_use]
pub fn pool() -> ComponentAddr {
    pool_meta().address(&TestHasher)
}

/// The order book's record.
#[must_use]
pub fn book_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("book"),
        config: vec![
            Value::Address(BASE.address()),
            Value::Address(QUOTE.address()),
        ],
        salt: Hash32([3; 32]),
    }
}

/// The book instance every shape test names.
#[must_use]
pub fn book() -> ComponentAddr {
    book_meta().address(&TestHasher)
}

#[must_use]
pub const fn resolver() -> PrefixShardResolver {
    PrefixShardResolver { bits: 8 }
}

/// Where [`resolver`] puts an address — asked rather than restated, so a
/// change to the resolver's own identities cannot leave the expectation
/// behind.
#[must_use]
pub fn shard_of(address: impl Into<Address>) -> ShardId {
    resolver().shard_of(address.into())
}

#[must_use]
pub fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

#[must_use]
pub fn claims(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        CLAIMS,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

#[must_use]
pub fn config_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
}

/// An account's stored-authority cell — what its sign-in reads.
#[must_use]
pub fn auth(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, AUTH, &[])
}

/// Build an exact expected set; panics only on reserve overflow, which the
/// fixtures never declare.
#[must_use]
pub fn effect_set(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    set
}

/// Extra methods for the over-approximation case: `withdraw_wide` declares
/// the exact withdraw effect plus a superset the method never touches.
#[must_use]
pub fn wide_account_metadata() -> PackageMetadata {
    let mut methods = account::metadata();
    let mut effects = methods.methods["withdraw"].effects.clone();
    effects.push(Clause::Effect {
        guard: None,
        target: TargetExpr::Point(self_child(SlotId(99), vec![])),
        mode: ModeExpr::Write,
        denomination: None,
    });
    methods.methods.insert(
        "withdraw_wide".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Address, ParamType::U128],
            abi: Vec::new(),
            outputs: vec![Expr::Arg(0)],
            effects,
            ..MethodSignature::default()
        },
    );
    methods
}
