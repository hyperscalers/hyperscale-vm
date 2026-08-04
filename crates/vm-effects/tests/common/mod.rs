//! Shared fixtures: authored effect signatures for the account, AMM pool,
//! and order-book packages, and the instance world the shape tests route
//! against.
#![allow(dead_code, unused_imports)] // shared between test binaries; each uses a subset

pub use hyperscale_vm_effects::stdlib::{
    ASKS, CLAIMS, CONFIG, FILL_CAP, VAULT, account_metadata, amm_metadata, book_metadata,
    splitter_metadata,
};
use hyperscale_vm_effects::{
    Address, CallSite, Clause, Effect, EffectSet, Expr, Hash32, Hasher, InstanceMeta,
    InstanceRegistry, ManifestHash, MetadataCache, MethodSignature, ModeExpr, PackageHash,
    PackageMetadata, ParamType, PrefixShardResolver, RoleId, ShardId, ShardResolver, SubstateKey,
    TargetExpr, TestHasher, Value, child_key,
};

pub const ALICE: Address = Address([0x10; 16]);
pub const BOB: Address = Address([0x20; 16]);
pub const POOL: Address = Address([0x30; 16]);
pub const BOOK: Address = Address([0x40; 16]);
pub const RES_X: Address = Address([0xE1; 16]);
pub const RES_Y: Address = Address([0xE2; 16]);
pub const BASE: Address = Address([0xE3; 16]);
pub const QUOTE: Address = Address([0xE4; 16]);

fn self_child(role: RoleId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        role,
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
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("book"), book_metadata());

    let mut instances = InstanceRegistry::new();
    for account in [ALICE, BOB] {
        instances.register(
            account,
            InstanceMeta {
                package: pkg("account"),
                config: vec![],
            },
        );
    }
    instances.register(
        POOL,
        InstanceMeta {
            package: pkg("amm"),
            config: vec![Value::Address(RES_X), Value::Address(RES_Y)],
        },
    );
    instances.register(
        BOOK,
        InstanceMeta {
            package: pkg("book"),
            config: vec![Value::Address(BASE), Value::Address(QUOTE)],
        },
    );
    (cache, instances)
}

#[must_use]
pub const fn resolver() -> PrefixShardResolver {
    PrefixShardResolver { bits: 8 }
}

/// Where [`resolver`] puts an address — asked rather than restated, so a
/// change to the resolver's own identities cannot leave the expectation
/// behind.
#[must_use]
pub fn shard_of(address: Address) -> ShardId {
    resolver().shard_of(address)
}

#[must_use]
pub fn vault(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

#[must_use]
pub fn claims(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        CLAIMS,
        &[Value::Address(resource).canonical_bytes()],
    )
}

#[must_use]
pub fn config_leaf(owner: Address) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
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
    let mut methods = account_metadata();
    let mut effects = methods.methods["withdraw"].effects.clone();
    effects.push(Clause::Effect {
        target: TargetExpr::Point(self_child(RoleId(99), vec![])),
        mode: ModeExpr::Write,
    });
    methods.methods.insert(
        "withdraw_wide".into(),
        MethodSignature {
            params: vec![ParamType::Address, ParamType::U128],
            abi: Vec::new(),
            outputs: vec![Expr::Arg(0)],
            effects,
            calls: vec![],
        },
    );
    methods
}

/// A router package whose single method forwards to an argument-named
/// account — the call-site shape the aggregator pattern uses.
#[must_use]
pub fn router_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "forward".into(),
        MethodSignature {
            params: vec![],
            abi: Vec::new(),
            outputs: vec![],
            effects: vec![],
            calls: vec![CallSite {
                target: Expr::Arg(0),
                method: "deposit".into(),
                args: vec![Expr::Arg(1)],
            }],
        },
    );
    methods
}
