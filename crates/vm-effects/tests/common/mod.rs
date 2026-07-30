//! Shared fixtures: authored effect signatures for the account, AMM pool,
//! and order-book packages, and the instance world the shape tests route
//! against.
#![allow(dead_code)] // shared between test binaries; each uses a subset

use hyperscale_vm_effects::{
    Address, CallSite, Clause, Effect, EffectSet, Expr, Hasher, InstanceMeta, InstanceRegistry,
    MetadataCache, MethodSignature, ModeExpr, PackageHash, PackageMetadata, PrefixShardResolver,
    RoleId, ShardId, SubstateKey, TargetExpr, TestHasher, Value, WindowExpr, child_key,
};

/// A fungible balance cell under its holder.
pub const VAULT: RoleId = RoleId(1);
/// The guaranteed-delivery fallback cell beside a vault.
pub const CLAIMS: RoleId = RoleId(2);
/// A creation-fixed configuration leaf.
pub const CONFIG: RoleId = RoleId(3);
/// The order book's ask-side ordered collection.
pub const ASKS: RoleId = RoleId(4);

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;

pub const ALICE: Address = Address([0x10; 16]);
pub const BOB: Address = Address([0x20; 16]);
pub const POOL: Address = Address([0x30; 16]);
pub const BOOK: Address = Address([0x40; 16]);
pub const RES_X: Address = Address([0xE1; 16]);
pub const RES_Y: Address = Address([0xE2; 16]);
pub const BASE: Address = Address([0xE3; 16]);
pub const QUOTE: Address = Address([0xE4; 16]);

#[must_use]
pub fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn self_child(role: RoleId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        role,
        material,
    }
}

/// `withdraw(resource, amount)`: reserve `amount` on the caller's vault for
/// `resource`. `deposit(bucket)`: delta on the recipient's vault plus the
/// claims-area fallback cell, both keyed by the bucket's resource.
#[must_use]
pub fn account_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(VAULT, vec![Expr::Arg(0)])),
                mode: ModeExpr::Reserve(Expr::Arg(1)),
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "deposit".into(),
        MethodSignature {
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(0)))],
                    )),
                    mode: ModeExpr::Delta,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        CLAIMS,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(0)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
    methods
}

/// `swap(input, min_out)`: an unbounded snapshot of the pool's locked
/// configuration and exclusive writes on its two reserve leaves, named by
/// the creation-fixed resource pair.
#[must_use]
pub fn amm_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "swap".into(),
        MethodSignature {
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(CONFIG, vec![])),
                    mode: ModeExpr::Snapshot(WindowExpr::Unbounded),
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(0)])),
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(1)])),
                    mode: ModeExpr::Write,
                },
            ],
            calls: vec![],
        },
    );
    methods
}

/// `place_ask(price, funds)`: insert at the computed entry key — the price
/// packed over a fresh sequence id — and escrow the maker's funds into the
/// book vault. `fill_asks(from, to, payment)`: an exclusive write over the
/// declared price interval with an entry cap, base outflow from the book's
/// escrow vault, quote inflow to it.
#[must_use]
pub fn book_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "place_ask".into(),
        MethodSignature {
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: ASKS,
                        order: Expr::Pack {
                            hi: Box::new(Expr::Arg(0)),
                            lo: Box::new(Expr::FreshId { slot: 0 }),
                        },
                    },
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(1)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "fill_asks".into(),
        MethodSignature {
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: ASKS,
                        lo: Expr::Pack {
                            hi: Box::new(Expr::Arg(0)),
                            lo: Box::new(Expr::Literal(Value::U64(0))),
                        },
                        hi: Expr::Pack {
                            hi: Box::new(Expr::Arg(1)),
                            lo: Box::new(Expr::Literal(Value::U64(u64::MAX))),
                        },
                        cap: FILL_CAP,
                    },
                    mode: ModeExpr::Write,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(0)])),
                    mode: ModeExpr::Delta,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(2)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
    methods
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

#[must_use]
pub fn shard_of(address: Address) -> ShardId {
    ShardId(u16::from(address.0[0]))
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
