//! The minimal stdlib's authored effect signatures: the fungible account,
//! the constant-product pool, the order book, the bucket splitter, and the
//! stake pool.
//!
//! These are the signatures the corpus guests execute under. They are
//! authored, not compiler-inferred — the inference backend is a later
//! phase; what is final here is the signature format they are written in.

use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::metadata::{AbiParam, MethodSignature, PackageMetadata, ParamType};
use crate::types::{RoleId, Value};

/// A fungible balance cell under its holder.
pub const VAULT: RoleId = RoleId(1);
/// The guaranteed-delivery fallback cell beside a vault.
pub const CLAIMS: RoleId = RoleId(2);
/// A creation-fixed configuration leaf.
pub const CONFIG: RoleId = RoleId(3);
/// The order book's ask-side ordered collection.
pub const ASKS: RoleId = RoleId(4);
/// An account's entropy leaf: the transaction draw a stamp records.
pub const ENTROPY: RoleId = RoleId(5);
/// A stake pool's total awaiting release to the delegators who returned
/// their units.
pub const UNBONDING: RoleId = RoleId(6);

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;

fn self_child(role: RoleId, material: Vec<Expr>) -> Expr {
    Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        role,
        material,
    }
}

/// The fungible account.
///
/// `withdraw(resource, amount)`: reserve `amount` on the caller's vault
/// for `resource`. `deposit(bucket)`: delta on the recipient's vault plus
/// the claims-area fallback cell, both keyed by the bucket's resource.
/// `stamp-entropy()`: an exclusive write of the transaction's randomness
/// draw into the account's entropy leaf.
///
/// No method reads another account's balance. A precondition on mutable
/// state is a fresh [`ModeExpr::Read`], which makes the read's owner a
/// participant — the account surface has no shape that wants one yet.
#[must_use]
pub fn account_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            params: vec![ParamType::Address, ParamType::U128],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
            outputs: vec![Expr::Arg(0)],
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
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![],
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
    methods.methods.insert(
        "stamp-entropy".into(),
        MethodSignature {
            params: vec![],
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(ENTROPY, vec![])),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    // Index order is the contract: the guest emits 0 and 1, and these are
    // what those indexes mean.
    methods.events = vec!["withdrawn".into(), "deposited".into()];
    methods
}

/// The stake pool.
///
/// `stake(funds)`: the delegation lands in the pool's vault for the
/// resource it is denominated in, and the call returns a bucket of the
/// pool's own stake-unit resource — the delegator's position, held as an
/// ordinary fungible balance in their own account rather than as a record
/// only the pool can read. `unstake(units)`: the returned units are
/// consumed and the pool's unbonding total grows by what they represent.
///
/// Both are `delta`, and that is the whole contention story: a delegation
/// commutes with every other delegation, so a pool's popularity costs its
/// shard throughput and never serialization. Nothing reads a pool
/// aggregate. The beacon accumulates per-pool totals from the events these
/// methods emit and spends them on its own capacity tests, so a total kept
/// here would be a second copy of a number consensus already holds, on a
/// cell every delegator would have to take a turn on.
///
/// Two creation-fixed fields configure an instance: the resource it stakes
/// and the resource it issues. There is deliberately no third naming the
/// pool, because a pool that named itself could name a different one: the
/// kernel stamps an event's emitter, so the instance is the subject and
/// nothing about it is the guest's to choose.
#[must_use]
pub fn staking_metadata() -> PackageMetadata {
    /// The staked resource — what a delegation is denominated in.
    const STAKED_RESOURCE: u32 = 0;
    /// The resource this pool issues against delegations.
    const UNIT_RESOURCE: u32 = 1;

    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "stake".into(),
        MethodSignature {
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![Expr::Config(UNIT_RESOURCE)],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(STAKED_RESOURCE)])),
                mode: ModeExpr::Delta,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "unstake".into(),
        MethodSignature {
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(
                    UNBONDING,
                    vec![Expr::Config(STAKED_RESOURCE)],
                )),
                mode: ModeExpr::Delta,
            }],
            calls: vec![],
        },
    );
    // Index order is the contract: the guest emits 0 and 1, and the
    // beacon's witness lift resolves exactly these two against this
    // package's metadata.
    methods.events = vec!["staked".into(), "unstaked".into()];
    methods
}

/// `swap(input, min_out)`: a locked read of the pool's
/// configuration and exclusive writes on its two reserve leaves, named by
/// the creation-fixed resource pair.
#[must_use]
pub fn amm_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "swap".into(),
        MethodSignature {
            params: vec![ParamType::Bucket, ParamType::U128],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Handle(2),
                AbiParam::Bucket(0),
                AbiParam::Derived(Expr::Arg(1)),
            ],
            outputs: vec![Expr::Config(1)],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(CONFIG, vec![])),
                    mode: ModeExpr::Locked,
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

/// The order book.
///
/// `place-ask(price, funds)`: insert at the computed entry key — the price
/// packed over a fresh sequence id — and escrow the maker's funds into the
/// book vault. `fill-asks(from, to, payment)`: an exclusive write over the
/// declared price interval with an entry cap, base outflow from the book's
/// escrow vault, quote inflow to it.
#[must_use]
pub fn book_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "place-ask".into(),
        MethodSignature {
            params: vec![ParamType::U64, ParamType::Bucket],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::FreshId { slot: 0 }),
                AbiParam::Bucket(1),
            ],
            outputs: vec![],
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
        "fill-asks".into(),
        MethodSignature {
            params: vec![ParamType::U64, ParamType::U64, ParamType::Bucket],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Handle(2),
                AbiParam::Bucket(2),
            ],
            outputs: vec![Expr::Config(0), Expr::ResourceOf(Box::new(Expr::Arg(2)))],
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

/// `take(bucket, amount)`: split a bucket, producing the taken part and
/// the rest — two output edges of the same resource, both of which
/// linearity forces the manifest to route.
#[must_use]
pub fn splitter_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "take".into(),
        MethodSignature {
            params: vec![ParamType::Bucket, ParamType::U128],
            abi: vec![AbiParam::Bucket(0), AbiParam::Derived(Expr::Arg(1))],
            outputs: vec![
                Expr::ResourceOf(Box::new(Expr::Arg(0))),
                Expr::ResourceOf(Box::new(Expr::Arg(0))),
            ],
            ..MethodSignature::default()
        },
    );
    methods
}
