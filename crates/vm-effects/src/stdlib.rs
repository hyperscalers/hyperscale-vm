//! The minimal stdlib's authored effect signatures: the fungible account,
//! the constant-product pool, the order book, and the bucket splitter.
//!
//! These are the signatures the corpus guests execute under. They are
//! authored, not compiler-inferred — the inference backend is a later
//! phase; what is final here is the signature format they are written in.

use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr, WindowExpr};
use crate::metadata::{MethodSignature, PackageMetadata, ParamType};
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
/// `assert-balance(resource, min, window)`: a bounded-window snapshot of
/// the vault for `resource` — refuses unless the pinned balance covers
/// `min`, touching nothing. `stamp-entropy()`: an exclusive write of the
/// transaction's randomness draw into the account's entropy leaf.
#[must_use]
pub fn account_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            params: vec![ParamType::Address, ParamType::U128],
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
        "assert-balance".into(),
        MethodSignature {
            params: vec![ParamType::Address, ParamType::U128, ParamType::U64],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(VAULT, vec![Expr::Arg(0)])),
                mode: ModeExpr::Snapshot(WindowExpr::Bounded(Expr::Arg(2))),
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "stamp-entropy".into(),
        MethodSignature {
            params: vec![],
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

/// `swap(input, min_out)`: an unbounded snapshot of the pool's locked
/// configuration and exclusive writes on its two reserve leaves, named by
/// the creation-fixed resource pair.
#[must_use]
pub fn amm_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "swap".into(),
        MethodSignature {
            params: vec![ParamType::Bucket, ParamType::U128],
            outputs: vec![Expr::Config(1)],
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

/// The order book.
///
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
            params: vec![ParamType::U64, ParamType::Bucket],
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
        "fill_asks".into(),
        MethodSignature {
            params: vec![ParamType::U64, ParamType::U64, ParamType::Bucket],
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
            outputs: vec![
                Expr::ResourceOf(Box::new(Expr::Arg(0))),
                Expr::ResourceOf(Box::new(Expr::Arg(0))),
            ],
            ..MethodSignature::default()
        },
    );
    methods
}
