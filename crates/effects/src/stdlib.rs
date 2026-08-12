//! The minimal stdlib's authored effect signatures: the fungible account,
//! the constant-product pool, the order book, the bucket splitter, and the
//! stake pool.
//!
//! These are the signatures the corpus guests execute under. They are
//! authored, not compiler-inferred — the inference backend is a later
//! phase; what is final here is the signature format they are written in.

use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::metadata::{AbiParam, Accessibility, MethodSignature, PackageMetadata, ParamType};
use crate::types::{NativeRole, RoleId, Value};

/// The native fee and transfer resource.
pub const XRD: NativeRole = NativeRole(1);
/// The publisher the protocol's own packages sit under.
pub const GENESIS_PUBLISHER: NativeRole = NativeRole(2);

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
/// A stake pool's record of one validator it operates.
pub const VALIDATORS: RoleId = RoleId(7);
/// A stake pool's one active network-parameter vote.
pub const VOTE: RoleId = RoleId(8);

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
/// Spending and writing require the account's own authority; being paid
/// does not. Anyone may credit you, and a transfer therefore still
/// composes under the sender's single signature — the recipient is not
/// asked for one, because nothing about a deposit is theirs to refuse.
/// The stamp is gated for the same reason the withdrawal is, though it
/// moves nothing: it writes a leaf under the target's prefix, and every
/// later method that does the same belongs on this side of the split.
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
            accessibility: Accessibility::Guarded(Expr::SelfAddr),
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
            accessibility: Accessibility::Public,
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
            accessibility: Accessibility::Guarded(Expr::SelfAddr),
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
/// The operator surface — `register-validator`, `deactivate-validator`,
/// `unjail` — is the pool speaking about validators rather than about
/// stake, and it has an actor a delegation does not. Each writes the
/// pool's own leaf for the validator it names, keyed by that validator, so
/// two operators of two validators never take turns and the pool's shard
/// is a participant in the tick that carries the fact. That participation
/// is the reason the leaf exists at all: an event is kept by the shard
/// owning its emitter, and a method declaring no access would leave the
/// pool's shard out of the transaction that emitted from it.
///
/// The governance surface — `cast-param-vote`, `clear-param-vote` — is
/// the same actor again, on the pool's single vote leaf. Its arguments
/// are the network parameters themselves rather than an opaque
/// encoding: the set is three numbers, so carrying them positionally
/// costs nothing and lets a malformed vote fail its transaction instead
/// of succeeding and being dropped where nobody sees it. It does weld
/// this package to the parameter set, which is the right coupling —
/// adding a governed parameter is a protocol change, and the package
/// that votes on them is versioned with them.
///
/// Two creation-fixed fields configure an instance: the resource it stakes
/// and the operator its validator surface admits. The resource it *issues*
/// is not among them — it derives from the pool, which is what keeps the
/// configuration writable at all, since a pool's address commits its
/// configuration and a configured field naming a value derived from that
/// address could not be written down. There is deliberately no field
/// naming the pool either, because a pool that named itself could name a
/// different one: the kernel stamps an event's emitter, so the instance is
/// the subject and nothing about it is the guest's to choose.
///
/// `stake` and `unstake` are public, and that is not an oversight. A pool
/// instance is owned by nobody; the authority behind a delegation is the
/// funds the caller supplies, and those were gated upstream at the
/// withdrawal that produced them. The operator surface supplies no funds,
/// so it has no such authority to inherit and names the one its
/// configuration carries.
#[must_use]
pub fn staking_metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    delegation_methods(&mut methods);
    validator_methods(&mut methods);
    governance_methods(&mut methods);
    // Index order is the contract: the guest emits these indexes, and the
    // beacon's witness lift resolves them against this package's metadata.
    methods.events = vec![
        "staked".into(),
        "unstaked".into(),
        "validator-registered".into(),
        "validator-deactivated".into(),
        "validator-unjailed".into(),
        "param-vote-cast".into(),
        "param-vote-cleared".into(),
    ];
    methods
}

/// The staked resource — what a delegation is denominated in.
const STAKED_RESOURCE: u32 = 0;
/// The principal whose signature the operator surface admits.
const OPERATOR: u32 = 1;

/// The resource this pool issues against delegations.
///
/// Derived from the pool rather than configured: the pool's address
/// commits its configuration, so a configured field naming a value
/// derived from that address would not be expressible.
const fn unit_resource() -> Expr {
    Expr::SelfResource {
        material: Vec::new(),
    }
}

/// `stake` and `unstake`: what anyone holding funds may do to a pool.
fn delegation_methods(methods: &mut PackageMetadata) {
    methods.methods.insert(
        "stake".into(),
        MethodSignature {
            accessibility: Accessibility::Public,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![unit_resource()],
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
            accessibility: Accessibility::Public,
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
}

/// The validator surface: each method names the validator it concerns and
/// writes that validator's own leaf, so the pool holds a record it can
/// read back — which is what lets a re-registration be refused here
/// rather than only where the beacon happens to refuse it.
fn validator_methods(methods: &mut PackageMetadata) {
    let validator = || {
        vec![Clause::Effect {
            target: TargetExpr::Point(self_child(VALIDATORS, vec![Expr::Arg(0)])),
            mode: ModeExpr::Write,
        }]
    };
    methods.methods.insert(
        "register-validator".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(Expr::Config(OPERATOR)),
            params: vec![ParamType::U64, ParamType::Bytes, ParamType::Bytes],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::Arg(1)),
                AbiParam::Derived(Expr::Arg(2)),
            ],
            outputs: vec![],
            effects: validator(),
            calls: vec![],
        },
    );
    methods.methods.insert(
        "deactivate-validator".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(Expr::Config(OPERATOR)),
            params: vec![ParamType::U64],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(0))],
            outputs: vec![],
            effects: validator(),
            calls: vec![],
        },
    );
    methods.methods.insert(
        "unjail".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(Expr::Config(OPERATOR)),
            params: vec![ParamType::U64],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(0))],
            outputs: vec![],
            effects: validator(),
            calls: vec![],
        },
    );
}

/// The governance surface: the pool's one vote, on one leaf. A pool holds
/// a single active vote and the network counts it once, so serializing a
/// pool's own votes against each other is the shape rather than a cost.
fn governance_methods(methods: &mut PackageMetadata) {
    let vote = || {
        vec![Clause::Effect {
            target: TargetExpr::Point(self_child(VOTE, vec![])),
            mode: ModeExpr::Write,
        }]
    };
    methods.methods.insert(
        "cast-param-vote".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(Expr::Config(OPERATOR)),
            params: vec![ParamType::U64, ParamType::U64, ParamType::U64],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::Arg(1)),
                AbiParam::Derived(Expr::Arg(2)),
            ],
            outputs: vec![],
            effects: vote(),
            calls: vec![],
        },
    );
    methods.methods.insert(
        "clear-param-vote".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(Expr::Config(OPERATOR)),
            params: vec![],
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![],
            effects: vote(),
            calls: vec![],
        },
    );
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
            accessibility: Accessibility::Public,
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
            accessibility: Accessibility::Public,
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
            accessibility: Accessibility::Public,
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
