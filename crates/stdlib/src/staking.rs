//! The stake pool: delegation for stake units, the validators a
//! pool operates, and the one governance vote it holds.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    RoleId, Totality, Value, package_role, self_child,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

/// A stake pool's total awaiting release to the delegators who returned
/// their units.
pub const UNBONDING: RoleId = package_role(0);
/// A stake pool's record of one validator it operates.
pub const VALIDATORS: RoleId = package_role(1);
/// A stake pool's one active network-parameter vote.
pub const VOTE: RoleId = package_role(2);

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
/// One creation-fixed field configures an instance: the resource it
/// stakes. The resource it *issues* is not among them — it derives from
/// the pool, which is what keeps the configuration writable at all,
/// since a pool's address commits its configuration and a configured
/// field naming a value derived from that address could not be written
/// down. Neither is the operator: the operator surface admits whoever
/// presents the pool's owner badge, itself derived from the pool, so
/// selling the pool is transferring the badge rather than rewriting a
/// configuration no instance can rewrite. There is deliberately no field
/// naming the pool either, because a pool that named itself could name a
/// different one: the kernel stamps an event's emitter, so the instance
/// is the subject and nothing about it is the guest's to choose.
///
/// `stake` and `unstake` are public, and that is not an oversight. A pool
/// instance is owned by nobody; the authority behind a delegation is the
/// funds the caller supplies, and those were gated upstream at the
/// withdrawal that produced them. The operator surface supplies no funds,
/// so it has no such authority to inherit and names the one its
/// configuration carries.
#[must_use]
pub fn metadata() -> PackageMetadata {
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

/// The material separating a pool's owner badge from the unit it issues.
pub const OWNER_BADGE: &[u8] = b"owner-badge";

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

/// The pool's owner badge — the identity its operator surface admits.
///
/// Derived like the unit and separated from it by material, and for the
/// same reason it is not configured: a configured badge would cycle
/// through the pool's own address. Holding it is operating the pool;
/// `present-badge` is how the holder says so.
fn owner_badge() -> Expr {
    Expr::SelfResource {
        material: vec![Expr::Literal(Value::Bytes(OWNER_BADGE.to_vec()))],
    }
}

/// `stake` and `unstake`: what anyone holding funds may do to a pool.
fn delegation_methods(methods: &mut PackageMetadata) {
    methods.methods.insert(
        "stake".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(owner_badge()),
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(owner_badge()),
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(owner_badge()),
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(owner_badge()),
            mints: None,
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
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(owner_badge()),
            mints: None,
            params: vec![],
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![],
            effects: vote(),
            calls: vec![],
        },
    );
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Delegate `funds` to `pool`, receiving the pool's own stake units —
/// an edge typed by the pool rather than by what was staked.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `stake`.
pub fn stake(
    builder: &mut TypedBuilder<'_>,
    pool: ComponentAddr,
    funds: impl BucketArg,
) -> Result<Bucket, TypedError> {
    builder.call(pool, "stake", (funds,))?.one()
}

/// Return `units` to `pool`, growing what it owes on release.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `unstake`.
pub fn unstake(
    builder: &mut TypedBuilder<'_>,
    pool: ComponentAddr,
    units: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(pool, "unstake", (units,))?.none()
}

/// Record `validator` on `pool`'s own leaf for it, under the key it
/// will sign with and the proof it holds the key.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `register-validator`.
pub fn register_validator(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
    key: Vec<u8>,
    possession_proof: Vec<u8>,
) -> Result<(), TypedError> {
    builder
        .call_as(
            operator,
            pool,
            "register-validator",
            (validator, key, possession_proof),
        )?
        .none()
}

/// Retire `validator` from `pool`'s operating set.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `deactivate-validator`.
pub fn deactivate_validator(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "deactivate-validator", (validator,))?
        .none()
}

/// Return `validator` to service.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `unjail`.
pub fn unjail(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "unjail", (validator,))?
        .none()
}

/// Replace `pool`'s single network-parameter vote with this one. The
/// parameters travel as themselves, so a malformed vote fails its
/// transaction rather than being counted and discarded.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `cast-param-vote`.
pub fn cast_param_vote(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    split_bytes: u64,
    impound_epochs: u64,
    activate_at: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(
            operator,
            pool,
            "cast-param-vote",
            (split_bytes, impound_epochs, activate_at),
        )?
        .none()
}

/// Empty `pool`'s vote leaf, so it backs nothing.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `clear-param-vote`.
pub fn clear_param_vote(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "clear-param-vote", ())?
        .none()
}
