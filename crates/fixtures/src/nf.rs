//! The non-fungible surface: an issuer that mints and burns, and the
//! holders whose instances are their holdings entries.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ConditionExpr, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::INSTANCE;
use hyperscale_vm_effects::{
    AbiParam, Expr, MethodSignature, PackageMetadata, ParamType, RuleExpr, Totality, Value,
    holdings_range,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};
use hyperscale_vm_types::{ComponentAddr, Denomination, Presence};

/// The mint's declaration: the instance-data write, and the one-way
/// door beside it. A mint creates; it never lands on an instance that
/// is already there. The fresh id makes that true in every ordinary
/// run, and the condition is what turns the one case where it is not —
/// a collision — from a silent overwrite of somebody's instance into a
/// refusal.
fn creating_instance(minted_resource: &Expr, minted_id: &Expr) -> Vec<Clause> {
    let target = || {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: INSTANCE,
            material: vec![minted_resource.clone(), minted_id.clone()],
        })
    };
    vec![
        Clause::Effect {
            guard: None,
            target: target(),
            mode: ModeExpr::Write,
            denomination: None,
        },
        Clause::Requires {
            guard: None,
            condition: ConditionExpr::Holds {
                target: Box::new(target()),
                presence: Presence::Absent,
            },
        },
    ]
}

/// The non-fungible surface end to end: an issuer that mints and burns,
/// and holders whose instances are the entries of their per-resource
/// holdings interval.
///
/// `mint` derives one fresh id, writes its `INSTANCE` data cell, and
/// produces the one-id edge — ungated, because this package is the
/// harness's demo issuer; what gates a real issuer's mint is its
/// author's declaration, not this vocabulary's. `deposit` files an
/// arriving edge's ids as entries at their ids; `withdraw` removes named
/// ids — one not held is a trap — and produces their edge; `burn`
/// consumes an edge outright.
/// Holdings are declared as the whole `(NF_VAULT, resource)` interval
/// capped at the count of ids the call itself names, the guest reaching
/// each id's entry through the one range capability — so a move
/// declares exactly the walk it performs.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let minted_resource = Expr::SelfResource { material: vec![] };
    let minted_id = Expr::FreshId { slot: 0 };
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "mint".into(),
        MethodSignature {
            totality: Totality::Infallible,
            // The pool's own resource, by the mark that separates it from
            // the instance's others — which is what the grant is for and
            // what makes another issuer's inexpressible here.
            issues: Some(Vec::new()),
            params: vec![],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(minted_id.clone()),
                AbiParam::Issuer,
            ],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(minted_resource.clone()),
                ids: Box::new(Expr::List(vec![minted_id.clone()])),
            }],
            effects: creating_instance(&minted_resource, &minted_id),
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "deposit".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: None,
            params: vec![ParamType::NfBucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            effects: vec![Clause::Effect {
                guard: None,
                target: holdings_range(
                    Expr::ResourceOf(Box::new(Expr::Arg(0))),
                    Expr::Len(Box::new(Expr::IdsOf(Box::new(Expr::Arg(0))))),
                ),
                mode: ModeExpr::Write,
                // The interval is one resource's holdings, and the
                // resource is the key it is narrowed by: what an entry
                // moving out of here carries is the same expression the
                // target names.
                denomination: Some(Box::new(Expr::ResourceOf(Box::new(Expr::Arg(0))))),
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: None,
            params: vec![ParamType::Address, ParamType::Ids],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(Expr::Arg(0)),
                ids: Box::new(Expr::Arg(1)),
            }],
            effects: vec![Clause::Effect {
                guard: None,
                target: holdings_range(Expr::Arg(0), Expr::Len(Box::new(Expr::Arg(1)))),
                mode: ModeExpr::Write,
                denomination: Some(Box::new(Expr::Arg(0))),
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "burn".into(),
        MethodSignature {
            totality: Totality::Infallible,
            // Bringing value out of existence is as declared as bringing
            // it in, and under the same grant.
            issues: Some(Vec::new()),
            params: vec![ParamType::NfBucket],
            abi: vec![AbiParam::Bucket(0), AbiParam::Issuer],
            ..MethodSignature::default()
        },
    );
    // The consumer side of custody, in three resolutions: the badge at
    // large, one named instance of it, and a quorum over three.
    for (name, rule) in consumer_gates() {
        methods.methods.insert(
            name.into(),
            MethodSignature {
                totality: Totality::Infallible,
                effects: vec![Clause::Requires {
                    guard: None,
                    condition: ConditionExpr::Satisfies { rule },
                }],
                issues: None,
                ..MethodSignature::default()
            },
        );
    }
    methods
}

/// Each badge-gated consumer method and the rule that opens it.
///
/// One config slot names the badge; the slots after it name the
/// instances an admin set is written as.
fn consumer_gates() -> [(&'static str, RuleExpr); 3] {
    let instance = |slot| RuleExpr::claim(Expr::Tuple(vec![Expr::Config(0), Expr::Config(slot)]));
    [
        // Opens for whoever presents the identity the configured badge
        // resource names.
        ("operate", RuleExpr::claim(Expr::Config(0))),
        // The same at instance resolution: the configured resource and
        // the configured id name one instance, and holding any other
        // instance of that resource opens nothing.
        ("operate-instance", instance(1)),
        // The same over an admin set: three badge instances in
        // configuration, any two of which open the surface. One badge
        // resource, one instance per admin — rotate by issuing, revoke
        // by burning, and never redeploy to seat a fourth.
        (
            "operate-quorum",
            RuleExpr::CountOf {
                count: 2,
                rules: (1..=3).map(instance).collect(),
            },
        ),
    ]
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Mint one fresh instance of `issuer`'s resource, producing its
/// one-id edge.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `mint`.
pub fn mint(builder: &mut TypedBuilder<'_>, issuer: ComponentAddr) -> Result<Bucket, TypedError> {
    builder.call(issuer, "mint", ())?.one()
}

/// File `funds`' instances as entries of `holder`'s holdings.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit`.
pub fn deposit(
    builder: &mut TypedBuilder<'_>,
    holder: ComponentAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(holder, "deposit", (funds,))?.none()
}

/// Remove the named `ids` of `resource` from `holder`'s holdings,
/// producing their edge; an id not held traps at execution.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw`.
pub fn withdraw(
    builder: &mut TypedBuilder<'_>,
    holder: ComponentAddr,
    resource: impl Into<Denomination>,
    ids: &[u64],
) -> Result<Bucket, TypedError> {
    let ids = Value::List(ids.iter().copied().map(Value::U64).collect());
    builder
        .call(holder, "withdraw", (resource.into(), ids))?
        .one()
}

/// Consume `funds` outright: its instances stop being held anywhere.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `burn`.
pub fn burn(
    builder: &mut TypedBuilder<'_>,
    issuer: ComponentAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(issuer, "burn", (funds,))?.none()
}

/// Act on the quorum-gated consumer, presenting one admin's instance.
///
/// Two presentations of two distinct configured instances open it; one
/// opens nothing, and a fourth instance of the same resource is not an
/// admin.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `operate-quorum`.
pub fn operate_quorum(
    builder: &mut TypedBuilder<'_>,
    gated: ComponentAddr,
    proofs: &[Proof],
) -> Result<(), TypedError> {
    builder
        .call_presenting(proofs, gated, "operate-quorum", ())?
        .none()
}

/// Act on the instance-gated consumer, presenting the instance claim a
/// custody gate minted. Holding another instance of the same resource
/// opens nothing here.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `operate-instance`.
pub fn operate_instance(
    builder: &mut TypedBuilder<'_>,
    gated: ComponentAddr,
    proof: Proof,
) -> Result<(), TypedError> {
    builder
        .call_as(proof, gated, "operate-instance", ())?
        .none()
}

/// Act on the badge-gated consumer, presenting the badge identity a
/// custody gate minted — any instance of it, or any of it held in a
/// vault.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `operate`.
pub fn operate(
    builder: &mut TypedBuilder<'_>,
    gated: ComponentAddr,
    proof: Proof,
) -> Result<(), TypedError> {
    builder.call_as(proof, gated, "operate", ())?.none()
}
