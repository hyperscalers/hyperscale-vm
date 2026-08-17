//! The non-fungible surface: an issuer that mints and burns, and the
//! holders whose instances are their holdings entries.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::{INSTANCE, NF_MOVE_CAP};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    ResourceRef, Totality, Value, holdings_range,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

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
/// Holdings are declared as the whole `(NF_VAULT, resource)` interval at
/// [`NF_MOVE_CAP`], the guest reaching each id's entry through the one
/// range capability.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let minted_resource = Expr::SelfResource { material: vec![] };
    let minted_id = Expr::FreshId { slot: 0 };
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "mint".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
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
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    role: INSTANCE,
                    material: vec![minted_resource, minted_id],
                }),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "deposit".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::NfBucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            effects: vec![Clause::Effect {
                target: holdings_range(Expr::ResourceOf(Box::new(Expr::Arg(0))), NF_MOVE_CAP),
                mode: ModeExpr::Write,
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::Address, ParamType::Ids],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(Expr::Arg(0)),
                ids: Box::new(Expr::Arg(1)),
            }],
            effects: vec![Clause::Effect {
                target: holdings_range(Expr::Arg(0), NF_MOVE_CAP),
                mode: ModeExpr::Write,
            }],
            ..MethodSignature::default()
        },
    );
    methods.methods.insert(
        "burn".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            // Bringing value out of existence is as declared as bringing
            // it in, and under the same grant.
            issues: Some(Vec::new()),
            params: vec![ParamType::NfBucket],
            abi: vec![AbiParam::Bucket(0), AbiParam::Issuer],
            ..MethodSignature::default()
        },
    );
    // The badge-gated consumer: opens for whoever presents the identity
    // the configured badge resource names — the whole consumer side of
    // custody, one config slot.
    methods.methods.insert(
        "operate".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(Expr::Config(0)),
            mints: None,
            issues: None,
            ..MethodSignature::default()
        },
    );
    methods
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
    resource: impl Into<ResourceRef>,
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

/// Act on the badge-gated instance, presenting the badge identity a
/// custody gate minted.
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
