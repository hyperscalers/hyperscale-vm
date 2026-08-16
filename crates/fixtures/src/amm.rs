//! The constant-product pool.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::{CONFIG, VAULT};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, ComponentAddr, Expr, MethodSignature, PackageMetadata, ParamType,
    Totality, self_child,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};

/// `swap(input, min_out)`: a locked read of the pool's
/// configuration and exclusive writes on its two reserve leaves, named by
/// the creation-fixed resource pair.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "swap".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
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

// ─── calls ─────────────────────────────────────────────────────────────

/// Trade `input` through `pool`, refusing to settle for less than
/// `min_out`. The proceeds are typed by the pool's configured output
/// resource.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `swap`.
pub fn swap(
    builder: &mut TypedBuilder<'_>,
    pool: ComponentAddr,
    input: impl BucketArg,
    min_out: u128,
) -> Result<Bucket, TypedError> {
    builder.call(pool, "swap", (input, min_out))?.one()
}
