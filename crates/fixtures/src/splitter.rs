//! The bucket splitter.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::{
    AbiParam, Expr, MethodSignature, PackageMetadata, ParamType, Totality,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};
use hyperscale_vm_types::ComponentAddr;

/// `take(bucket, amount)`: split a bucket, producing the taken part and
/// the rest — two output edges of the same resource, both of which
/// linearity forces the manifest to route.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        "take".into(),
        MethodSignature {
            totality: Totality::Infallible,
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

// ─── calls ─────────────────────────────────────────────────────────────

/// Split `amount` off `funds`, answering the part taken and then the
/// rest — both typed by what went in, and both of which linearity
/// forces the graph to route.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `take`.
pub fn take(
    builder: &mut TypedBuilder<'_>,
    splitter: ComponentAddr,
    funds: impl BucketArg,
    amount: u128,
) -> Result<[Bucket; 2], TypedError> {
    builder
        .call(splitter, "take", (funds, amount))?
        .into_array()
}
