//! The share vault: assets in, shares out, at whatever the pool is worth.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the wrappers, which a signature cannot supply — nothing in one says
//! which address class a method is addressed to.
//!
//! Here rather than only in its own crate because of what it computes.
//! Four entry points, two of which round the other way, over the widest
//! arithmetic the vocabulary has — which is precisely the shape two
//! engines could disagree on by a subunit without either being obviously
//! wrong. A fixture runs on both lanes; a guest crate's own tests run on
//! neither.

use hyperscale_vm_effects::{ComponentAddr, PackageMetadata};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/shares/src/lib.rs"]
mod package;

/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a lane running
/// this is running the code the artifact was built from.
pub use package::shares::invoke;

/// What an entry point declines with when the pool cannot price a share.
pub const EMPTY_VAULT: u32 = 0;
/// What it declines with when the payment does not cover what was asked.
pub const INSUFFICIENT: u32 = 1;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::shares::blueprint().metadata()
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Hand `funds` over, taking whatever shares they are worth.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit`.
pub fn deposit(
    builder: &mut TypedBuilder<'_>,
    vault: ComponentAddr,
    funds: impl BucketArg,
) -> Result<Bucket, TypedError> {
    builder.call(vault, "deposit", (funds,))?.one()
}

/// Ask for exactly `want` shares, paying out of `funds`; the shares come
/// back first and the change second.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `mint`.
pub fn mint(
    builder: &mut TypedBuilder<'_>,
    vault: ComponentAddr,
    want: u128,
    funds: impl BucketArg,
) -> Result<[Bucket; 2], TypedError> {
    builder.call(vault, "mint", (want, funds))?.into_array()
}

/// Ask for exactly `want` assets, paying in `units`; the assets come back
/// first and the unspent units second.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw`.
pub fn withdraw(
    builder: &mut TypedBuilder<'_>,
    vault: ComponentAddr,
    want: u128,
    units: impl BucketArg,
) -> Result<[Bucket; 2], TypedError> {
    builder.call(vault, "withdraw", (want, units))?.into_array()
}

/// Hand `units` back, taking whatever assets they are worth.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `redeem`.
pub fn redeem(
    builder: &mut TypedBuilder<'_>,
    vault: ComponentAddr,
    units: impl BucketArg,
) -> Result<Bucket, TypedError> {
    builder.call(vault, "redeem", (units,))?.one()
}
