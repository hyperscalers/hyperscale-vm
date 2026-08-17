//! The constant-product pool.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the wrappers, which a signature cannot supply — nothing in one says
//! which address class a method is addressed to.

use hyperscale_vm_effects::{ComponentAddr, PackageMetadata};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/amm/src/lib.rs"]
mod package;

/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a lane running
/// this is running the code the artifact was built from.
pub use package::amm::invoke;

/// The code `swap` declines with when the output misses its floor.
pub const SLIPPAGE_EXCEEDED: u32 = 0;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::amm::blueprint().metadata()
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
