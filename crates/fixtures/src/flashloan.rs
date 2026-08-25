//! A loan that lasts one transaction, and the obligation that makes it
//! safe.
//!
//! The transient resource, where [`security`](crate::security) is the
//! restricted one: `Debt` grants `deposit = nobody`, so no vault may
//! hold it under any owner and the only thing a borrower can do with it
//! is hand it back to be burned. What that makes checkable is the half
//! of the movement seam a credential cannot reach — whether a resource
//! may come to rest at all, which is decidable from the entry before
//! anything routes.
//!
//! Here rather than only in its own crate because the property is about
//! what a *graph* may do rather than what a body computes, and the cases
//! that establish it are a refusal at admission and an execution that
//! completes. A fixture reaches both; a guest crate's own tests reach
//! neither.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/flashloan/src/lib.rs"]
mod package;

/// The material separating the obligation from anything else the pool
/// might issue — the package's own, re-exported rather than restated.
pub use package::flashloan::DEBT;
pub use package::flashloan::client::*;
/// The package's own bodies, dispatched natively.
pub use package::flashloan::invoke;

/// What `repay` declines with when less came back than was owed.
pub const SHORT: u32 = 0;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::flashloan::blueprint().metadata()
}
