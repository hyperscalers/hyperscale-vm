//! A resource that grants restrictions, authored through the macro.
//!
//! The declaring end of the movement seam. What
//! [`custodian`](crate::custodian) establishes is that a package
//! declaring nothing is bound anyway; this is the package that writes
//! the rule down — a share class whose withdrawals are governed by a
//! standing register entry, and the entry itself, soulbound so it cannot
//! be handed on.

use hyperscale_vm_effects::PackageMetadata;

#[path = "../../../guests/security/src/lib.rs"]
mod package;

pub use package::security::client::*;
/// The package's own bodies, dispatched natively.
pub use package::security::invoke;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::security::blueprint().metadata()
}
