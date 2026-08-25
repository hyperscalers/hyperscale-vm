//! A component that holds value and declares no rule about it.
//!
//! The case a holder-side fence cannot bind: every method is one a real
//! application already has, and none of them cooperates. What a corpus
//! running it establishes is not that the component is unusual but that
//! it is ordinary — if a movement requirement binds this, it binds every
//! application, because there is nothing here for an author to have done
//! differently.

use hyperscale_vm_effects::PackageMetadata;

#[path = "../../../guests/custodian/src/lib.rs"]
mod package;

pub use package::custodian::blueprint;
pub use package::custodian::client::*;
/// The package's own bodies, dispatched natively.
pub use package::custodian::invoke;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    blueprint().metadata()
}
