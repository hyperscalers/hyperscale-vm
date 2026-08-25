//! Supply an entry withholds, supply an entry only shrinks, and minting
//! a badge holder does.
//!
//! The issuer's side of the authority seam, where
//! [`security`](crate::security) is the holder's. What it establishes is
//! that the three questions are independent: a resource can be founded
//! and never minted, destroyed by an authority that could never create
//! it, and minted by somebody the issuer named rather than by the issuer.
//!
//! All three grant only authorities, so all three addresses stay plain
//! `Resource` — the control for anyone tempted to re-cut the class byte
//! around whether a resource grants anything at all.

use hyperscale_vm_effects::PackageMetadata;

#[path = "../../../guests/capped/src/lib.rs"]
mod package;

/// The package's traced declaration, as `package!` reaches it.
pub use package::capped::blueprint;
pub use package::capped::client::*;
/// The package's own bodies, dispatched natively.
pub use package::capped::invoke;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    blueprint().metadata()
}
