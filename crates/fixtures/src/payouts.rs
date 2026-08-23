//! The fee splitter: revenue in, three configured shares out.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it divides.
//! One division against a whole weight table is the only operation in
//! the vocabulary that yields more than two edges at once, and how many
//! it yields is read off the source rather than computed — which is the
//! shape a corpus running on both lanes is worth having over.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/payouts/src/lib.rs"]
mod package;

pub use package::payouts::client::*;
/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a lane running
/// this is running the code the artifact was built from.
pub use package::payouts::invoke;

/// What a division declines with when the shares leave part of the
/// payment unclaimed.
pub const SHARE_UNCLAIMED: u32 = 0;
/// What it declines with when the payment is short of a whole lot.
pub const BELOW_ONE_LOT: u32 = 1;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::payouts::blueprint().metadata()
}
