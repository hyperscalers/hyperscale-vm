//! The order book: makers place asks, takers fill by price-time
//! priority.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/book/src/lib.rs"]
mod package;

use hyperscale_vm_effects::{SlotId, package_slot};
pub use package::book::client::*;

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;

/// The order book's ask-side ordered collection.
pub const ASKS: SlotId = package_slot(0);

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::book::blueprint().metadata()
}
