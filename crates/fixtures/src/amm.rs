//! The constant-product pool.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/amm/src/lib.rs"]
mod package;

pub use package::amm::client::*;
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
