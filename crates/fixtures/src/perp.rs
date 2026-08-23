//! A perpetual position: margin against a size, marked to an oracle, and
//! charged funding for as long as it is held.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it carries. Its
//! cumulative funding figure is the corpus's only signed stored value,
//! and it is signed by hand — a magnitude, an integer flag beside it, and
//! a normalizing addition the guest wrote itself.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/perp/src/lib.rs"]
mod package;

pub use package::perp::client::*;
/// The package's own bodies, dispatched natively.
pub use package::perp::invoke;

/// What an entry point declines with when no mark has been posted.
pub const MARK_UNSET: u32 = 0;
/// What `open` declines with against a market already holding one.
pub const ALREADY_OPEN: u32 = 1;
/// What a close or a liquidation declines with against no position.
pub const NOT_OPEN: u32 = 2;
/// What `open` declines with when the margin does not cover maintenance.
pub const BELOW_MAINTENANCE: u32 = 3;
/// What a liquidation declines with against a covered position.
pub const STILL_COVERED: u32 = 4;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::perp::blueprint().metadata()
}
