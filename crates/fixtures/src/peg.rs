//! A redemption window at a price that moves both ways: hand in the
//! stable, take reserve at parity plus what the oracle says the market
//! has done to it.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it holds. Its
//! deviation is the corpus's only signed stored value, and it is signed
//! by the vocabulary rather than by hand — which makes it the package
//! that says whether the type carries its weight.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/peg/src/lib.rs"]
mod package;

pub use package::peg::client::*;
/// The package's own bodies, dispatched natively.
pub use package::peg::invoke;

/// What a redemption declines with when the market has moved past the
/// band the window quotes in.
pub const OUTSIDE_BAND: u32 = 0;
/// What it declines with when the redemption is worth no reserve at all.
pub const NOTHING_REDEEMED: u32 = 1;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::peg::blueprint().metadata()
}
