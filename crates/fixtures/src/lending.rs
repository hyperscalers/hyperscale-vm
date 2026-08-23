//! A collateralized borrowing position: collateral in one resource, debt
//! in another, and a judgment between them that crosses a numeraire.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it stores. The
//! debt index is the only two-hundred-fifty-six-bit value in the corpus
//! that outlives a transaction, and a stored rate is exactly the shape
//! two engines could disagree about by a subunit without either looking
//! wrong.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/lending/src/lib.rs"]
mod package;

pub use package::lending::client::*;
/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a lane running
/// this is running the code the artifact was built from.
pub use package::lending::invoke;

/// What an entry point declines with when no price has been posted.
pub const PRICE_UNSET: u32 = 0;
/// What it declines with when the index has not been carried to the
/// period the call names.
pub const INDEX_STALE: u32 = 1;
/// What a draw declines with when it would owe more than the collateral
/// allows.
pub const OVER_LTV: u32 = 2;
/// What a liquidation declines with against a position that still covers
/// what it owes.
pub const STILL_COVERED: u32 = 3;
/// What it declines with against a position that owes nothing.
pub const NOTHING_OWED: u32 = 4;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::lending::blueprint().metadata()
}
