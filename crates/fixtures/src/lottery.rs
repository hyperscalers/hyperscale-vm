//! The lottery: a pot anyone may enter, and a winner nobody chooses.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! `enter(who, funds)`: one ticket at the entrant's hashed order and the
//! stake into the pot, both commutative with every other entry — two
//! people entering at once write two entries and one delta, and neither
//! waits on the other. It is public, and the authority behind an entry is
//! the funds it carries, gated upstream at the withdrawal that produced
//! them. Whoever pays may name whoever they like as the entrant, which is
//! buying somebody a ticket.
//!
//! `draw()`: a fresh read of the whole entrants interval and an exclusive
//! write of the result. Public for a reason that is not laziness — the
//! draw is the transaction's randomness, and no signer chooses it, so
//! there is nothing an operator would be trusted with.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/lottery/src/lib.rs"]
mod package;

pub use package::lottery::Outcome;
pub use package::lottery::client::*;

/// The entrant cap a draw declares: the round a single draw settles.
pub const ROUND_CAP: u32 = 64;

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::lottery::blueprint().metadata()
}
