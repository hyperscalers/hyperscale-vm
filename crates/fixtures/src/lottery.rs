//! The lottery: a pot anyone may enter, and a winner nobody chooses.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the wrappers, which a signature cannot supply.
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

use hyperscale_vm_effects::{ComponentAddr, PackageMetadata, PrincipalAddr, RoleId, package_role};
use hyperscale_vm_manifest_builder::{BucketArg, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/lottery/src/lib.rs"]
mod package;

/// The entrant cap a draw declares: the round a single draw settles.
pub const ROUND_CAP: u32 = 64;

/// A lottery's entrants: one entry per entrant, at the entrant's hashed
/// order, so a second entry from one address lands on its own ticket.
pub const TICKETS: RoleId = package_role(0);
/// A lottery's settled round: the draw, and the entrant it selected.
pub const DRAW: RoleId = package_role(1);

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::lottery::blueprint().metadata()
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Enter `who` in `lottery`'s round, staking `funds` into the pot.
///
/// Whoever composes the call names the entrant, which is what buying
/// somebody a ticket looks like: the authority behind an entry is the
/// funds, gated at the withdrawal that produced them.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `enter`.
pub fn enter(
    builder: &mut TypedBuilder<'_>,
    lottery: ComponentAddr,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(lottery, "enter", (who, funds))?.none()
}

/// Settle `lottery`'s round on the transaction's randomness draw.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `draw`.
pub fn draw(builder: &mut TypedBuilder<'_>, lottery: ComponentAddr) -> Result<(), TypedError> {
    builder.call(lottery, "draw", ())?.none()
}
