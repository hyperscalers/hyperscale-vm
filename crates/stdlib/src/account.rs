//! The fungible account: the package every principal answers.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on,
//! the code that executes them and the wrappers a client calls them
//! through are all read off one text.
//!
//! Free functions rather than a handle, because the instance registry
//! serves this package to every principal address by class rather than
//! by record. A principal's address derives from a key and folds in
//! no package hash, so [`PrincipalAddr`] is already the whole of what a
//! handle could say.
//!
//! [`PrincipalAddr`]: hyperscale_vm_effects::PrincipalAddr

use hyperscale_vm_effects::{PackageMetadata, RoleTable, StoredRule};
use hyperscale_vm_manifest_builder::{Proof, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/account/src/lib.rs"]
mod package;

pub use package::account::client::*;
/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a test running
/// this is running the code the artifact was built from rather than a
/// stand-in for it.
pub use package::account::invoke;

/// The fungible account.
///
/// Spending and writing require the account's own authority; being paid
/// does not. Anyone may credit you, and a transfer therefore still
/// composes under the sender's single signature — the recipient is not
/// asked for one, because nothing about a deposit is theirs to refuse.
/// A method writing a leaf under the target's prefix is gated for the
/// same reason a withdrawal is, though it moves nothing.
///
/// No method reads another account's balance. A precondition on mutable
/// state is a fresh read, which makes the read's owner a participant —
/// the account surface has no shape that wants one yet.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::account::blueprint().metadata()
}

/// Securify with one rule as all three reserved roles.
///
/// # Errors
///
/// Any refusal the call does not type against `securify`.
///
/// # Panics
///
/// On a rule past the vocabulary's own caps, which no admission path
/// would accept; the compose site is where its author can fix it.
pub fn securify_uniform(
    b: &mut TypedBuilder<'_>,
    proof: Proof,
    rule: &StoredRule,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    let roles = RoleTable::uniform(rule).expect("a rule within the caps encodes");
    securify(b, proof, roles, recovery_delay_ms)
}
