//! The order book: makers place asks, takers fill by price-time
//! priority.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the wrappers, which a signature cannot supply — nothing in one says
//! which address class a method is addressed to.

use hyperscale_vm_effects::{ComponentAddr, PackageMetadata};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/book/src/lib.rs"]
mod package;

use hyperscale_vm_effects::{RoleId, package_role};

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;

/// The order book's ask-side ordered collection.
pub const ASKS: RoleId = package_role(0);

/// The package's declaration, traced from its own module.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::book::blueprint().metadata()
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Offer `funds` on `book` at `price`, escrowed until filled.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `place-ask`.
pub fn place_ask(
    builder: &mut TypedBuilder<'_>,
    book: ComponentAddr,
    price: u64,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(book, "place-ask", (price, funds))?.none()
}

/// Spend `payment` against `book`'s asks priced within `from..=to`,
/// answering what was bought and then what of the payment was not
/// spent, in that order.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `fill-asks`.
pub fn fill_asks(
    builder: &mut TypedBuilder<'_>,
    book: ComponentAddr,
    from: u64,
    to: u64,
    payment: impl BucketArg,
) -> Result<[Bucket; 2], TypedError> {
    builder
        .call(book, "fill-asks", (from, to, payment))?
        .into_array()
}
