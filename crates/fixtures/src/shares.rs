//! The share vault: assets in, shares out, at whatever the pool is worth.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it computes.
//! Four entry points, two of which round the other way, over the widest
//! arithmetic the vocabulary has — which is precisely the shape two
//! engines could disagree on by a subunit without either being obviously
//! wrong. A fixture runs on both lanes; a guest crate's own tests run on
//! neither.

guest!(shares, "../../../guests/shares/src/lib.rs");

/// The material separating the vault's own unit from anything else it
/// might issue — the package's own, re-exported rather than restated.
pub use package::shares::UNIT;

/// What an entry point declines with when the pool cannot price a share.
pub const EMPTY_VAULT: u32 = 0;
/// What it declines with when the payment does not cover what was asked.
pub const INSUFFICIENT: u32 = 1;
