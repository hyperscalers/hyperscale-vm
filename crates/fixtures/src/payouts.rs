//! The fee splitter: revenue in, three configured shares out.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! Here rather than only in its own crate because of what it divides.
//! One division against a whole weight table is the only operation in
//! the vocabulary that yields more than two edges at once, and how many
//! it yields is read off the source rather than computed — which is the
//! shape a corpus running on both lanes is worth having over.

guest!(payouts, "../../../guests/payouts/src/lib.rs");

/// What a division declines with when the shares leave part of the
/// payment unclaimed.
pub const SHARE_UNCLAIMED: u32 = 0;
/// What it declines with when the payment is short of a whole lot.
pub const BELOW_ONE_LOT: u32 = 1;
