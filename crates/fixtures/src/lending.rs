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

guest!(lending, "../../../guests/lending/src/lib.rs");

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
