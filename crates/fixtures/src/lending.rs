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

/// The refusal table, as the variants its author wrote.
pub use package::lending::Error;
