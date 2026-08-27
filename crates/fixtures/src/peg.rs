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

guest!(peg, "../../../guests/peg/src/lib.rs");

/// The refusal table, as the variants its author wrote.
pub use package::peg::Error;
