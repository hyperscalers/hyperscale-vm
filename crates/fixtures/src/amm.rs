//! The constant-product pool.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.

guest!(amm, "../../../guests/amm/src/lib.rs");

/// The refusal table, as the variants its author wrote.
pub use package::amm::Error;
