//! The order book: makers place asks, takers fill by price-time
//! priority.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.

guest!(book, "../../../guests/book/src/lib.rs");

/// The entry cap the book's fill range declares.
pub const FILL_CAP: u32 = 64;
