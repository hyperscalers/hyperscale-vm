//! The constant-product pool.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.

guest!(amm, "../../../guests/amm/src/lib.rs");

/// The code `swap` declines with when the output misses its floor.
pub const SLIPPAGE_EXCEEDED: u32 = 0;
