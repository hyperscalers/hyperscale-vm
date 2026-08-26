//! Supply an entry withholds, supply an entry only shrinks, and minting
//! a badge holder does.
//!
//! The issuer's side of the authority seam, where
//! [`security`](crate::security) is the holder's. What it establishes is
//! that the three questions are independent: a resource can be founded
//! and never minted, destroyed by an authority that could never create
//! it, and minted by somebody the issuer named rather than by the issuer.
//!
//! All three grant only authorities, so all three addresses stay plain
//! `Resource` — the control for anyone tempted to re-cut the class byte
//! around whether a resource grants anything at all.

guest!(capped, "../../../guests/capped/src/lib.rs");
