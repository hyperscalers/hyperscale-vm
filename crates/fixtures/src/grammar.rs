//! The shapes a contract body may take, as a package two lanes run.
//!
//! Building the artifact settles that the emission has a rewriting for
//! each shape. It says nothing about whether what the guest half writes
//! is what the bodies wrote — the two halves of a cfg are read on
//! different targets, and a host build reads only one of them. So the
//! shapes whose halves could differ are here, where a fixture runs on
//! both lanes and the lanes are held to each other.

guest!(grammar, "../../../guests/grammar/src/lib.rs");

/// The material separating the seat from anything else the package
/// might issue — the package's own, re-exported rather than restated.
pub use package::grammar::SEAT;
/// The record a seat's instance carries, so a lane can hold the cell to
/// the encoding the mark declares rather than to bytes copied here.
pub use package::grammar::Seat;
