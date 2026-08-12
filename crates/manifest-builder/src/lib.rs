//! Fluent construction of the signed manifest graph.
//!
//! The graph a transaction signs — [`ManifestGraph`]'s typed dataflow DAG —
//! asks three structural things of its author: producers precede
//! consumers, every output edge is consumed exactly once, and indices
//! stay addressable. Hand-assembling nodes keeps those rules by care;
//! this crate keeps them by shape. A [`GraphBuilder`] appends nodes and
//! mints each call's outputs as affine [`Bucket`] handles, so a forward
//! edge cannot be written, a double consumption is a move error, and the
//! one rule left — nothing dangles — is [`build`]'s check.
//!
//! A [`TypedBuilder`] adds the tables admission consults — the metadata
//! cache and the instance registry — and types each call against the
//! signature its target declares: arity, argument kinds and output count
//! stop being the author's claims, and an edge whose type the producing
//! signature determines asserts that type by itself.
//!
//! The builder sits strictly on the client side of the trust boundary.
//! It renders no judgement; admission re-derives every property it
//! enforces, so its whole contract is that a graph it emits without error
//! is one admission accepts, and a defect here can never admit what the
//! protocol would refuse.
//!
//! [`ManifestGraph`]: hyperscale_vm_effects::ManifestGraph
//! [`build`]: GraphBuilder::build

pub mod args;
pub mod builder;
pub mod typed;

pub use args::{Arg, Args};
pub use builder::{Bucket, BuildError, GraphBuilder, Param};
pub use typed::{Outputs, TypedBuilder, TypedError};
