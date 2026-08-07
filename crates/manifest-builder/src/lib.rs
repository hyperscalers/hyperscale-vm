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
//! The builder sits strictly on the client side of the trust boundary.
//! It reads no metadata and renders no judgement; admission re-derives
//! every property it enforces, so its whole contract is that a graph it
//! emits without error passes the structural half of admission, and a
//! defect here can never admit what the protocol would refuse.
//!
//! [`ManifestGraph`]: hyperscale_vm_effects::ManifestGraph
//! [`build`]: GraphBuilder::build

pub mod args;
pub mod builder;

pub use args::{Arg, Args};
pub use builder::{Bucket, BuildError, GraphBuilder, Param};
