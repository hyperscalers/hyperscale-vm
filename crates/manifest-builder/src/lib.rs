//! Fluent construction of the signed manifest graph.
//!
//! The graph a transaction signs — [`ManifestGraph`]'s typed dataflow DAG —
//! asks three structural things of its author: producers precede
//! consumers, every output edge is consumed exactly once, and indices
//! stay addressable. Hand-assembling nodes keeps those rules by care;
//! this crate keeps them by shape. A [`GraphBuilder`] appends nodes and
//! mints each call's outputs as affine [`Bucket`] handles, so a forward
//! edge cannot be written, a double consumption is a move error, and the
//! one rule left — nothing dangles — is [`build`]'s check. An author who
//! would rather not route their own change names where it goes with
//! [`rest_to`], and what nothing claimed is deposited there.
//!
//! A [`TypedBuilder`] adds the tables admission consults — the metadata
//! cache and the instance registry — and types each call against the
//! signature its target declares: arity, argument kinds and output count
//! stop being the author's claims, and an edge whose type the producing
//! signature determines asserts that type by itself.
//!
//! Above the graph, an [`EnvelopeBuilder`] composes intents through the
//! sockets they declare — ones the composer writes, and ones somebody
//! else already signed — wiring an edge or a proof into each, and
//! [`preflight()`] answers what the chain will make of the result before
//! any of it is signed.
//!
//! The builder sits strictly on the client side of the trust boundary.
//! It renders no judgement; admission re-derives every property it
//! enforces, so its whole contract is that a graph it emits without error
//! is one admission accepts, and a defect here can never admit what the
//! protocol would refuse.
//!
//! [`ManifestGraph`]: hyperscale_vm_effects::ManifestGraph
//! [`build`]: GraphBuilder::build
//! [`rest_to`]: GraphBuilder::rest_to

pub mod args;
pub mod builder;
pub mod envelope;
pub mod preflight;
pub mod render;
pub mod signing;
pub mod typed;

pub use args::{AddressArg, Arg, Args, BucketArg};
pub use builder::{Bucket, BuildError, GraphBuilder, SocketRef};
pub use envelope::{EnvelopeBuilder, EnvelopeError, IntentBuilder, Offered, OpenSocket};
pub use preflight::{Authority, PreflightError, Report, Required, preflight, preflight_tree};
pub use render::{Names, render};
pub use typed::{Answered, Outputs, Proof, TypedBuilder, TypedError, graph_records};
