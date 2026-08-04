//! The lowered form of a manifest node: which export to call, and where
//! each of its ABI arguments comes from.
//!
//! A method's declared parameters have no arity relation to its guest ABI
//! — the capability table mediates, so one declared bucket and two
//! declared effects can become two ABI arguments of which one is a handle
//! for the vault's delta and the other the bucket's bytes. The
//! [`crate::metadata::MethodSignature`]'s binding states which; this
//! module is that statement resolved against one node's bound inputs.
//!
//! Everything a binding names is resolvable before execution except one
//! thing: a bucket's amount, which is whatever the producing node
//! actually returned. So a lowered argument is either a settled value, a
//! table position, or an edge to read once its producer has run.

use crate::manifest::Bounds;
use crate::metadata::PackageHash;
use crate::types::Address;

/// The width of one value edge's cell: an amount is a little-endian
/// `u128`, and a bucket crossing the guest boundary is exactly that.
pub const EDGE_CELL_BYTES: usize = 16;

/// Where one ABI argument comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallArg {
    /// The capability at this position in the transaction's materialized
    /// table.
    ///
    /// Resolved from the clause the binding names, through that clause's
    /// span in its frame's flattened order plus the frame's own offset —
    /// so the position is a function of the whole transaction's
    /// declaration, which is what the table is built from.
    Handle(u32),
    /// The cell an earlier node produced on one of its output edges.
    Bucket {
        /// The producing node's index in the flattened manifest.
        source: u32,
        /// Which of the producer's outputs the edge carries.
        output: u32,
    },
    /// A 64-bit scalar the signature derived from the node's inputs.
    U64(u64),
    /// A byte string the signature derived from the node's inputs.
    Bytes(Vec<u8>),
}

/// One edge a node consumes, with the bound its consumer signed.
///
/// Separate from the argument list, because the two are not the same
/// set. A method that forwards its funds to a callee never reads the
/// amount, so nothing in its own ABI carries the edge — and the bound is
/// still the signer's, still owed a check. What owes the check is the
/// node where the edge resolves, whatever the node's guest then does
/// with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeBound {
    /// The producing node's index in the flattened manifest.
    pub source: u32,
    /// Which of the producer's outputs the edge carries.
    pub output: u32,
    /// The consuming node's declared parameter the edge is bound to —
    /// what a refusal names, since the signer wrote the bound against a
    /// parameter and not against an ABI position.
    pub param: u32,
    /// The consumer's signed bounds on the amount, folded to their
    /// conjunction at admission.
    ///
    /// Asserted independently of the callee, which is the manifest's own
    /// guarantee: a producer returning less than the consumer declared
    /// fails the transaction whatever the producer's code checked.
    pub bounds: Bounds,
}

/// One manifest node lowered to the invocation it performs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeCall {
    /// The package whose code runs. Content-addressed, so an embedder
    /// resolves the artifact by this and never by the instance's address.
    pub package: PackageHash,
    /// The instance invoked: the emitter every event of this frame is
    /// stamped with.
    pub target: Address,
    /// The guest export to invoke. A method's name is its export name —
    /// a publish refuses metadata naming a method the component does not
    /// export under exactly that name.
    pub export: String,
    /// One entry per exported parameter, in the export's own order.
    pub args: Vec<CallArg>,
    /// Every value edge the node consumes, in its declared parameter
    /// order, each with the bound its consumer signed. Checked before
    /// the invocation.
    pub edges: Vec<EdgeBound>,
    /// How many value edges the node produces. An export returns bytes
    /// exactly when this is non-zero, and then exactly
    /// `outputs * EDGE_CELL_BYTES` of them.
    pub outputs: u32,
}
