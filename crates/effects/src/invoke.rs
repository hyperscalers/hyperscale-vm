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

use hyperscale_vm_types::{Address, CellKind, ResourceAddr};

use crate::manifest::{Bounds, JudgedLeaf};
use crate::metadata::PackageHash;
use crate::presented::Presented;
use crate::rule::Rule;
use crate::types::{EdgeContent, MAX_IDS_PER_EDGE};

/// What kind of value an edge carries.
///
/// Declared — evaluated from the producing method's output projection —
/// and never sniffed from what crosses: the kind is what admission binds
/// a consumer's parameter against, and what a signed bound is judged in
/// the terms of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    /// The edge carries a dynamic amount.
    Fungible,
    /// The edge carries named instances.
    NonFungible,
}

impl EdgeKind {
    /// The cell shape a projection's content crosses the boundary as.
    #[must_use]
    pub const fn of(content: &EdgeContent) -> Self {
        match content {
            EdgeContent::Fungible => Self::Fungible,
            EdgeContent::NonFungible { .. } => Self::NonFungible,
        }
    }
}

/// The ids a non-fungible edge carries, as a set, or `None` for a list
/// that is not one: more than [`MAX_IDS_PER_EDGE`], or a repeated id.
///
/// An id set is distinct wherever it exists — evaluation's `id_set`
/// refuses a repeat in a declared set, and this refuses one in a set a
/// guest named — so an id count is an instance count everywhere it is
/// judged. The cap is here rather than in a wire format because there is
/// no longer a wire format: a list of ids crosses as a list of ids, and
/// what bounds it is the rule rather than a count byte.
#[must_use]
pub fn distinct_ids(ids: &[u64]) -> Option<Vec<u64>> {
    if ids.len() > MAX_IDS_PER_EDGE {
        return None;
    }
    for (index, id) in ids.iter().enumerate() {
        if ids[..index].contains(id) {
            return None;
        }
    }
    Some(ids.to_vec())
}

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
    /// A handle position no capability occupies: the clause that would
    /// have backed it was guarded out.
    ///
    /// The kind travels because nothing downstream can recover it. An
    /// engine reads a handle's world type off the capability at its rep,
    /// and there is no capability here — routing has the type, from the
    /// clause's own target and mode, and is the last thing that does.
    AbsentHandle(CellKind),
    /// A clause's own guard verdict, as the export's `bool`.
    Bool(bool),
    /// A 64-bit scalar the signature derived from the node's inputs.
    U64(u64),
    /// An address the signature derived from the node's inputs.
    Address(Address),
    /// A byte string the signature derived from the node's inputs.
    Bytes(Vec<u8>),
    /// A set of non-fungible instance ids.
    ///
    /// Its own variant rather than the bytes a count-prefixed cell would
    /// make of it: what crosses is a list of ids, and the framing a
    /// guest would otherwise decode is the kernel's own business.
    Ids(Vec<u64>),
    /// This invocation's authority to issue.
    ///
    /// Carries nothing: the grant is that it exists, and which resource
    /// the value it creates is denominated in is what [`NodeCall::outputs`]
    /// already says.
    Issuer,
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
    /// The declared shape of the carried cell, which is what the bound is
    /// judged over: a fungible edge's amount, a non-fungible edge's id
    /// count.
    pub kind: EdgeKind,
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
    /// The declared cell shape of each value edge the node produces, in
    /// output order. An export produces exactly one edge per entry: a
    /// fungible one as a bucket the kernel takes back, a non-fungible one
    /// as the cell its ids frame.
    pub outputs: Vec<EdgeKind>,
    /// The resource this node's method may bring into being, where its
    /// declaration says it brings one.
    ///
    /// Evaluated at routing from the mark the signature carries, against
    /// the target's own address — so an instance can issue what its own
    /// address derives and nothing else, which is the whole of what
    /// grants the authority. Carrying the address rather than a bit is
    /// what lets an issued edge be stamped with what it holds.
    pub issues: Option<ResourceAddr>,
    /// The claims this call presents, resolved from the signed evidence
    /// the manifest node names.
    pub evidence: Vec<Presented>,
    /// The authority conditions this node's declaration requires, each a
    /// judged rule over the call's presented evidence and the stored
    /// rules its cells hold. All must be satisfied — a claim leaf by the
    /// presented set alone, a stored leaf by the rule the named role
    /// selects at the cell, judged where the cell lives.
    pub requires: Vec<Rule<JudgedLeaf>>,
}

#[cfg(test)]
mod tests {
    use super::{MAX_IDS_PER_EDGE, distinct_ids};

    /// What an id set is: distinct ids, no more than an edge carries.
    ///
    /// The framing that used to carry them is gone — a list of ids
    /// crosses as a list of ids — so what is left to judge is the set
    /// property itself, and it is judged here rather than fallen out of
    /// a decode.
    #[test]
    fn an_id_set_is_distinct_and_within_the_edge_cap() {
        assert_eq!(distinct_ids(&[]), Some(vec![]));
        assert_eq!(distinct_ids(&[3, 9]), Some(vec![3, 9]));

        assert_eq!(distinct_ids(&[7, 7]), None);
        assert_eq!(distinct_ids(&[1, 2, 1]), None);

        let full: Vec<u64> = (0..u64::try_from(MAX_IDS_PER_EDGE).unwrap()).collect();
        assert_eq!(distinct_ids(&full), Some(full.clone()));
        let over: Vec<u64> = (0..=u64::try_from(MAX_IDS_PER_EDGE).unwrap()).collect();
        assert_eq!(distinct_ids(&over), None);
    }
}
