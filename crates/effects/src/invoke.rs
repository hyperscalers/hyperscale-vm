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

use crate::manifest::{AuthorityGate, Bounds};
use crate::metadata::PackageHash;
use crate::types::{Address, EdgeContent, MAX_IDS_PER_EDGE};

/// The width of a fungible edge's cell: an amount is a little-endian
/// `u128`, and a fungible bucket crossing the guest boundary is exactly
/// that.
pub const EDGE_CELL_BYTES: usize = 16;

/// The shape of one value edge's boundary cell.
///
/// The kind is declared — evaluated from the producing method's output
/// projection — and the cell is framed by it, never sniffed from the
/// bytes: a fungible cell is exactly [`EDGE_CELL_BYTES`], a non-fungible
/// cell is [`ids_cell`]'s count-prefixed id list.
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

/// A non-fungible edge's boundary cell: one count byte, then that many
/// little-endian `u64` ids.
///
/// The count fits a byte because [`MAX_IDS_PER_EDGE`] does; every decoder
/// refuses a count past the cap, so the byte's spare range is
/// unrepresentable rather than reserved.
///
/// # Panics
///
/// On more ids than [`MAX_IDS_PER_EDGE`] — a set no admitted projection
/// can carry.
#[must_use]
pub fn ids_cell(ids: &[u64]) -> Vec<u8> {
    assert!(ids.len() <= MAX_IDS_PER_EDGE, "id set exceeds the edge cap");
    let mut cell = Vec::with_capacity(1 + ids.len() * 8);
    cell.push(u8::try_from(ids.len()).expect("the cap fits a byte"));
    for id in ids {
        cell.extend_from_slice(&id.to_le_bytes());
    }
    cell
}

/// The frame width of the non-fungible cell at the head of `bytes`, or
/// `None` for a missing or over-cap count byte.
///
/// The width covers the count byte and the ids it announces; the caller
/// owns checking that many bytes exist. This is how a stream of
/// concatenated cells is split without decoding: the count byte alone
/// fixes where the next cell begins.
#[must_use]
pub fn nf_cell_len(bytes: &[u8]) -> Option<usize> {
    let count = usize::from(*bytes.first()?);
    (count <= MAX_IDS_PER_EDGE).then_some(1 + count * 8)
}

/// The ids a non-fungible cell carries, or `None` for bytes that are not
/// exactly one well-formed cell: a missing or over-cap count, a width
/// that disagrees with it, a repeated id.
///
/// An id set is distinct wherever it exists: evaluation's `id_set`
/// refuses a repeated id in a declared set, and this decoder refuses one
/// in a runtime cell — so an id count is an instance count everywhere it
/// is judged, whatever bytes a guest returns.
#[must_use]
pub fn cell_ids(cell: &[u8]) -> Option<Vec<u64>> {
    let width = nf_cell_len(cell)?;
    if cell.len() != width {
        return None;
    }
    let ids: Vec<u64> = cell[1..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|id| u64::from_le_bytes(*id))
        .collect();
    for (index, id) in ids.iter().enumerate() {
        if ids[..index].contains(id) {
            return None;
        }
    }
    Some(ids)
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
    /// A 64-bit scalar the signature derived from the node's inputs.
    U64(u64),
    /// An address the signature derived from the node's inputs.
    Address(Address),
    /// A byte string the signature derived from the node's inputs.
    Bytes(Vec<u8>),
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
    /// Whether this node's method declares an output the invoked instance
    /// issues itself.
    ///
    /// Evaluated at routing from the same output projections that fixed
    /// the edge kinds: a resource derived from the target's own address
    /// is a method saying it produces what it issues, which is the whole
    /// of what grants the authority.
    pub issues: bool,
    /// The identities this call presents, resolved from the signed
    /// evidence the manifest node names.
    pub evidence: Vec<Address>,
    /// The gate the presented identities are judged against. `None` for
    /// a method admitting anyone, and then the presented set is empty
    /// too.
    pub authority: Option<AuthorityGate>,
}

#[cfg(test)]
mod tests {
    use super::{MAX_IDS_PER_EDGE, cell_ids, ids_cell};

    #[test]
    fn an_id_cell_is_a_count_byte_then_little_endian_ids() {
        assert_eq!(ids_cell(&[]), vec![0]);
        assert_eq!(
            ids_cell(&[3, 0x0102]),
            vec![2, 3, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(cell_ids(&ids_cell(&[3, 9])), Some(vec![3, 9]));
    }

    #[test]
    fn bytes_that_are_not_exactly_one_cell_are_refused() {
        // No count byte, a count with no ids behind it, a cell cut
        // short, a count past the cap, and trailing bytes.
        assert_eq!(cell_ids(&[]), None);
        assert_eq!(cell_ids(&[1]), None);
        assert_eq!(cell_ids(&ids_cell(&[7])[..8]), None);
        let over = u8::try_from(MAX_IDS_PER_EDGE + 1).unwrap();
        let mut cell = vec![over];
        cell.extend(std::iter::repeat_n(0u8, usize::from(over) * 8));
        assert_eq!(cell_ids(&cell), None);
        let mut trailing = ids_cell(&[7]);
        trailing.push(0);
        assert_eq!(cell_ids(&trailing), None);
    }

    #[test]
    fn a_repeated_id_is_refused() {
        assert_eq!(cell_ids(&ids_cell(&[7, 7])), None);
        assert_eq!(cell_ids(&ids_cell(&[1, 2, 1])), None);
    }
}
