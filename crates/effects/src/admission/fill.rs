//! What stands behind a socket once the tree is resolved: the node or
//! the account that fills it, the intent as the checks read it, and the
//! fill check every intent clears before anything is ordered.

use std::ops::Deref;

use hyperscale_vm_types::{IntentHash, PrincipalAddr};

use super::AdmissionError;
use super::tree::Resolution;
use crate::graph::{Constraint, EdgeRef, ManifestGraph};
use crate::intent::Socket;

/// What fills one socket, followed to the node or the account that
/// ultimately stands behind it.
///
/// The tree resolves every composer's wiring to this before anything
/// is ordered or lowered, so the checker below sees a flat list of
/// intents whose sockets are filled from named nodes — the same view a
/// leaf presents with no sockets at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fill {
    /// A value edge, with the constraints of every socket it passed
    /// through on its way here, each signed by the intent that declared
    /// it. Bound beside the consuming socket's own.
    Value {
        /// The edge, and the intent whose node produces it.
        produced: Produced,
        /// The pass-through constraints.
        through: Vec<Constraint>,
    },
    /// The claim node `node` of `intent` proves.
    Claim {
        /// The proving intent, by its position in the tree.
        intent: u32,
        /// The proving node, in that intent's graph.
        node: u32,
    },
    /// An account the granting intent acts as, granted by the signer
    /// who signed it: the account's shard attests the keys, so the
    /// claim stands before any node runs and the socket it fills waits
    /// on nothing.
    Account(PrincipalAddr),
}

/// One produced value edge, located in the tree: the intent whose
/// graph produces it, and the edge in that graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Produced {
    /// The producing intent, by its position in the tree.
    pub(crate) intent: u32,
    /// The produced edge within that intent's graph.
    pub(crate) edge: EdgeRef,
}

impl Fill {
    /// The node this fill waits on, as the intent and the node in it —
    /// nothing for a grant, whose claim stands before any node runs.
    pub(crate) const fn waits_on(&self) -> Option<(u32, u32)> {
        match self {
            Self::Value { produced, .. } => Some((produced.intent, produced.edge.producer)),
            Self::Claim { intent, node } => Some((*intent, *node)),
            Self::Account(_) => None,
        }
    }
}

/// One intent as the interleave and the fill checks read it: its graph,
/// its sockets, and what the tree resolved behind them.
pub struct Wired<'a> {
    pub(crate) graph: &'a ManifestGraph,
    pub(crate) sockets: &'a [Socket],
    /// What fills this intent's sockets, and where its members' gives
    /// come from, resolved by the tree.
    pub(crate) resolution: &'a Resolution,
}

impl<'a> Wired<'a> {
    /// The fill of `socket`, where the intent declares one.
    pub(crate) fn fill(&self, socket: u32) -> Option<&'a Fill> {
        self.resolution.fills.get(usize::try_from(socket).ok()?)
    }
}

/// One intent as the shared admission checker consumes it: the wired
/// intent, and what admission adds to it.
pub struct IntentView<'a> {
    pub(crate) wired: Wired<'a>,
    /// The accounts this intent acts as: the owners of its nullifiers,
    /// the owners of the `auth` cells its sign-ins are judged against,
    /// and the subjects its signature resolves to.
    pub(crate) accounts: &'a [PrincipalAddr],
    /// The principals whose keys attested this intent.
    ///
    /// Separate from the accounts, and that separation is the whole of
    /// what a sign-in decides: a key reaching for an account it does not
    /// derive is admissible here and refused by that account's own shard,
    /// which is what lets an account's rule name somebody else's key.
    pub(crate) attested_by: &'a [PrincipalAddr],
    /// What this intent's own signer signed: the intent's hash.
    ///
    /// Carried so a cell keyed by a node can be keyed by content that
    /// node's signer chose. A transaction hash covers a whole
    /// composition the composer assembles, which is material a party
    /// other than the cell's owner can grind.
    pub(crate) identity: IntentHash,
    /// When what this intent's signature brought into being stops being
    /// owed: the window its own signer signed plus the artifact grace,
    /// on [`nullifier_expiry_ms`](crate::nullifier_expiry_ms)'s terms. The
    /// other half of the material a node's cells are keyed by, and
    /// carried here for the reason the identity is.
    pub(crate) expiry_ms: u64,
}

impl<'a> Deref for IntentView<'a> {
    type Target = Wired<'a>;

    fn deref(&self) -> &Self::Target {
        &self.wired
    }
}

/// Fills, intent by intent: one per socket, each naming a real source,
/// each of the channel its socket declares. What an intent's own graph
/// and wiring make of its sockets was held by the tree's shape.
pub(super) fn check_bindings(intents: &[&Wired<'_>]) -> Result<(), AdmissionError> {
    for (index, intent) in intents.iter().enumerate() {
        let intent_index = u32::try_from(index).expect("intents are bounded by MAX_INTENTS");
        let fills = &intent.resolution.fills;
        if fills.len() != intent.sockets.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.sockets.len(),
                found: fills.len(),
            });
        }
        for (position, fill) in fills.iter().enumerate() {
            let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
            let unknown = || AdmissionError::UnknownBinding {
                intent: intent_index,
                socket,
            };
            // A fill naming a node is bounded by that intent's graph; a
            // grant names none, and what bounded it was the tree.
            if let Some((source, producer)) = fill.waits_on() {
                let Some(source) = usize::try_from(source)
                    .ok()
                    .and_then(|source| intents.get(source))
                else {
                    return Err(unknown());
                };
                let producer = usize::try_from(producer).unwrap_or(usize::MAX);
                if producer >= source.graph.nodes.len() {
                    return Err(unknown());
                }
            }
            // The fill's channel against the socket's declared one. The
            // tree refuses the mismatch where the wiring is read, so
            // every later destructure over the pair holds by
            // construction; held here too, so the checker does not rest
            // on the resolver alone.
            let declared = &intent.sockets[position];
            let agreed = matches!(
                (declared, fill),
                (Socket::Value { .. }, Fill::Value { .. })
                    | (Socket::Authority(_), Fill::Claim { .. } | Fill::Account(_))
            );
            if !agreed {
                return Err(AdmissionError::SocketKindMismatch {
                    intent: intent_index,
                    socket,
                    declared: match declared {
                        Socket::Value { .. } => "value",
                        Socket::Authority(_) => "authority",
                    },
                    offered: match fill {
                        Fill::Value { .. } => "an edge",
                        Fill::Claim { .. } | Fill::Account(_) => "a proof",
                    },
                });
            }
        }
    }

    Ok(())
}
