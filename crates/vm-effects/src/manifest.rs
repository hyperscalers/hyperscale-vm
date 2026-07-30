//! The manifest as routing consumes it: typed invocation nodes in
//! topological order, with value flows bound as literals or as edges
//! carrying a static resource type.
//!
//! The graph's full form — typed edges with single-producer/single-consumer
//! linearity and constraint annotations — is admission's concern. Routing
//! reads only what signatures evaluate over: each node's target, method, and
//! bound inputs. Amounts are dynamic; types are static.

use crate::hash::{Hash32, Hasher};
use crate::types::{Address, Value};

/// One bound argument of an invocation node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeInput {
    /// A literal from the signed envelope.
    Literal(Value),
    /// An inbound value edge from an earlier node's output. Routing sees
    /// only the edge's static resource type.
    Edge {
        /// The producing node's index; must be earlier than the consumer.
        source: u32,
        /// The resource type the edge carries.
        resource: Address,
    },
}

/// A method invocation node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The target instance, named in the manifest — dynamic dispatch
    /// through state does not exist.
    pub target: Address,
    /// The method to invoke on the target.
    pub method: String,
    /// The node's bound inputs, in the method's parameter order.
    pub inputs: Vec<NodeInput>,
}

/// A manifest: invocation nodes in topological order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The invocation nodes; an edge's source index is always smaller than
    /// its consumer's.
    pub nodes: Vec<Node>,
}

/// The manifest's identity: what fresh-ID derivation and transaction dedup
/// key on. Computed through the hasher seam over the in-memory graph, so
/// the eventual wire encoding can change beneath it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestHash(pub Hash32);

const DOMAIN_NODE: &[u8] = b"hyperscale-vm/manifest-node";
const DOMAIN_MANIFEST: &[u8] = b"hyperscale-vm/manifest";

impl Manifest {
    /// Hash the manifest through the hasher seam.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let mut node_hashes = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let mut parts: Vec<Vec<u8>> = Vec::with_capacity(2 + node.inputs.len());
            parts.push(node.target.0.to_vec());
            parts.push(node.method.as_bytes().to_vec());
            for input in &node.inputs {
                let mut bytes = Vec::new();
                match input {
                    NodeInput::Literal(value) => {
                        bytes.push(0);
                        bytes.extend(value.canonical_bytes());
                    }
                    NodeInput::Edge { source, resource } => {
                        bytes.push(1);
                        bytes.extend(source.to_le_bytes());
                        bytes.extend(resource.0);
                    }
                }
                parts.push(bytes);
            }
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            node_hashes.push(hasher.hash(DOMAIN_NODE, &refs));
        }
        let refs: Vec<&[u8]> = node_hashes.iter().map(|hash| hash.0.as_slice()).collect();
        ManifestHash(hasher.hash(DOMAIN_MANIFEST, &refs))
    }
}

#[cfg(test)]
mod tests {
    use super::{Manifest, Node, NodeInput};
    use crate::hash::TestHasher;
    use crate::types::{Address, Value};

    #[test]
    fn hash_covers_every_node_field() {
        let base = Manifest {
            nodes: vec![Node {
                target: Address([1; 16]),
                method: "m".into(),
                inputs: vec![NodeInput::Literal(Value::U64(7))],
            }],
        };
        let mut renamed = base.clone();
        renamed.nodes[0].method = "n".into();
        let mut rebound = base.clone();
        rebound.nodes[0].inputs = vec![NodeInput::Literal(Value::U64(8))];
        let mut retyped = base.clone();
        retyped.nodes[0].inputs = vec![NodeInput::Edge {
            source: 0,
            resource: Address([2; 16]),
        }];

        let h = |m: &Manifest| m.hash(&TestHasher);
        assert_eq!(h(&base), h(&base));
        assert_ne!(h(&base), h(&renamed));
        assert_ne!(h(&base), h(&rebound));
        assert_ne!(h(&base), h(&retyped));
    }
}
