//! Shared across the builder's lanes: admitting a built graph as the
//! tree of one leaf the chain would carry it as.
#![allow(dead_code)] // shared between test binaries; each uses a subset

use hyperscale_vm_effects::{
    AdmissionError, Admitted, ChainRecords, EnvelopeTree, Hasher, Intent, IntentHeader,
    ManifestGraph, ResourceMeta, admit_tree,
};
use hyperscale_vm_types::{NetworkId, PrincipalAddr};

/// Any window; nothing here validates one against a clock.
pub const HEADER: IntentHeader = IntentHeader {
    network: NetworkId(242),
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

/// A tree of one leaf over `graph`: acting as `account`, attested by
/// `attested_by`, presenting `records`.
pub fn leaf_tree(
    graph: &ManifestGraph,
    account: PrincipalAddr,
    attested_by: &[PrincipalAddr],
    records: &[ResourceMeta],
) -> EnvelopeTree {
    EnvelopeTree {
        root: Intent {
            attested_by: attested_by.to_vec(),
            ..Intent::leaf(HEADER, account, graph.clone())
        },
        instances: Vec::new(),
        resources: records.to_vec(),
    }
}

/// Admit `graph` as a tree of one leaf acting as `account`, attested by
/// that account's own key and presenting nothing.
pub fn admit_leaf(
    graph: &ManifestGraph,
    account: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    admit_leaf_presenting(graph, account, &[account], chain, &[], hasher)
}

/// As [`admit_leaf`], attested by `attested_by` and presenting
/// `records`.
pub fn admit_leaf_presenting(
    graph: &ManifestGraph,
    account: PrincipalAddr,
    attested_by: &[PrincipalAddr],
    chain: &dyn ChainRecords,
    records: &[ResourceMeta],
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let tree = leaf_tree(graph, account, attested_by, records);
    admit_tree(&tree, tree.hash(hasher), chain, hasher)
}
