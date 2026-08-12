//! Preflight: the chain's whole verdict on a transaction, before it is
//! signed.
//!
//! Everything downstream of the signed form is a pure function of the form
//! and content-addressed metadata — that is what lets every node reach the
//! identical verdict, and it lets a client reach it too. Nothing here
//! computes anything new. Admission, routing, the footprint schedule and
//! the declared authorities all exist already; this composes them into one
//! call and one report, so a wallet asks its question once instead of
//! learning the shape of four APIs.
//!
//! What comes back is a report, never a judgement. Whether to sign is the
//! holder's, and a report that names an unsatisfiable authority still
//! describes the transaction rather than refusing to.
//!
//! The network word is an input. A report names addresses, an address's
//! text form is scoped to the network it is read on, and there is no
//! default to fall back on — so it is supplied where the report is asked
//! for, and a word the encoding refuses fails once here rather than at
//! every address.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{
    Accessibility, Address, AdmissionError, Admitted, CallTarget, EnvelopeTree, Hasher,
    InstanceRegistry, Manifest, ManifestGraph, ManifestHash, MetadataCache, NetworkWord,
    PrincipalAddr, RouteError, Routing, SchemeId, ShardId, ShardResolver, SubintentRecord,
    TextError, Value, admit, admit_tree, declared_work, footprint, route, route_tree,
    signature_work,
};

/// Why a transaction could not be preflighted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreflightError {
    /// The signed form is one admission would refuse.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    /// The admitted form is one routing would refuse.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// A network word no address can be named under.
    #[error(transparent)]
    Network(#[from] TextError),
}

/// Whose signature naming one node requires.
///
/// Read off the target package's declared [`Accessibility`], which is the
/// only thing that knows: an address is a hash, so nothing about a target
/// can be read from the address itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Anyone may name this method on this target. What the caller
    /// supplies was gated wherever it was obtained.
    Anyone,
    /// A signature this principal's address derives.
    Signature(PrincipalAddr),
    /// The target's own authority, which its address derives from no key.
    /// An instance is owned by nobody, so a method gated on its own
    /// authority cannot be named on it by anyone.
    TargetHasNoKey,
    /// A configured authority slot naming no principal — past the
    /// instance's configuration, or holding something that is not a
    /// principal address.
    NoPrincipalConfigured {
        /// The configuration slot the signature named.
        slot: u32,
    },
}

/// What one node of the flattened manifest requires of a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Required {
    /// The node's index in the flattened manifest.
    pub node: u32,
    /// The instance the method runs on.
    pub target: Address,
    /// The method named.
    pub method: String,
    /// Whose authority naming it requires.
    pub authority: Authority,
}

/// Everything a holder can know before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The network the text forms in [`named`](Self::named) are read on.
    pub network: NetworkWord,
    /// The admitted form: the lowered manifest and the identity every
    /// fresh derivation — and every signature — binds to.
    pub admitted: Admitted,
    /// The routing: per-shard declared effects, evaluated frames, the
    /// lowered call list, and the static call graph.
    pub routing: Routing,
    /// What each participating shard's declaration costs on the footprint
    /// schedule.
    pub footprints: BTreeMap<ShardId, u64>,
    /// What naming each node requires of a signature, in node order.
    pub authority: Vec<Required>,
    /// The nullifier record of every bound subintent, empty for a bare
    /// graph.
    pub subintents: Vec<SubintentRecord>,
    /// Every address the report names, in this network's text form.
    pub named: BTreeMap<Address, String>,
}

impl Report {
    /// The lowered routing manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        self.admitted.manifest()
    }

    /// The identity a signature covers.
    #[must_use]
    pub const fn identity(&self) -> ManifestHash {
        self.admitted.identity()
    }

    /// The shards this transaction touches.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.footprints.keys().copied()
    }

    /// The whole declared footprint: the sum over participating shards,
    /// because the reservation is taken once against all of it rather than
    /// per shard.
    #[must_use]
    pub fn footprint(&self) -> u64 {
        self.footprints
            .values()
            .fold(0, |total, shard| total.saturating_add(*shard))
    }

    /// What this transaction costs a block at `gas_limit` under
    /// `schemes`: the fixed carry charge, the footprint it declares, the
    /// ceiling it would sign for its own execution, and what the
    /// signatures it will carry cost to check.
    ///
    /// `schemes` names one entry per signature the envelope will bind —
    /// the composer's and each bound subintent signer's. Neither it nor
    /// the ceiling can be read off the graph: both are the signer's own
    /// choices, so both are asked for here rather than reported.
    #[must_use]
    pub fn declared_work(&self, gas_limit: u64, schemes: &[SchemeId]) -> u64 {
        let signatures = schemes.iter().fold(0u64, |total, scheme| {
            total.saturating_add(signature_work(*scheme))
        });
        declared_work(self.footprint(), gas_limit, signatures)
    }

    /// Every signature the transaction needs: what its nodes' declared
    /// access requires, plus the signer of every bound subintent.
    #[must_use]
    pub fn signers(&self) -> BTreeSet<PrincipalAddr> {
        self.authority
            .iter()
            .filter_map(|required| match required.authority {
                Authority::Signature(principal) => Some(principal),
                Authority::Anyone
                | Authority::TargetHasNoKey
                | Authority::NoPrincipalConfigured { .. } => None,
            })
            .chain(self.subintents.iter().map(|record| record.signer))
            .collect()
    }

    /// The nodes whose access no signature can satisfy. A transaction
    /// carrying one cannot be made to succeed by signing it differently.
    pub fn unsatisfiable(&self) -> impl Iterator<Item = &Required> {
        self.authority.iter().filter(|required| {
            matches!(
                required.authority,
                Authority::TargetHasNoKey | Authority::NoPrincipalConfigured { .. }
            )
        })
    }

    /// An address the report names, in this network's text form.
    #[must_use]
    pub fn text(&self, address: impl Into<Address>) -> Option<&str> {
        self.named.get(&address.into()).map(String::as_str)
    }
}

/// The whole verdict on a bare graph, before signing.
///
/// # Errors
///
/// [`PreflightError::Admission`] or [`PreflightError::Route`] for a
/// transaction the chain would refuse, and [`PreflightError::Network`] for
/// a network word no address can be named under.
pub fn preflight(
    graph: &ManifestGraph,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
    network: &str,
) -> Result<Report, PreflightError> {
    let admitted = admit(graph, cache, instances, hasher)?;
    let routing = route(&admitted, cache, instances, hasher, shards)?;
    report(admitted, routing, Vec::new(), instances, cache, network)
}

/// The same verdict on a composed envelope, whose subintent records name
/// the nullifier each one spends.
///
/// # Errors
///
/// As [`preflight`].
pub fn preflight_tree(
    tree: &EnvelopeTree,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
    network: &str,
) -> Result<Report, PreflightError> {
    let identity = tree.hash(hasher);
    let admitted = admit_tree(tree, identity, cache, instances, hasher)?;
    let routing = route_tree(&admitted, cache, instances, hasher, shards)?;
    report(
        admitted.admitted,
        routing,
        admitted.subintents,
        instances,
        cache,
        network,
    )
}

/// Assemble the report both entry points answer with.
fn report(
    admitted: Admitted,
    routing: Routing,
    subintents: Vec<SubintentRecord>,
    instances: &InstanceRegistry,
    cache: &MetadataCache,
    network: &str,
) -> Result<Report, PreflightError> {
    let footprints = routing
        .per_shard
        .iter()
        .map(|(shard, declared)| (*shard, footprint(declared)))
        .collect();

    let mut authority = Vec::with_capacity(admitted.manifest().nodes.len());
    for (index, node) in admitted.manifest().nodes.iter().enumerate() {
        let node_index = u32::try_from(index).unwrap_or(u32::MAX);
        authority.push(Required {
            node: node_index,
            target: node.target,
            method: node.method.clone(),
            authority: required_authority(node.target, &node.method, instances, cache),
        });
    }

    // Every address the report names, rendered once so a network word the
    // encoding refuses fails here rather than at a display seam.
    let mut named = BTreeMap::new();
    let addresses = authority
        .iter()
        .map(|required| required.target)
        .chain(
            authority
                .iter()
                .filter_map(|required| match required.authority {
                    Authority::Signature(principal) => Some(principal.address()),
                    _ => None,
                }),
        )
        .chain(subintents.iter().map(|record| record.signer.address()));
    for address in addresses {
        if let Entry::Vacant(slot) = named.entry(address) {
            slot.insert(address.to_text(network)?);
        }
    }

    Ok(Report {
        network: NetworkWord(network.to_owned()),
        admitted,
        routing,
        footprints,
        authority,
        subintents,
        named,
    })
}

/// Whose authority naming `method` on `target` requires.
///
/// The target resolved at admission, so anything unresolvable here is a
/// manifest that could not have been admitted — reported as an authority
/// nothing satisfies rather than by refusing a report that already stands.
fn required_authority(
    target: Address,
    method: &str,
    instances: &InstanceRegistry,
    cache: &MetadataCache,
) -> Authority {
    let declared = CallTarget::try_from(target)
        .ok()
        .and_then(|target| instances.get(target))
        .and_then(|meta| Some((meta, cache.get(meta.package)?)))
        .and_then(|(meta, package)| Some((meta, package.methods.get(method)?)));
    let Some((meta, signature)) = declared else {
        return Authority::TargetHasNoKey;
    };
    match signature.accessibility {
        Accessibility::Public => Authority::Anyone,
        // A principal's address derives from its key material, so its own
        // authority is a signature. Every other class derives from a hash
        // of what it is, and nothing signs for that.
        Accessibility::RequiresTargetAuth => match CallTarget::try_from(target) {
            Ok(CallTarget::Principal(principal)) => Authority::Signature(principal),
            _ => Authority::TargetHasNoKey,
        },
        Accessibility::RequiresConfiguredAuth(slot) => usize::try_from(slot)
            .ok()
            .and_then(|slot| meta.config.get(slot))
            .and_then(|value| match value {
                Value::Address(address) => PrincipalAddr::try_from(*address).ok(),
                _ => None,
            })
            .map_or(Authority::NoPrincipalConfigured { slot }, |principal| {
                Authority::Signature(principal)
            }),
    }
}
