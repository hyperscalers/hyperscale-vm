//! What the chain answers for, as a seam rather than a collection.
//!
//! Admission resolves a call through two records: the instance the
//! target names, and the package that instance runs. Both are committed
//! state — a component's record is the `CONFIG` leaf its instantiation
//! sealed, and a package's metadata rides the artifact its publish cell
//! holds — so where they are *kept* is the caller's business and not the
//! vocabulary's.
//!
//! [`ChainRecords`] states only what admission has to ask, on the terms
//! [`Substates`] already sets for durable state: the caller decides
//! whether an answer comes from a genesis-static map, a cell read at an
//! anchored height, a cache of records fetched from other shards, or any
//! layering of those. [`Records`] is the in-memory implementation the
//! composer and the corpus hold; [`Composed`] is the per-envelope
//! layering that puts a transaction's own records in front of one.
//!
//! Answers are `Arc`s rather than borrows because an implementation need
//! not be a live map it can lend a reference from — an evicting cache and
//! a state read can neither. `Substates` returns cell bytes owned for the
//! same reason; a package's metadata is too big to copy per lookup, so
//! the handle is shared instead of cloned.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_types::{Address, CallTarget};

use crate::hash::Hasher;
use crate::instance::{InstanceMeta, InstanceRegistry};
use crate::metadata::{MetadataCache, PackageHash, PackageMetadata};

/// The records the chain answers for, as one node holds them.
///
/// # Stability
///
/// One derivation asks this many times and has to get one world's
/// answers throughout: routing is a function of what the chain holds,
/// and an implementation that changed under a derivation would let one
/// node route an envelope two ways. An implementation whose contents can
/// move pins a view for the caller's use — the contract a substate view
/// already keeps by anchoring at a height.
pub trait ChainRecords: Send + Sync {
    /// The creation-fixed record serving a call target, or `None` where
    /// the chain answers for no such component.
    ///
    /// A principal resolves by its address class alone — its address
    /// derives from a key, so there is no record to look up — and a
    /// component by the record its address derives.
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>>;

    /// A published package's metadata, or `None` where this node has not
    /// seen the package publish.
    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>>;
}

impl<T: ChainRecords + ?Sized> ChainRecords for &T {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        T::instance(self, target)
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        T::package(self, hash)
    }
}

impl<T: ChainRecords + ?Sized> ChainRecords for Arc<T> {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        T::instance(self, target)
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        T::package(self, hash)
    }
}

/// The in-memory implementation: a package cache and an instance
/// registry side by side.
///
/// What a composer holds, what a test builds, and what a cold start
/// seeds — every case where the whole answer fits in memory and nothing
/// pages. A node serving a live chain implements the trait over its own
/// state instead.
#[derive(Clone, Debug, Default)]
pub struct Records {
    /// The packages this world has published.
    pub packages: MetadataCache,
    /// The instances it answers for.
    pub instances: InstanceRegistry,
}

impl Records {
    /// An empty world.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packages: MetadataCache::new(),
            instances: InstanceRegistry::new(),
        }
    }

    /// A world over an existing cache and registry.
    #[must_use]
    pub const fn from_parts(packages: MetadataCache, instances: InstanceRegistry) -> Self {
        Self {
            packages,
            instances,
        }
    }
}

impl ChainRecords for Records {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        self.instances.record(target)
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        self.packages.record(hash)
    }
}

/// A transaction's own records, over what the chain answers for.
///
/// The base is asked first, so a presented record can never displace a
/// committed one — the rule is the order rather than a check, and a
/// record naming a component the chain already holds resolves to the
/// chain's answer whatever the envelope says.
///
/// Which components the chain happens to hold does not otherwise enter
/// it: an envelope means the same thing wherever it is judged, so what
/// a presented record may stand for is decided by the node it sits
/// beside and not by the state around it.
pub struct Composed<'a> {
    base: &'a dyn ChainRecords,
    presented: BTreeMap<Address, Arc<InstanceMeta>>,
}

impl<'a> Composed<'a> {
    /// `base` with `records` layered behind it, each keyed at exactly the
    /// address its own contents derive.
    #[must_use]
    pub fn new(base: &'a dyn ChainRecords, records: &[InstanceMeta], hasher: &dyn Hasher) -> Self {
        let presented = records
            .iter()
            .map(|meta| (meta.address(hasher).address(), Arc::new(meta.clone())))
            .collect();
        Self { base, presented }
    }
}

impl ChainRecords for Composed<'_> {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        self.base.instance(target).or_else(|| match target {
            CallTarget::Principal(_) => None,
            CallTarget::Component(address) => self.presented.get(&address.address()).cloned(),
        })
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        self.base.package(hash)
    }
}
