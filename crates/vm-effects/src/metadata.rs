//! Package metadata: effect signatures and static call sites, cached by
//! content address.

use std::collections::BTreeMap;

use crate::dsl::{Clause, Expr};
use crate::hash::Hash32;
use crate::types::{Address, Value};

/// A published package's identity: the hash of its artifact, which covers
/// the metadata section, so metadata is immutable with the package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageHash(pub Hash32);

/// A static call site: the callee named by an input-derived address, its
/// method, and the callee's arguments as expressions over the caller's
/// inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    /// The callee instance; must evaluate to an address.
    pub target: Expr,
    /// The callee method.
    pub method: String,
    /// The callee's arguments, bound from the caller's inputs.
    pub args: Vec<Expr>,
}

/// A method's declared access. Its transitive effect set is the fold of its
/// callees' signatures over the static call graph, which is acyclic — a DAG
/// fold, never a fixpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MethodSignature {
    /// The method's own effect clauses.
    pub effects: Vec<Clause>,
    /// The method's static call sites.
    pub calls: Vec<CallSite>,
}

/// Everything routing reads about a published package.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageMetadata {
    /// Effect signatures by method name.
    pub methods: BTreeMap<String, MethodSignature>,
}

/// The content-addressed metadata cache. An entry never invalidates —
/// equal hash means equal artifact — so publishing is idempotent and
/// first-write-wins.
#[derive(Clone, Debug, Default)]
pub struct MetadataCache {
    packages: BTreeMap<PackageHash, PackageMetadata>,
}

impl MetadataCache {
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packages: BTreeMap::new(),
        }
    }

    /// Add a package's metadata under its content address.
    pub fn publish(&mut self, hash: PackageHash, metadata: PackageMetadata) {
        self.packages.entry(hash).or_insert(metadata);
    }

    /// Look up a package's metadata.
    #[must_use]
    pub fn get(&self, hash: PackageHash) -> Option<&PackageMetadata> {
        self.packages.get(&hash)
    }
}

/// An instance's creation-fixed record: its package and its immutable
/// configuration.
///
/// These are locked substates — verified once, cached process-wide — which
/// is what lets routing consult them and stay state-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceMeta {
    /// The package the instance runs.
    pub package: PackageHash,
    /// The instance's creation-fixed configuration fields.
    pub config: Vec<Value>,
}

/// Instance address to creation-fixed record.
#[derive(Clone, Debug, Default)]
pub struct InstanceRegistry {
    instances: BTreeMap<Address, InstanceMeta>,
}

impl InstanceRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
        }
    }

    /// Record an instance's creation-fixed metadata.
    pub fn register(&mut self, address: Address, meta: InstanceMeta) {
        self.instances.entry(address).or_insert(meta);
    }

    /// Look up an instance's creation-fixed metadata.
    #[must_use]
    pub fn get(&self, address: Address) -> Option<&InstanceMeta> {
        self.instances.get(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::{MetadataCache, MethodSignature, PackageHash, PackageMetadata};
    use crate::hash::Hash32;

    #[test]
    fn publish_is_first_write_wins() {
        let hash = PackageHash(Hash32([1; 32]));
        let mut cache = MetadataCache::new();
        let mut first = PackageMetadata::default();
        first.methods.insert("m".into(), MethodSignature::default());
        cache.publish(hash, first.clone());
        cache.publish(hash, PackageMetadata::default());
        assert_eq!(cache.get(hash), Some(&first));
    }
}
