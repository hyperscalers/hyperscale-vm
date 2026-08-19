//! Package identity and the content-addressed metadata cache.

use std::collections::BTreeMap;

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{Address, SubstateKey};

use crate::KERNEL_SLOT_BASE;
use crate::hash::{Hash32, Hasher};
use crate::signature::MethodSignature;
use crate::types::{SlotId, child_key};

/// A published package's identity: the hash of its artifact, which covers
/// the metadata section, so metadata is immutable with the package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct PackageHash(pub Hash32);

const DOMAIN_PACKAGE: &[u8] = b"hyperscale-vm/package";

/// The content address of a package artifact — the identity the metadata
/// cache keys on and instances bind to.
#[must_use]
pub fn package_hash(hasher: &dyn Hasher, artifact: &[u8]) -> PackageHash {
    PackageHash(hasher.hash(DOMAIN_PACKAGE, &[artifact]))
}

/// The reserved role a publisher's package cells key under.
///
/// In the kernel's own band at the top of the role space, above anything
/// the protocol vocabulary or a package numbers into, so the cell is
/// reachable by the publish path and by nothing else.
pub const PACKAGE_SLOT: SlotId = SlotId(0xFFFE);

const _: () = assert!(PACKAGE_SLOT.0 >= KERNEL_SLOT_BASE);

/// Where `publisher`'s copy of the package addressed by `package` lives.
///
/// Keyed by content address under the publisher, so republishing the
/// same artifact is the same cell — which is what makes publishing
/// idempotent rather than a conflict.
#[must_use]
pub fn package_key(
    hasher: &dyn Hasher,
    publisher: impl Into<Address>,
    package: PackageHash,
) -> SubstateKey {
    child_key(hasher, publisher, PACKAGE_SLOT, &[package.0.0.to_vec()])
}

/// Everything routing reads about a published package.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct PackageMetadata {
    /// Effect signatures by method name.
    pub methods: BTreeMap<String, MethodSignature>,
    /// The package's event names, in the index order a receipt event's
    /// type refers to.
    ///
    /// Nothing on the execution path reads this: an event carries the
    /// index, and the kernel bounds it without resolving it. The table is
    /// what lets a consumer name what it read, and it can only mean one
    /// thing because a package is content-addressed and immutable.
    pub events: Vec<String>,
    /// The package's error names, in the index order a declined
    /// invocation's code refers to.
    ///
    /// The same shape as [`events`](Self::events) and for the same
    /// reasons: the kernel bounds a returned code without resolving it,
    /// the table is what turns that code into something a wallet can
    /// render, and immutability is what stops an index coming to mean
    /// something else. Empty for a package whose methods cannot decline.
    pub errors: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
