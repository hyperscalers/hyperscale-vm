//! Package identity and the content-addressed metadata cache.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{Address, SubstateKey};

use crate::KERNEL_SLOT_BASE;
use crate::hash::{Hash32, Hasher};
use crate::publish::{CheckedSignature, SignatureError, check_signature};
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

/// Why a record was refused at the cache door.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("method {method:?}: {source}")]
pub struct PublishRefusal {
    /// The method whose signature was refused.
    pub method: String,
    /// The judgment that refused it.
    #[source]
    pub source: SignatureError,
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

    /// Add a package's metadata under its content address, judging every
    /// method's signature at the door.
    ///
    /// The door is what lets every consumer downstream stop re-asking:
    /// admission and routing read signatures out of the cache as
    /// [`CheckedSignature`] witnesses, so a record that never passed the
    /// composed check cannot be behind one.
    ///
    /// # Errors
    ///
    /// [`PublishRefusal`], naming the first refused method.
    pub fn publish(
        &mut self,
        hash: PackageHash,
        metadata: PackageMetadata,
    ) -> Result<(), PublishRefusal> {
        for (name, signature) in &metadata.methods {
            check_signature(signature).map_err(|source| PublishRefusal {
                method: name.clone(),
                source,
            })?;
        }
        self.store(hash, metadata);
        Ok(())
    }

    /// Seed a record past the door's judgment — for fixtures whose
    /// signatures state the one property a test is about rather than the
    /// whole vocabulary. Everything the door guarantees is this caller's
    /// to keep.
    #[cfg(any(test, feature = "testing"))]
    pub fn publish_unchecked(&mut self, hash: PackageHash, metadata: PackageMetadata) {
        self.store(hash, metadata);
    }

    fn store(&mut self, hash: PackageHash, metadata: PackageMetadata) {
        match self.packages.entry(hash) {
            Entry::Vacant(slot) => {
                slot.insert(metadata);
            }
            // The hash is the content address, so a divergent re-publish
            // is a collision or a caller defect; the first record stands
            // either way.
            Entry::Occupied(stored) => {
                debug_assert_eq!(*stored.get(), metadata, "one package hash, two records");
            }
        }
    }

    /// The checked signature of `package`'s `method`.
    ///
    /// The witness is the cache's invariant: everything behind the door
    /// passed the composed signature check when it entered.
    #[must_use]
    pub fn method(&self, package: PackageHash, method: &str) -> Option<CheckedSignature<'_>> {
        self.packages
            .get(&package)?
            .methods
            .get(method)
            .map(CheckedSignature::trusted)
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
    fn publish_is_idempotent() {
        let hash = PackageHash(Hash32([1; 32]));
        let mut cache = MetadataCache::new();
        let mut record = PackageMetadata::default();
        record
            .methods
            .insert("m".into(), MethodSignature::default());
        cache.publish(hash, record.clone()).expect("publishes");
        cache.publish(hash, record.clone()).expect("republishes");
        assert_eq!(cache.get(hash), Some(&record));
    }
}
