//! Package identity and the content-addressed metadata cache.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::{Arc, LazyLock};

pub use hyperscale_hbor::MAX_SHAPE_DEPTH;
use hyperscale_hbor::{
    Hbor, HborShape, ReadError, ShapeRegistry, ShapeTable, ShapeValue, TypeShape,
};
use hyperscale_vm_types::{
    Address, CallTarget, ComponentAddr, Event, NativeAddr, PackageAddr, PrincipalAddr,
    ResourceAddr, SubstateKey,
};

use crate::KERNEL_SLOT_BASE;
use crate::hash::{Hash32, Hasher};
use crate::publish::{
    CheckedMetadata, CheckedSignature, MetadataError, SignatureError, check_signature, seals,
};
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
///
/// The two scopes the publish gate judges in, so a refusal says which
/// question the record failed rather than only that it did.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublishRefusal {
    /// One method's signature was refused.
    #[error("method {method:?}: {source}")]
    Method {
        /// The method whose signature was refused.
        method: String,
        /// The judgment that refused it.
        #[source]
        source: SignatureError,
    },
    /// The package's tables, read together, say more than one thing.
    #[error(transparent)]
    Package(#[from] MetadataError),
}

/// The names the protocol's own types hold, under the shapes those types
/// give them.
///
/// Built by asking them rather than written down, so there is no second
/// statement of what an address looks like for this one to drift from.
static RESERVED_SHAPES: LazyLock<ShapeTable> = LazyLock::new(|| {
    let mut registry = ShapeRegistry::new();
    Address::shape(&mut registry);
    PrincipalAddr::shape(&mut registry);
    ComponentAddr::shape(&mut registry);
    PackageAddr::shape(&mut registry);
    ResourceAddr::shape(&mut registry);
    NativeAddr::shape(&mut registry);
    CallTarget::shape(&mut registry);
    registry.into_types()
});

/// The shape the protocol pins `name` to, for a name it pins at all.
///
/// What makes a reserved name a fact rather than a convention: a package
/// binding one to anything else is refused at the door, so a consumer
/// that finds `address` in a package's types has found an address.
#[must_use]
pub fn reserved_shape(name: &str) -> Option<&'static TypeShape> {
    RESERVED_SHAPES.get(name)
}

/// The shape of state a declared slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum SlotKind {
    /// One leaf under the slot.
    Cell,
    /// A family of leaves, each under material a body names. The key is
    /// hashed into the child key, so a consumer reads a leaf it can
    /// name and cannot enumerate the family.
    Keyed,
    /// An ordered collection: entries under an order key.
    Ordered,
    /// An unordered collection: entries under a hashed key.
    Unordered,
}

/// What one leaf holds.
///
/// A leaf is empty or exactly one of these: absence is no bytes at all,
/// and what an empty leaf means is the element's own business — zero for
/// a number, nothing stored for a record.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum LeafForm {
    /// One canonical encoding of this shape.
    Value(TypeShape),
    /// The leaf's own bytes, delimited by the leaf and by nothing inside
    /// it.
    ///
    /// What a byte parameter and a stored rule both reach a cell as. The
    /// encoding's own byte string carries a length, and these do not:
    /// the substate is the frame, so the bytes inside it need no second
    /// one.
    Bytes,
}

/// One declared state slot: what it is called, what shape of state it
/// is, and what its leaves hold.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct SlotShape {
    /// The field's name, as its author spelled it.
    pub name: String,
    /// What shape of state the slot holds.
    pub kind: SlotKind,
    /// What one leaf holds.
    pub element: LeafForm,
}

/// How a crate lists the packages it declares: each by the name its
/// artifacts and snapshots are filed under, with the function that
/// traces its declaration.
///
/// The shape rather than the list — which packages there are is each
/// crate's own business, and this is only what "a package, by name, with
/// what it declares" is spelled as so that a consumer sweeping several
/// crates sweeps one shape.
pub type DeclaredPackages = &'static [(&'static str, fn() -> PackageMetadata)];

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
    /// Every type this package declares, by the name the tables above
    /// index it under.
    ///
    /// A shape says how to decode a payload, never how to render one: it
    /// is what turns an event's bytes into named fields, and a cell's
    /// into a record. Nothing on the execution path reads it, on the same
    /// terms as the name tables — the kernel bounds an index without
    /// resolving it, and resolving is the consumer's business.
    ///
    /// Protocol names resolve to the protocol's shapes, which the door
    /// pins: `address` is an address in every package that declares one.
    pub types: ShapeTable,
    /// The instance configuration's field names, in the order the
    /// creation-fixed record holds them.
    ///
    /// The record is a list of [`Value`](crate::types::Value)s, and a
    /// value carries its own kind — so what a consumer cannot recover
    /// from the leaf is the name, and the name is all this adds. The
    /// same shape as [`events`](Self::events) and for the same reason: a
    /// signature indexes a field positionally, and immutability is what
    /// stops a position coming to mean something else.
    pub config: Vec<String>,
    /// The component's state, by the slot its leaves sit under.
    ///
    /// What gets a consumer from a substate key to a type: a slot
    /// number is all a stored leaf carries about what it is, and the
    /// tables above describe types without saying which cell holds one.
    ///
    /// Keyed by the slot rather than by position, because `#[slot(n)]`
    /// is the author's own number and a system package pins every one of
    /// them — a positional table would renumber under an in-place
    /// upgrade, which is the thing pinning exists to prevent.
    pub state: BTreeMap<SlotId, SlotShape>,
}

impl PackageMetadata {
    /// Read an event's payload against the shape its type declares.
    ///
    /// The whole of what the tables are for: an index becomes a name,
    /// the name becomes a shape, and the shape turns opaque bytes into
    /// named fields. `None` where the index names no declared type.
    ///
    /// This must be the metadata of the package the emitter answers to.
    /// An index is a number in that package's own table, and nothing
    /// here maps an emitter back to the package behind it — so an event
    /// from elsewhere whose index happens to be in range reads against
    /// the wrong shape rather than against none. Pairing an emitter with
    /// the package that answers for it is the caller's.
    ///
    /// # Errors
    ///
    /// [`ReadError`] for a payload the declared shape does not describe.
    #[must_use]
    pub fn read_event(&self, event: &Event) -> Option<Result<(&str, ShapeValue), ReadError>> {
        let name = self.events.get(usize::try_from(event.event_type).ok()?)?;
        let shape = self.types.get(name)?;
        Some(
            shape
                .read(&event.payload, &self.types)
                .map(|value| (name.as_str(), value)),
        )
    }

    /// Read a state leaf against the shape its slot declares.
    ///
    /// `Ok(None)` for an empty leaf, which is the absence every element
    /// reads as its own zero. `None` where the slot is not one this
    /// package declares.
    ///
    /// As [`read_event`](Self::read_event), this must be the metadata of
    /// the package the leaf's owner answers to: a slot is that package's
    /// own number.
    ///
    /// # Errors
    ///
    /// [`ReadError`] for bytes the declared shape does not describe.
    #[must_use]
    pub fn read_leaf(
        &self,
        slot: SlotId,
        leaf: &[u8],
    ) -> Option<Result<Option<ShapeValue>, ReadError>> {
        Some(self.read_form(&self.state.get(&slot)?.element, leaf))
    }

    /// Read an instance's data cell against the shape its mark declares.
    ///
    /// The mark is the material a signature's own claim names, and it is
    /// the name the mark's schema is declared under — so a consumer that
    /// found a resource in a signature can read what its instances hold.
    ///
    /// As [`read_event`](Self::read_event), this must be the metadata of
    /// the package that mints under the mark.
    ///
    /// # Errors
    ///
    /// [`ReadError`] for bytes the declared shape does not describe.
    #[must_use]
    pub fn read_instance(
        &self,
        mark: &[u8],
        cell: &[u8],
    ) -> Option<Result<Option<ShapeValue>, ReadError>> {
        let name = core::str::from_utf8(mark).ok()?;
        Some(self.read_value(self.types.get(name)?, cell))
    }

    /// One leaf, read against the form it holds.
    fn read_form(&self, form: &LeafForm, leaf: &[u8]) -> Result<Option<ShapeValue>, ReadError> {
        match form {
            LeafForm::Value(shape) => self.read_value(shape, leaf),
            // The substate frames these, so what it holds is the whole of
            // them and an empty one is no bytes at all.
            LeafForm::Bytes if leaf.is_empty() => Ok(None),
            LeafForm::Bytes => Ok(Some(ShapeValue::ByteArray(leaf.to_vec()))),
        }
    }

    /// One leaf's bytes, read against the shape declared for them.
    ///
    /// An empty leaf is the absence every element reads as its own zero:
    /// nothing stored for a record, and zero for a number.
    fn read_value(&self, shape: &TypeShape, leaf: &[u8]) -> Result<Option<ShapeValue>, ReadError> {
        if leaf.is_empty() {
            return Ok(None);
        }
        shape.read(leaf, &self.types).map(Some)
    }

    /// The method that makes a component of this package actual, and the
    /// name it publishes under.
    ///
    /// Found by what it declares rather than by what it is called: the
    /// seal is the method writing the component's own configuration
    /// leaf, which is the same question the publish gate asks before it
    /// admits the package at all. A caller looking the name up would be
    /// a second answer, and a hand-written package that spelled the name
    /// differently would publish fine and compose nowhere.
    ///
    /// `None` for a package serving principals, which has no creation to
    /// finish.
    #[must_use]
    pub fn seal(&self) -> Option<(&str, &MethodSignature)> {
        self.methods
            .iter()
            .find(|(_, signature)| seals(signature))
            .map(|(name, signature)| (name.as_str(), signature))
    }
}

/// The content-addressed metadata cache. An entry never invalidates —
/// equal hash means equal artifact — so publishing is idempotent and
/// first-write-wins.
#[derive(Clone, Debug, Default)]
pub struct MetadataCache {
    packages: BTreeMap<PackageHash, Arc<PackageMetadata>>,
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
    /// Both scopes, because a package is more than its methods one at a
    /// time. What two of them say a slot holds is a question only the
    /// whole metadata answers, and a record admitted without it asked
    /// would let a balance be written as bytes and debited as value.
    ///
    /// # Errors
    ///
    /// [`PublishRefusal`], naming the first refused method or the table
    /// the package disagrees with itself about.
    pub fn publish(
        &mut self,
        hash: PackageHash,
        metadata: PackageMetadata,
    ) -> Result<(), PublishRefusal> {
        for (name, signature) in &metadata.methods {
            check_signature(signature).map_err(|source| PublishRefusal::Method {
                method: name.clone(),
                source,
            })?;
        }
        self.store(hash, CheckedMetadata::judge(metadata)?);
        Ok(())
    }

    /// Seed a record past the door's judgment — for fixtures whose
    /// signatures state the one property a test is about rather than the
    /// whole vocabulary. Everything the door guarantees is this caller's
    /// to keep.
    #[cfg(any(test, feature = "testing"))]
    pub fn publish_unchecked(&mut self, hash: PackageHash, metadata: PackageMetadata) {
        self.store(hash, CheckedMetadata::trusted(metadata));
    }

    fn store(&mut self, hash: PackageHash, checked: CheckedMetadata) {
        let metadata = checked.into_metadata();
        match self.packages.entry(hash) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(metadata));
            }
            // The hash is the content address, so a divergent re-publish
            // is a collision or a caller defect; the first record stands
            // either way.
            Entry::Occupied(stored) => {
                debug_assert_eq!(**stored.get(), metadata, "one package hash, two records");
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
        self.packages.get(&hash).map(AsRef::as_ref)
    }

    /// The shared handle to a package's metadata — what this cache
    /// answers a [`ChainRecords`](crate::records::ChainRecords) lookup
    /// with.
    #[must_use]
    pub fn record(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        self.packages.get(&hash).map(Arc::clone)
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

    /// The door asks what only the whole metadata answers.
    ///
    /// An event named with no shape is a package-scope disagreement and
    /// nothing else: every signature here passes on its own, so a door
    /// that judged only signatures would let it through and leave the
    /// verdict to whichever consumer happened to decode the artifact.
    #[test]
    fn a_record_whose_tables_disagree_is_refused_at_the_door() {
        let hash = PackageHash(Hash32([2; 32]));
        let mut record = PackageMetadata::default();
        record.events.push("paid".into());
        let refusal = MetadataCache::new()
            .publish(hash, record)
            .expect_err("an event with no shape opens to nothing");
        assert!(
            matches!(
                refusal,
                PublishRefusal::Package(MetadataError::EventWithoutShape { .. })
            ),
            "unexpected refusal: {refusal:?}"
        );
    }
}
