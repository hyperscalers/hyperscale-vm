//! Package identity and the content-addressed metadata cache.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use hyperscale_hbor::{
    DecodeError, Hbor, HborBound, HborShape, Name, NodeId, ShapeNode, ShapeTable, ShapeValue,
};
use hyperscale_vm_types::{
    AMOUNT_CELL_BYTES, Address, CallTarget, ComponentAddr, Event, MAX_SLOT_WIDTH, NativeAddr,
    PackageAddr, PrincipalAddr, ResourceAddr, SubstateKey,
};

use crate::KERNEL_SLOT_BASE;
use crate::auth::Authority;
use crate::dsl::Expr;
use crate::hash::{Hash32, Hasher};
use crate::publish::{
    CheckedMetadata, CheckedSignature, MetadataError, SignatureError, check_signature, seals,
};
use crate::signature::MethodSignature;
use crate::types::{SlotId, child_key, package_address};

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

/// Where the package addressed by `package` lives.
///
/// Under the package's own address, which is a function of the very
/// bytes the cell holds and of nothing else. So one artifact is one cell
/// network-wide however many publishers offer it — publishing is
/// idempotent rather than a conflict — and a request naming a package
/// names its key, with no index between the two. The shard owning that
/// prefix is the one obliged to keep it.
#[must_use]
pub fn package_key(hasher: &dyn Hasher, package: PackageHash) -> SubstateKey {
    child_key(hasher, package_address(hasher, package), PACKAGE_SLOT, &[])
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
        method: Name,
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
/// The types' own nodes rather than a second statement, so there is
/// nothing here for what an address looks like to drift from.
const RESERVED_SHAPES: &[&ShapeNode] = &[
    Address::NODE,
    PrincipalAddr::NODE,
    ComponentAddr::NODE,
    PackageAddr::NODE,
    ResourceAddr::NODE,
    NativeAddr::NODE,
    CallTarget::NODE,
];

/// The named node the protocol pins `name` to, for a name it pins at all.
///
/// What makes a reserved name a fact rather than a convention: a package
/// binding one to anything else is refused at the door, so a consumer
/// that finds `address` in a package's types has found an address.
#[must_use]
pub fn reserved_shape(name: &str) -> Option<&'static ShapeNode> {
    RESERVED_SHAPES
        .iter()
        .copied()
        .find(|node| matches!(node, ShapeNode::Named { name: held, .. } if *held == name))
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

/// One declared state slot: what it is called, what shape of state it
/// is, and what its leaves hold.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct SlotShape {
    /// The field's name, as its author spelled it.
    pub name: Name,
    /// What shape of state the slot holds.
    pub kind: SlotKind,
    /// The shape one leaf holds, at its node of the package's
    /// [`types`](PackageMetadata::types).
    ///
    /// A leaf is empty or exactly one canonical encoding of it: absence
    /// is no bytes at all, and what an empty leaf means is the element's
    /// own business — zero for a number, nothing stored for a record.
    pub element: NodeId,
    /// The most bytes one leaf under the slot may hold, which is what the
    /// element's own shape measures.
    ///
    /// Held to [`MAX_SLOT_WIDTH`], and what turns a declared entry cap
    /// into a declared byte count.
    pub width: u32,
    /// The resource a declared vault holds, where the field's
    /// `#[holds(..)]` states one — the same expression the field's
    /// effects carry, so a consumer resolves the balance sheet against
    /// the instance's configuration.
    pub denomination: Option<Expr>,
}

/// The width of every declared slot of one package, for evaluation to
/// stamp onto the targets a signature reaches.
///
/// A target names its slot, and the slot's width is what bounds the
/// leaves under it; a slot the table does not hold — the protocol's own
/// band, or a reach into another package — is bounded at the cap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotWidths(BTreeMap<SlotId, u32>);

impl SlotWidths {
    /// No slots known: every target bounded at the cap.
    #[must_use]
    pub fn none() -> &'static Self {
        static NONE: SlotWidths = SlotWidths(BTreeMap::new());
        &NONE
    }

    /// The most bytes one leaf under `slot` may hold: what the package
    /// declared, or what the protocol's own band holds there, or the cap
    /// for a slot neither knows.
    #[must_use]
    pub(crate) fn width_of(&self, slot: SlotId) -> u32 {
        self.0
            .get(&slot)
            .copied()
            .unwrap_or_else(|| protocol_width(slot))
    }
}

/// The width of a leaf in the protocol's own band, which every owner has
/// and no package declares, and of the cells the kernel writes of its
/// own accord.
///
/// An amount cell is sixteen bytes; an instance entry holds nothing, its
/// id being its order; a halt flag is a byte; a resource record is a
/// kind and its display digits; a stored rule is an argument's width. A
/// nullifier and a committed cell are markers, either answer to a
/// crossing carries the record it answers for beside them, and an escrow
/// record is a crossing cell, each at the width its encoding pins. The
/// configuration leaf is the whole instance record, whose configuration
/// [`MAX_CONFIG_BYTES`] bounds where a creator chooses it, so the leaf
/// occupies the slot. An instance's data is a record whose shape belongs
/// to the package that wrote it, and is bounded at the cap here as is
/// every slot outside the band.
fn protocol_width(slot: SlotId) -> u32 {
    use crate::cells::{
        COMMITTED_TX_SLOT, CROSSING_ANSWER_CELL_BYTES, CROSSING_CELL_BYTES, CROSSING_CLAIM_SLOT,
        CROSSING_DECLINE_SLOT, CROSSING_OBLIGATION_CELL_BYTES, CROSSING_OBLIGATION_SLOT,
        ESCROW_RECORD_SLOT, MARKER_CELL_BYTES, NULLIFIER_SLOT,
    };
    use crate::vocabulary::{AUTH, HALT, NF_VAULT, RESOURCE, VAULT};
    match slot {
        VAULT => AMOUNT_WIDTH,
        NF_VAULT => 0,
        HALT => 1,
        RESOURCE => 2,
        AUTH => authority_width(),
        NULLIFIER_SLOT | COMMITTED_TX_SLOT => MARKER_CELL_BYTES,
        CROSSING_CLAIM_SLOT | CROSSING_DECLINE_SLOT => CROSSING_ANSWER_CELL_BYTES,
        CROSSING_OBLIGATION_SLOT => CROSSING_OBLIGATION_CELL_BYTES,
        ESCROW_RECORD_SLOT => CROSSING_CELL_BYTES,
        _ => MAX_SLOT_WIDTH,
    }
}

/// An amount cell's width, stated in the type the table speaks.
const AMOUNT_WIDTH: u32 = 16;
const _: () = assert!(AMOUNT_WIDTH as usize == AMOUNT_CELL_BYTES);

/// The governing cell's width: the record of two rules, as its own type
/// measures it.
///
/// The cell holds each rule's record rather than its bare argument bytes
/// — a byte string encodes behind its own length — so this is wider than
/// two argument caps, and the widest pair of rules anyone can hand an
/// account is the pair it refuses. Held to the encoding by
/// `an_authority_at_the_argument_cap_fits_its_cell`.
///
/// # Panics
///
/// Never: the record is two byte strings at the argument cap, orders
/// under what the width field carries.
fn authority_width() -> u32 {
    u32::try_from(<Authority as HborBound>::MAX_ENCODED_LEN)
        .expect("the governing record is narrower than the width field")
}

impl PackageMetadata {
    /// The width of every slot this package declares.
    #[must_use]
    pub(crate) fn slot_widths(&self) -> SlotWidths {
        SlotWidths(
            self.state
                .iter()
                .map(|(slot, shape)| (*slot, shape.width))
                .collect(),
        )
    }
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
    pub methods: BTreeMap<Name, MethodSignature>,
    /// The package's event names, in the index order a receipt event's
    /// type refers to.
    ///
    /// Nothing on the execution path reads this: an event carries the
    /// index, and the kernel bounds it without resolving it. The table is
    /// what lets a consumer name what it read, and it can only mean one
    /// thing because a package is content-addressed and immutable.
    pub events: Vec<Name>,
    /// The package's error names, in the index order a declined
    /// invocation's code refers to.
    ///
    /// The same shape as [`events`](Self::events) and for the same
    /// reasons: the kernel bounds a returned code without resolving it,
    /// the table is what turns that code into something a wallet can
    /// render, and immutability is what stops an index coming to mean
    /// something else. Empty for a package whose methods cannot decline.
    pub errors: Vec<Name>,
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
    pub config: Vec<Name>,
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
    /// An event payload is guest bytes: the kernel bounds its length but
    /// does not hold it to its declared shape, so — unlike a state leaf the
    /// encoder wrote — it need not be canonical. [`ShapeTable::read`] does
    /// not gate a set's or a map's key order, so a hand-written guest can
    /// emit an unsorted one that reads here to a value that would not
    /// re-encode to itself. Nothing today re-encodes or hashes a
    /// `ShapeValue` read from an event; a caller that would must
    /// re-canonicalize first, since this read does not.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for a payload the declared shape does not describe.
    #[must_use]
    pub fn read_event(&self, event: &Event) -> Option<Result<(&str, ShapeValue), DecodeError>> {
        let name = self.events.get(usize::try_from(event.event_type).ok()?)?;
        let shape = self.types.named(name)?;
        Some(
            self.types
                .read(shape, &event.payload)
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
    /// [`DecodeError`] for bytes the declared shape does not describe.
    #[must_use]
    pub fn read_leaf(
        &self,
        slot: SlotId,
        leaf: &[u8],
    ) -> Option<Result<Option<ShapeValue>, DecodeError>> {
        Some(self.read_value(self.state.get(&slot)?.element, leaf))
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
    /// [`DecodeError`] for bytes the declared shape does not describe.
    #[must_use]
    pub fn read_instance(
        &self,
        mark: &[u8],
        cell: &[u8],
    ) -> Option<Result<Option<ShapeValue>, DecodeError>> {
        let name = core::str::from_utf8(mark).ok()?;
        Some(self.read_value(self.types.named(name)?, cell))
    }

    /// One leaf's bytes, read against the shape declared for them.
    ///
    /// An empty leaf is the absence every element reads as its own zero:
    /// nothing stored for a record, and zero for a number.
    fn read_value(&self, shape: NodeId, leaf: &[u8]) -> Result<Option<ShapeValue>, DecodeError> {
        if leaf.is_empty() {
            return Ok(None);
        }
        self.types.read(shape, leaf).map(Some)
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
    use hyperscale_hbor::Bytes;

    use super::*;
    use crate::auth::RuleBytes;
    use crate::types::MAX_VALUE_BYTES;
    use crate::vocabulary::AUTH;

    /// A rule cell is wide enough for the widest rule anyone can hand
    /// it, which is the only width worth stating.
    ///
    /// The width the type derives is arithmetic over the argument cap and
    /// the length a byte string encodes behind itself, and what ties that
    /// arithmetic to the bytes HBOR writes is the encoding itself — so it
    /// is tied here. A rule at the cap that does not fit is an account
    /// whose owner cannot replace its own gate.
    #[test]
    fn a_rule_at_the_argument_cap_fits_its_cell() {
        let widest =
            RuleBytes(Bytes::new(vec![0xAB; MAX_VALUE_BYTES]).expect("at the cap")).in_cell();
        assert_eq!(
            widest.len(),
            <RuleBytes as HborBound>::MAX_ENCODED_LEN,
            "the width is the encoding, not the argument it carries"
        );
    }

    /// The governing cell holds two such rules, and is priced and
    /// bounded at exactly what the record of two at the cap encodes to.
    #[test]
    fn an_authority_at_the_argument_cap_fits_its_cell() {
        let widest = RuleBytes(Bytes::new(vec![0xAB; MAX_VALUE_BYTES]).expect("at the cap"));
        let authority = Authority {
            primary: widest.clone(),
            confirmation: widest,
        }
        .in_cell();
        assert_eq!(
            authority.len(),
            <Authority as HborBound>::MAX_ENCODED_LEN,
            "the width is the encoding, not the arguments it carries"
        );
        assert_eq!(
            protocol_width(AUTH),
            authority_width(),
            "and the auth cell is priced and bounded at it"
        );
    }

    #[test]
    fn publish_is_idempotent() {
        let hash = PackageHash(Hash32([1; 32]));
        let mut cache = MetadataCache::new();
        let mut record = PackageMetadata::default();
        record
            .methods
            .insert(Name::declared("m"), MethodSignature::default());
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
        record.events.push(Name::declared("paid"));
        record.methods.insert(
            Name::declared("pay"),
            MethodSignature {
                event_bytes: 64,
                ..MethodSignature::default()
            },
        );
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
