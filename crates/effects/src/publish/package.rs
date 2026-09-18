//! Coherence: what the whole metadata has to answer.
//!
//! A package's tables are read together or they say nothing. An event
//! index resolves through the table to a name and the name to one shape;
//! a slot is a leaf two methods may reach; a type name the protocol
//! holds means what the protocol says it means. None of those is a
//! property of any one signature, so none of them can be judged where
//! [`bounds`](super::bounds) judges.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Name, ShapeFault};
use hyperscale_vm_types::{
    EVENT_FRAME_BYTES, MAX_ERROR_CODES, MAX_EVENT_BYTES_PER_TX, MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_TYPES, MAX_SLOT_WIDTH,
};

use super::bounds::{PlacedBounds, check_signature_bounds};
use crate::dsl::{Clause, TargetExpr, slot_of};
use crate::instance::MAX_CONFIG_FIELDS;
use crate::metadata::{PackageMetadata, reserved_shape};
use crate::types::SlotId;
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

/// Why metadata is past a bound the vocabulary fixes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// An event table longer than the index an emitted event can carry.
    #[error("event table names {0} types, past the {MAX_EVENT_TYPES} an event index can reach")]
    EventTable(usize),
    /// An event table no method may emit against.
    #[error("the package declares events and no method that may emit one")]
    EventBytesUndeclared,
    /// A method bounded to emit in a package that declares no events.
    #[error("the package bounds a method's emissions and declares no events")]
    EventBytesWithoutEvents,
    /// A method whose events come to more than one transaction may emit
    /// at all.
    #[error(
        "a method's events come to {0} bytes, past the {MAX_EVENT_BYTES_PER_TX} a transaction may emit"
    )]
    EventBytesTooHigh(usize),
    /// A method names an event index the package's table does not hold,
    /// or names one twice.
    #[error("method {method} emits event {index}, which its package does not declare once")]
    EmitsUnknownEvent {
        /// The method naming it.
        method: Name,
        /// The index it named.
        index: u32,
    },
    /// A method's stated event bytes are not what its events encode to.
    #[error("method {method} declares {declared} event bytes and its events encode to {derived}")]
    EventBytesDisagrees {
        /// The method whose figure disagrees.
        method: Name,
        /// What it declared.
        declared: u32,
        /// What its events derive to.
        derived: usize,
    },
    /// An event whose own payload is wider than one emit may carry.
    ///
    /// The kernel traps `EventPayloadTooLarge` on a payload past the cap,
    /// and the per-method sum beside this one does not catch it: a method
    /// emitting one such event is inside the transaction budget and traps
    /// on its first emit. So the package is refused rather than published
    /// and bricked.
    #[error(
        "event {name} encodes to {bound} bytes, past the {MAX_EVENT_PAYLOAD_BYTES} one emit may carry"
    )]
    EventPayloadTooWide {
        /// The event past the cap.
        name: Name,
        /// What its shape measures.
        bound: usize,
    },
    /// A declared type wider than any leaf may hold.
    ///
    /// Every declared type is a leaf's record or an event's payload, and
    /// the kernel traps `CellValueTooLarge` on a write past the slot's
    /// width. A package whose own record cannot fit one is a package that
    /// traps on the call that stores it.
    #[error("type {name:?} encodes to {bound} bytes, past the {MAX_SLOT_WIDTH} a leaf may hold")]
    TypeTooWide {
        /// The type past the cap.
        name: Name,
        /// What its shape measures.
        bound: usize,
    },
    /// An error table longer than the index a declined code can carry.
    #[error("error table names {0} codes, past the {MAX_ERROR_CODES} a declined code can reach")]
    ErrorTable(usize),
    /// A configuration table longer than the record it names the fields
    /// of, which is a name for a field no instance can hold.
    #[error("configuration table names {0} fields, past the {MAX_CONFIG_FIELDS} a record holds")]
    ConfigTable(usize),
    /// A method whose signature is past a bound.
    #[error("method {name:?}: {source}")]
    Method {
        /// The method whose signature is refused.
        name: Name,
        /// What is past its bound, and where in the signature.
        #[source]
        source: PlacedBounds,
    },
    /// A slot wider than a leaf may be.
    #[error("slot {slot:?} declares {width} bytes, past the {MAX_SLOT_WIDTH} a leaf may hold")]
    SlotWidthTooWide {
        /// The slot past the cap.
        slot: SlotId,
        /// What it declared.
        width: u32,
    },
    /// A slot whose declared width is not the width its shape derives,
    /// so one of the two is wrong.
    #[error("slot {slot:?} declares {width} bytes, but its shape holds at most {derived}")]
    SlotWidthDisagrees {
        /// The slot whose two statements differ.
        slot: SlotId,
        /// What it declared.
        width: u32,
        /// What its shape derives.
        derived: u32,
    },
    /// An event named with no shape declared for it.
    ///
    /// The table promises a consumer it can name what it read; without a
    /// shape under that name the payload stays the opaque bytes the
    /// table exists to open. An event carrying nothing still has a shape
    /// — the empty one — so there is no event this refuses that a
    /// derivation could produce.
    #[error("event {name:?} declares no shape, so its payload opens to nothing")]
    EventWithoutShape {
        /// The event named without one.
        name: Name,
    },
    /// One name over two entries of the event table.
    ///
    /// An index resolves through the table to a name and the name to one
    /// shape, so a name at two indices reads the later event's bytes
    /// against the earlier one's shape — a wrong answer rather than no
    /// answer. Two of a package's own types cannot reach one name, so
    /// there is no event this refuses that a derivation could produce.
    #[error("event {name:?} is named at two indices, so one of them decodes as the other")]
    EventNamedTwice {
        /// The name at both.
        name: Name,
    },
    /// A declared slot outside the band a package numbers its own state
    /// in.
    ///
    /// The table says what a package declares, and below the band are
    /// the protocol's own cells — an engine derives their keys without
    /// consulting any metadata, so they are declared by nobody and
    /// described by the vocabulary rather than by whoever stores beside
    /// them. Above the band are the kernel's, which no signature reaches
    /// at all. A row for either is a package telling a consumer that a
    /// cell it does not own holds what it says.
    #[error("slot {slot:?} is not in the band a package numbers its own state in")]
    SlotOutsideBand {
        /// The slot claimed.
        slot: SlotId,
    },
    /// Two of a package's methods disagreeing about what a slot holds.
    ///
    /// The denomination chooses which handle a clause materializes, so a
    /// slot one method denominates and another does not is a leaf handed
    /// out as a vault and as a byte cell in turn. Nothing downstream
    /// catches it: `check_agreement` judges the clauses of one signature
    /// and the kernel's own fold the clauses of one transaction, and two
    /// calls in two transactions meet at neither. What lands is a balance
    /// written as bytes and debited as value, which is value no mint made.
    #[error(
        "slot {slot:?} holds value where {denominating:?} declares it and bytes where \
         {plain:?} does"
    )]
    SlotHoldsTwoThings {
        /// The slot both name.
        slot: SlotId,
        /// The method that says it holds value.
        denominating: Name,
        /// The method that says it holds bytes.
        plain: Name,
    },
    /// A declared slot whose element names a node the package's types do
    /// not hold.
    #[error("slot {slot:?}: {source}")]
    Slot {
        /// The slot whose element is refused.
        slot: SlotId,
        /// What cannot be read about it.
        #[source]
        source: ShapeFault,
    },
    /// A declared type under a name the protocol holds, describing
    /// something else. The name is what a consumer resolves by, so one
    /// meaning two things means neither.
    #[error("type {name:?} is the protocol's name for another shape")]
    ReservedType {
        /// The name claimed.
        name: Name,
    },
}

/// Reject metadata past a bound the vocabulary fixes.
///
/// The depth walks mirror the evaluator's own recursion — same starting
/// depth, same comparison — so a signature this accepts is one
/// evaluation will not refuse on structure alone, and the event table
/// stays inside the index an emitted event can carry.
///
/// # Errors
///
/// [`MetadataError`]; verdicts are deterministic and identical on
/// every node.
pub fn check_metadata(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    check_table_caps(metadata)?;
    for (name, signature) in &metadata.methods {
        check_signature_bounds(signature).map_err(|source| MetadataError::Method {
            name: name.clone(),
            source,
        })?;
    }
    check_table_agreement(metadata)?;
    check_event_bounds(metadata)
}

/// The three table caps: what an index into each can reach.
const fn check_table_caps(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    if metadata.events.len() > MAX_EVENT_TYPES as usize {
        return Err(MetadataError::EventTable(metadata.events.len()));
    }
    if metadata.errors.len() > MAX_ERROR_CODES as usize {
        return Err(MetadataError::ErrorTable(metadata.errors.len()));
    }
    if metadata.config.len() > MAX_CONFIG_FIELDS {
        return Err(MetadataError::ConfigTable(metadata.config.len()));
    }
    Ok(())
}

/// The event bounds read with the event table: a package that emits has
/// a method that may, one that does not has none, and no call may emit
/// more than a transaction may carry.
///
/// Per method, so a package's emissions are priced where they are
/// authored. The package-wide half is a sanity check between the two
/// tables — a declared event nothing may emit is a table that means
/// nothing, and a bound with no event behind it is a charge for
/// something the package cannot do.
fn check_event_bounds(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    let mut emits = false;
    for (name, signature) in &metadata.methods {
        // Every index names an event the package declares: one past the
        // table indexes a shape nobody registered, and a repeat would
        // charge one event's bytes twice.
        let mut seen = BTreeSet::new();
        for index in &signature.emits {
            let event = metadata.events.get(*index as usize).ok_or_else(|| {
                MetadataError::EmitsUnknownEvent {
                    method: name.clone(),
                    index: *index,
                }
            })?;
            if !seen.insert(event) {
                return Err(MetadataError::EmitsUnknownEvent {
                    method: name.clone(),
                    index: *index,
                });
            }
        }
        emits |= !signature.emits.is_empty();

        // An event's widest encoding is a figure its shape measures. The
        // author names the events; the bytes are derived, and a
        // declaration that disagrees is refused on the terms a slot's
        // width is.
        //
        // Each event's framing counts beside its payload, because the
        // receipt carries both: the figure bounds what crosses, which is
        // what the retention rate prices.
        let mut derived = 0usize;
        for index in &signature.emits {
            let event = &metadata.events[*index as usize];
            let shape =
                metadata
                    .types
                    .named(event)
                    .ok_or_else(|| MetadataError::EventWithoutShape {
                        name: event.clone(),
                    })?;
            // One payload against the cap the kernel traps on, beside the
            // per-method sum below: an event inside the transaction
            // budget can still be one no emit may carry.
            let bound = metadata.types.most(shape);
            if bound > MAX_EVENT_PAYLOAD_BYTES {
                return Err(MetadataError::EventPayloadTooWide {
                    name: event.clone(),
                    bound,
                });
            }
            derived = derived
                .saturating_add(EVENT_FRAME_BYTES)
                .saturating_add(bound);
        }
        if derived > MAX_EVENT_BYTES_PER_TX {
            return Err(MetadataError::EventBytesTooHigh(derived));
        }
        if u64::from(signature.event_bytes) != derived as u64 {
            return Err(MetadataError::EventBytesDisagrees {
                method: name.clone(),
                declared: signature.event_bytes,
                derived,
            });
        }
    }
    match (metadata.events.is_empty(), emits) {
        (false, false) => Err(MetadataError::EventBytesUndeclared),
        (true, true) => Err(MetadataError::EventBytesWithoutEvents),
        _ => Ok(()),
    }
}

/// Whether the tables, read together, say one thing: every event has a
/// shape and one name, every reserved name means what the protocol says,
/// and every slot sits in the package band holding something readable.
fn check_table_agreement(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    let mut named = BTreeSet::new();
    for name in &metadata.events {
        if metadata.types.named(name).is_none() {
            return Err(MetadataError::EventWithoutShape { name: name.clone() });
        }
        if !named.insert(name.as_str()) {
            return Err(MetadataError::EventNamedTwice { name: name.clone() });
        }
    }
    check_types(metadata)?;
    for (slot, declared) in &metadata.state {
        if !(PACKAGE_SLOT_BASE..KERNEL_SLOT_BASE).contains(&slot.0) {
            return Err(MetadataError::SlotOutsideBand { slot: *slot });
        }
        if declared.width > MAX_SLOT_WIDTH {
            return Err(MetadataError::SlotWidthTooWide {
                slot: *slot,
                width: declared.width,
            });
        }
        if metadata.types.get(declared.element).is_none() {
            return Err(MetadataError::Slot {
                slot: *slot,
                source: ShapeFault::Unresolved(declared.element),
            });
        }
        // A shape derives its width, which may be nothing at all for a
        // leaf whose entry is its own key; the stated figure has to be
        // that one, or a body could write past what the type holds.
        let derived = u32::try_from(metadata.types.most(declared.element)).unwrap_or(u32::MAX);
        if derived != declared.width {
            return Err(MetadataError::SlotWidthDisagrees {
                slot: *slot,
                width: declared.width,
                derived,
            });
        }
    }
    check_slot_contents(metadata)
}

/// Metadata the package-wide gate has passed.
///
/// The witness [`CheckedMetadata::judge`] mints, and what the cache's own
/// store demands — so a record reaching admission without the tables
/// having been read together is unrepresentable rather than a rule
/// stated in prose. [`CheckedSignature`] says the same of one signature;
/// the two scopes each have one.
///
/// [`CheckedSignature`]: super::CheckedSignature
#[derive(Clone, Debug)]
pub struct CheckedMetadata {
    metadata: PackageMetadata,
}

impl CheckedMetadata {
    /// Judge the package-wide gate and mint the witness.
    ///
    /// The tables' caps and their agreement. Each method's signature is
    /// [`check_signature`](super::check_signature)'s question, asked by
    /// the cache door beside this one; a standalone caller wanting both
    /// scopes in one call asks [`check_metadata`].
    ///
    /// # Errors
    ///
    /// [`MetadataError`]; verdicts are deterministic and identical on
    /// every node.
    pub(crate) fn judge(metadata: PackageMetadata) -> Result<Self, MetadataError> {
        check_table_caps(&metadata)?;
        check_table_agreement(&metadata)?;
        Ok(Self { metadata })
    }

    /// Mint the witness without judging — for the fixtures whose tables
    /// state the one property a test is about rather than the whole
    /// vocabulary. Everything the gate guarantees is that caller's to
    /// keep, which is why the hatch compiles only where they do.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) const fn trusted(metadata: PackageMetadata) -> Self {
        Self { metadata }
    }

    /// The metadata itself.
    #[must_use]
    pub const fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    /// Take it back out.
    pub(crate) fn into_metadata(self) -> PackageMetadata {
        self.metadata
    }
}

/// Which leaves a slot numbers: a cell's, or a collection's entries.
///
/// Two spaces rather than one, because `child_key` and `collection_id`
/// are domain-separated — a cell at a slot and a collection at the same
/// slot are leaves nothing can bring together, so holding them to one
/// answer would refuse a package for a disagreement it does not have.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Numbered {
    /// The cell the slot names under an owner.
    Cell(SlotId),
    /// Every entry of the collection the slot names under an owner.
    Entries(SlotId),
}

impl Numbered {
    /// The slot, whichever space it numbers in.
    const fn slot(self) -> SlotId {
        match self {
            Self::Cell(slot) | Self::Entries(slot) => slot,
        }
    }
}

/// What a slot holds is one answer for the package that numbers it.
///
/// A denomination chooses which handle a clause materializes, and the two
/// share no operation — so a slot one method denominates and another does
/// not is a leaf reached as a vault and as a byte cell in turn. That is
/// the same statement [`check_agreement`] makes of one signature and
/// `MixedContents` of one transaction, and neither of them spans a
/// package: two methods are judged one at a time and their calls need not
/// share a transaction. Judged here, where the whole metadata is in hand.
///
/// Per slot rather than per target expression, which is what makes it
/// total. A slot is a literal on every target that names one, so two
/// clauses land on one leaf only if they carry the same slot — where
/// comparing expressions would let two spellings of one key through, and
/// the evaluated comparison that catches those exists only inside a
/// transaction. A fresh key carries no slot and needs none: its leaf is
/// derived from the transaction creating it, so no later declaration
/// names it again.
///
/// The form is the whole of what two methods can disagree about. A
/// denomination is the first material of the key it names
/// ([`DeclarationError::DenominationNotKeyed`]), so two denominated
/// clauses reaching one leaf keyed it by the same resource and have no
/// room to name a second — what is left is a leaf one method denominates
/// and another does not.
fn check_slot_contents(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    let mut answered: BTreeMap<Numbered, (bool, &Name)> = BTreeMap::new();
    for (method, signature) in &metadata.methods {
        // A method's own first answer, so what is compared here is one
        // method against another. Two clauses of one signature reaching
        // one leaf are [`check_agreement`]'s to judge, and it says more
        // about them than a slot can.
        let mut says: BTreeMap<Numbered, bool> = BTreeMap::new();
        for clause in signature.effects.iter().flat_map(Clause::effects) {
            let Clause::Effect {
                reach: None,
                target,
                denomination,
                ..
            } = clause
            else {
                continue;
            };
            if let Some(numbered) = numbered(target) {
                says.entry(numbered)
                    .or_insert_with(|| denomination.is_some());
            }
        }
        for (numbered, holds) in says {
            let (said, first) = *answered.entry(numbered).or_insert((holds, method));
            if said != holds {
                let (denominating, plain) = if said {
                    (first, method)
                } else {
                    (method, first)
                };
                return Err(MetadataError::SlotHoldsTwoThings {
                    slot: numbered.slot(),
                    denominating: denominating.clone(),
                    plain: plain.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Which leaves a target's slot numbers, where it names one.
fn numbered(target: &TargetExpr) -> Option<Numbered> {
    let slot = slot_of(target)?.0.fixed()?;
    Some(match target {
        TargetExpr::Point(_) => Numbered::Cell(slot),
        TargetExpr::Entry { .. } | TargetExpr::Range { .. } => Numbered::Entries(slot),
    })
}

/// Every declared type inside a leaf, and every reserved name meaning
/// what the protocol says it means.
///
/// The first is the width check for the records no slot row states: an
/// instance's data cell and every record reached through one. A leaf is
/// what a declared type is stored in, and the kernel traps on a write
/// past the slot's width — so a package whose own record cannot fit a
/// leaf is one that traps on the call that stores it.
///
/// The second is what makes `address` a fact — a package may declare any
/// type it likes and may not declare one under the protocol's name for
/// something else. That every declared shape is readable needs no check
/// here: a table that exists was measured node by node as it was built
/// or decoded.
fn check_types(metadata: &PackageMetadata) -> Result<(), MetadataError> {
    for (name, id) in metadata.types.names() {
        let bound = metadata.types.most(id);
        if bound > MAX_SLOT_WIDTH as usize {
            return Err(MetadataError::TypeTooWide {
                name: name.clone(),
                bound,
            });
        }
        if reserved_shape(name).is_some_and(|reserved| !metadata.types.matches(id, reserved)) {
            return Err(MetadataError::ReservedType { name: name.clone() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        Capped, Name, NodeId, ShapeFault, ShapeField, ShapeNode, ShapeTable, TypeShape,
    };
    use hyperscale_vm_types::Moves;

    use super::super::fixtures::{a_resource, one_clause, own_interval, own_point};
    use super::*;
    use crate::dsl::ModeExpr;
    use crate::metadata::{PackageMetadata, SlotKind, SlotShape, reserved_shape};
    use crate::signature::MethodSignature;
    use crate::types::SlotId;
    use crate::vocabulary::VAULT;
    use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

    /// Metadata declaring `types` and nothing else, which is what the
    /// shape door reads.
    fn declaring(types: ShapeTable) -> PackageMetadata {
        PackageMetadata {
            types,
            ..PackageMetadata::default()
        }
    }

    /// The framing one event costs, in the units a signature states it
    /// in.
    fn frame_bytes() -> u32 {
        u32::try_from(EVENT_FRAME_BYTES).expect("a frame fits u32")
    }

    /// One method emitting the package's first event at `bytes`, so a
    /// package declaring events has one that may emit them.
    fn emitting(bytes: u32) -> BTreeMap<Name, MethodSignature> {
        std::iter::once((
            Name::declared("moves"),
            MethodSignature {
                emits: Capped::new(vec![0]).unwrap(),
                event_bytes: bytes,
                ..MethodSignature::default()
            },
        ))
        .collect()
    }

    /// One type's table: `shape` under `name`.
    fn one(name: &str, shape: TypeShape) -> ShapeTable {
        let mut types = ShapeTable::new();
        let shape = types.push(shape).expect("a form the table holds");
        types
            .push(TypeShape::Named {
                name: Name::declared(name),
                shape,
            })
            .expect("one name over one shape");
        types
    }

    /// A table holding `shape` unnamed, and the node it sits at.
    fn holding_shape(shape: TypeShape) -> (ShapeTable, NodeId) {
        let mut types = ShapeTable::new();
        let id = types.push(shape).expect("a form the table holds");
        (types, id)
    }

    /// An event's name is a promise its payload opens; a name with no
    /// shape under it is a promise nothing keeps.
    #[test]
    fn an_event_with_no_shape_is_refused() {
        // The empty shape encodes to nothing, so the method that emits
        // it is bounded at nothing too.
        let named = |types: ShapeTable| PackageMetadata {
            events: vec![Name::declared("moved")],
            methods: emitting(frame_bytes()),
            types,
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&named(ShapeTable::new())),
            Err(MetadataError::EventWithoutShape {
                name: Name::declared("moved")
            })
        );
        // An event carrying nothing still declares the empty shape, so
        // there is no derived event this refuses.
        assert_eq!(
            check_metadata(&named(one("moved", TypeShape::Tuple(Vec::new())))),
            Ok(())
        );
    }

    /// An index resolves to a name and a name to one shape, so a name at
    /// two indices would read one event's bytes as the other's.
    #[test]
    fn one_name_at_two_event_indices_is_refused() {
        let metadata = PackageMetadata {
            events: vec![Name::declared("moved"), Name::declared("moved")],
            methods: emitting(frame_bytes() + 8),
            types: one("moved", TypeShape::U64),
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&metadata),
            Err(MetadataError::EventNamedTwice {
                name: Name::declared("moved")
            })
        );
    }

    /// A slot's element names a node the same table holds, and a slot
    /// reaching outside it would be a leaf nobody could read.
    #[test]
    fn a_slot_reaching_a_type_the_package_lacks_is_refused() {
        let holding = |types, element| PackageMetadata {
            types,
            state: std::iter::once((
                SlotId(17),
                SlotShape {
                    name: Name::declared("held"),
                    kind: SlotKind::Keyed,
                    element,
                    width: 8,
                    denomination: None,
                },
            ))
            .collect(),
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&holding(ShapeTable::new(), NodeId(3))),
            Err(MetadataError::Slot {
                slot: SlotId(17),
                source: ShapeFault::Unresolved(NodeId(3)),
            })
        );
        let (types, word) = holding_shape(TypeShape::U64);
        assert_eq!(check_metadata(&holding(types, word)), Ok(()));
    }

    /// A slot's width is what turns a declared entry cap into a byte
    /// count, and it is the one its element's shape measures: a figure
    /// beside it that disagrees is one of the two wrong, a leaf whose
    /// entry is its own key measures nothing, and no leaf is wider than
    /// a leaf may be.
    #[test]
    fn a_slot_is_held_to_one_width() {
        let mut types = ShapeTable::new();
        let byte = types.push(TypeShape::U8).unwrap();
        let bytes = types
            .push(TypeShape::Seq {
                cap: 63,
                element: byte,
            })
            .unwrap();
        let word = types.push(TypeShape::U64).unwrap();
        let unit = types.push(TypeShape::Tuple(Vec::new())).unwrap();
        let holding = |element, width| PackageMetadata {
            types: types.clone(),
            state: std::iter::once((
                SlotId(17),
                SlotShape {
                    name: Name::declared("held"),
                    kind: SlotKind::Keyed,
                    element,
                    width,
                    denomination: None,
                },
            ))
            .collect(),
            ..PackageMetadata::default()
        };
        let slot = SlotId(17);
        assert_eq!(
            check_metadata(&holding(bytes, MAX_SLOT_WIDTH + 1)),
            Err(MetadataError::SlotWidthTooWide {
                slot,
                width: MAX_SLOT_WIDTH + 1,
            })
        );
        // A run derives its width from its cap: sixty-three bytes behind
        // one byte of length.
        assert_eq!(
            check_metadata(&holding(bytes, 0)),
            Err(MetadataError::SlotWidthDisagrees {
                slot,
                width: 0,
                derived: 64,
            })
        );
        assert_eq!(check_metadata(&holding(bytes, 64)), Ok(()));
        assert_eq!(
            check_metadata(&holding(word, 9)),
            Err(MetadataError::SlotWidthDisagrees {
                slot,
                width: 9,
                derived: 8,
            })
        );
        assert_eq!(check_metadata(&holding(word, 8)), Ok(()));
        assert_eq!(check_metadata(&holding(unit, 0)), Ok(()));
    }

    /// The state table is what a package declares, and the protocol's
    /// own cells are declared by nobody — so a row for one is refused
    /// where the authoring macro refuses the field.
    #[test]
    fn a_slot_outside_the_package_band_is_refused() {
        let (types, word) = holding_shape(TypeShape::U64);
        let at = |slot| PackageMetadata {
            types: types.clone(),
            state: std::iter::once((
                SlotId(slot),
                SlotShape {
                    name: Name::declared("held"),
                    kind: SlotKind::Cell,
                    element: word,
                    width: 8,
                    denomination: None,
                },
            ))
            .collect(),
            ..PackageMetadata::default()
        };
        // The protocol's vault, whose leaf every owner has already.
        assert_eq!(
            check_metadata(&at(VAULT.0)),
            Err(MetadataError::SlotOutsideBand { slot: VAULT })
        );
        // The kernel's own band at the top, which no signature reaches.
        assert_eq!(
            check_metadata(&at(KERNEL_SLOT_BASE)),
            Err(MetadataError::SlotOutsideBand {
                slot: SlotId(KERNEL_SLOT_BASE)
            })
        );
        assert_eq!(check_metadata(&at(PACKAGE_SLOT_BASE)), Ok(()));
        assert_eq!(check_metadata(&at(KERNEL_SLOT_BASE - 1)), Ok(()));
    }

    /// What a slot holds is one answer for the package that numbers it.
    ///
    /// Two methods that disagree are one leaf reached as a vault and as a
    /// byte cell, and nothing below sees them together: a signature is
    /// judged alone and a transaction need not carry both calls. So the
    /// bytes one writes are a balance the other debits, and value exists
    /// that no mint made.
    #[test]
    fn two_methods_disagreeing_about_what_a_slot_holds_are_refused() {
        let slot = SlotId(PACKAGE_SLOT_BASE);
        let package = |forge: MethodSignature, withdraw: MethodSignature| PackageMetadata {
            methods: [
                (Name::declared("forge"), forge),
                (Name::declared("withdraw"), withdraw),
            ]
            .into_iter()
            .collect(),
            ..PackageMetadata::default()
        };
        let disagreed = |slot| MetadataError::SlotHoldsTwoThings {
            slot,
            denominating: Name::declared("withdraw"),
            plain: Name::declared("forge"),
        };
        let cell = |denomination| {
            one_clause(
                own_point(slot, vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                denomination,
            )
        };
        let entries = |denomination| {
            one_clause(
                own_interval(slot, vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                denomination,
            )
        };

        assert_eq!(
            check_metadata(&package(cell(None), cell(Some(a_resource())))),
            Err(disagreed(slot))
        );
        // An instance holding is the same disagreement in collection
        // form: an entry written as bytes is one a take lifts out as an
        // instance nothing minted.
        assert_eq!(
            check_metadata(&package(entries(None), entries(Some(a_resource())))),
            Err(disagreed(slot))
        );

        // Agreement passes, whichever answer the two agree on.
        assert_eq!(check_metadata(&package(cell(None), cell(None))), Ok(()));
        assert_eq!(
            check_metadata(&package(cell(Some(a_resource())), cell(Some(a_resource())))),
            Ok(())
        );

        // A cell and a collection at one slot are leaves nothing brings
        // together — the two derivations are domain-separated — so they
        // are two answers about two things.
        assert_eq!(
            check_metadata(&package(cell(None), entries(Some(a_resource())))),
            Ok(())
        );
    }

    /// Every leaf a package writes is one the kernel traps on past its
    /// own cap, and two of them have no slot row to state a width: an
    /// event's payload, and the record an instance's data cell holds. So
    /// the gate measures the shape and compares it here.
    #[test]
    fn a_leaf_past_the_cap_the_kernel_traps_on_is_refused() {
        // A byte string sits behind its own length, so a run at the cap
        // measures two bytes past it.
        let run = |cap| {
            let mut types = ShapeTable::new();
            let byte = types.push(TypeShape::U8).unwrap();
            let run = types.push(TypeShape::Seq { cap, element: byte }).unwrap();
            (types, run)
        };

        let payload = |cap| {
            let (mut types, run) = run(cap);
            let shape = types
                .push(TypeShape::Struct(vec![ShapeField {
                    name: Name::declared("note"),
                    shape: run,
                }]))
                .unwrap();
            types
                .push(TypeShape::Named {
                    name: Name::declared("noted"),
                    shape,
                })
                .unwrap();
            PackageMetadata {
                events: vec![Name::declared("noted")],
                methods: emitting(frame_bytes() + u32::try_from(types.most(shape)).unwrap()),
                types,
                ..PackageMetadata::default()
            }
        };
        let payload_cap = u32::try_from(MAX_EVENT_PAYLOAD_BYTES).expect("a cap inside u32");
        assert_eq!(check_metadata(&payload(payload_cap - 2)), Ok(()));
        assert_eq!(
            check_metadata(&payload(payload_cap - 1)),
            Err(MetadataError::EventPayloadTooWide {
                name: Name::declared("noted"),
                bound: MAX_EVENT_PAYLOAD_BYTES + 1,
            })
        );

        // A record no event emits still lands in a leaf, and the leaf is
        // what bounds it.
        let record = |cap| {
            let (mut types, run) = run(cap);
            types
                .push(TypeShape::Named {
                    name: Name::declared("entry"),
                    shape: run,
                })
                .unwrap();
            declaring(types)
        };
        assert_eq!(check_metadata(&record(MAX_SLOT_WIDTH - 2)), Ok(()));
        assert_eq!(
            check_metadata(&record(MAX_SLOT_WIDTH - 1)),
            Err(MetadataError::TypeTooWide {
                name: Name::declared("entry"),
                bound: MAX_SLOT_WIDTH as usize + 1,
            })
        );
    }

    /// The protocol's name for an address describes an address, in every
    /// package that declares one — which is what lets a consumer resolve
    /// by the name at all.
    #[test]
    fn a_reserved_name_over_a_foreign_shape_is_refused() {
        let pinned = reserved_shape("ResourceAddr").expect("the protocol pins it");
        assert!(matches!(pinned, ShapeNode::Named { .. }));
        let mut types = ShapeTable::new();
        types.declare(pinned).expect("the protocol's own shape");
        assert_eq!(check_metadata(&declaring(types)), Ok(()));
        let text = TypeShape::Text { cap: 8 };
        assert_eq!(
            check_metadata(&declaring(one("ResourceAddr", text.clone()))),
            Err(MetadataError::ReservedType {
                name: Name::declared("ResourceAddr"),
            })
        );
        // A name the protocol does not hold is the package's own to spend.
        assert_eq!(check_metadata(&declaring(one("Outcome", text))), Ok(()));
    }
}
