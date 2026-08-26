//! Coherence: what the whole metadata has to answer.
//!
//! A package's tables are read together or they say nothing. An event
//! index resolves through the table to a name and the name to one shape;
//! a slot is a leaf two methods may reach; a type name the protocol
//! holds means what the protocol says it means. None of those is a
//! property of any one signature, so none of them can be judged where
//! [`bounds`](super::bounds) judges.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Resolution, ShapeFault};
use hyperscale_vm_types::{MAX_ERROR_CODES, MAX_EVENT_TYPES};

use super::bounds::{SignatureBoundsError, check_signature_bounds};
use crate::dsl::{Clause, TargetExpr, slot_of};
use crate::instance::MAX_CONFIG_FIELDS;
use crate::metadata::{LeafForm, MAX_SHAPE_DEPTH, PackageMetadata, reserved_shape};
use crate::types::SlotId;
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

/// Why metadata is past a bound the vocabulary fixes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// An event table longer than the index an emitted event can carry.
    #[error("event table names {0} types, past the {MAX_EVENT_TYPES} an event index can reach")]
    EventTable(usize),
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
        name: String,
        /// What is past its bound.
        #[source]
        source: SignatureBoundsError,
    },
    /// A declared type whose shape cannot be read.
    #[error("type {name:?}: {source}")]
    Type {
        /// The type whose shape is refused.
        name: String,
        /// What cannot be read about it.
        #[source]
        source: ShapeFault,
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
        name: String,
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
        name: String,
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
        denominating: String,
        /// The method that says it holds bytes.
        plain: String,
    },
    /// A declared slot whose element cannot be read.
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
        name: String,
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
    if metadata.events.len() > MAX_EVENT_TYPES as usize {
        return Err(MetadataError::EventTable(metadata.events.len()));
    }
    if metadata.errors.len() > MAX_ERROR_CODES as usize {
        return Err(MetadataError::ErrorTable(metadata.errors.len()));
    }
    if metadata.config.len() > MAX_CONFIG_FIELDS {
        return Err(MetadataError::ConfigTable(metadata.config.len()));
    }
    for (name, signature) in &metadata.methods {
        check_signature_bounds(signature).map_err(|source| MetadataError::Method {
            name: name.clone(),
            source,
        })?;
    }
    let mut named = BTreeSet::new();
    for name in &metadata.events {
        if !metadata.types.contains_key(name) {
            return Err(MetadataError::EventWithoutShape { name: name.clone() });
        }
        if !named.insert(name.as_str()) {
            return Err(MetadataError::EventNamedTwice { name: name.clone() });
        }
    }
    // One resolution for the whole metadata: a name two shapes reach is
    // one answer, and asking the table per shape would be the same walk
    // multiplied by the number of shapes that ask.
    let mut resolved = Resolution::of(&metadata.types);
    check_types(&mut resolved)?;
    for (slot, declared) in &metadata.state {
        if !(PACKAGE_SLOT_BASE..KERNEL_SLOT_BASE).contains(&slot.0) {
            return Err(MetadataError::SlotOutsideBand { slot: *slot });
        }
        let LeafForm::Value(shape) = &declared.element else {
            continue;
        };
        resolved
            .readable(shape, MAX_SHAPE_DEPTH)
            .map_err(|source| MetadataError::Slot {
                slot: *slot,
                source,
            })?;
    }
    check_slot_contents(metadata)
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
    let mut answered: BTreeMap<Numbered, (bool, &str)> = BTreeMap::new();
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
                    (first, method.as_str())
                } else {
                    (method.as_str(), first)
                };
                return Err(MetadataError::SlotHoldsTwoThings {
                    slot: numbered.slot(),
                    denominating: denominating.to_owned(),
                    plain: plain.to_owned(),
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

/// Every declared shape readable, and every reserved name meaning what
/// the protocol says it means.
///
/// The first is what stops a wallet meeting a shape it cannot walk: a
/// reference to nothing, or a nest past what a decoder will follow. The
/// second is what makes `address` a fact — a package may declare any type
/// it likes and may not declare one under the protocol's name for
/// something else.
fn check_types(resolved: &mut Resolution<'_>) -> Result<(), MetadataError> {
    for (name, shape) in resolved.types() {
        resolved
            .readable(shape, MAX_SHAPE_DEPTH)
            .map_err(|source| MetadataError::Type {
                name: name.clone(),
                source,
            })?;
        if reserved_shape(name).is_some_and(|reserved| reserved != shape) {
            return Err(MetadataError::ReservedType { name: name.clone() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{ShapeFault, ShapeField, ShapeTable, TypeShape};
    use hyperscale_vm_types::Moves;

    use super::super::fixtures::{a_resource, one_clause, own_interval, own_point};
    use super::*;
    use crate::dsl::ModeExpr;
    use crate::metadata::{
        LeafForm, MAX_SHAPE_DEPTH, PackageMetadata, SlotKind, SlotShape, reserved_shape,
    };
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

    /// One entry's table, for a shape whose whole content is its own.
    fn one(name: &str, shape: TypeShape) -> ShapeTable {
        std::iter::once((name.to_owned(), shape)).collect()
    }

    #[test]
    fn a_shape_reaching_outside_the_package_is_refused() {
        let types = one(
            "holder",
            TypeShape::Struct(vec![ShapeField {
                name: "held".into(),
                shape: TypeShape::Ref("elsewhere".into()),
            }]),
        );
        assert_eq!(
            check_metadata(&declaring(types)),
            Err(MetadataError::Type {
                name: "holder".into(),
                source: ShapeFault::Unresolved("elsewhere".into()),
            })
        );
    }

    #[test]
    fn a_shape_past_the_cap_is_refused_and_one_at_it_is_not() {
        let nested =
            |levels| (0..levels).fold(TypeShape::U8, |inner, _| TypeShape::Option(Box::new(inner)));
        // The walk spends its budget on the shape's own levels, so the
        // deepest admissible type is one shallower than the cap.
        assert_eq!(
            check_metadata(&declaring(one("deep", nested(MAX_SHAPE_DEPTH - 1)))),
            Ok(())
        );
        assert_eq!(
            check_metadata(&declaring(one("deep", nested(MAX_SHAPE_DEPTH)))),
            Err(MetadataError::Type {
                name: "deep".into(),
                source: ShapeFault::TooDeep,
            })
        );
    }

    /// A cycle is refused by the bound a deep nest is refused by, because
    /// it is the same walk running out of the same budget.
    #[test]
    fn a_reference_cycle_is_refused() {
        let holding = |held: &str| {
            TypeShape::Struct(vec![ShapeField {
                name: "next".into(),
                shape: TypeShape::Option(Box::new(TypeShape::Ref(held.to_owned()))),
            }])
        };
        let types = [
            ("first".to_owned(), holding("second")),
            ("second".to_owned(), holding("first")),
        ]
        .into_iter()
        .collect();
        assert!(matches!(
            check_metadata(&declaring(types)),
            Err(MetadataError::Type {
                source: ShapeFault::TooDeep,
                ..
            })
        ));
    }

    /// An event's name is a promise its payload opens; a name with no
    /// shape under it is a promise nothing keeps.
    #[test]
    fn an_event_with_no_shape_is_refused() {
        let named = |types: ShapeTable| PackageMetadata {
            events: vec!["moved".into()],
            types,
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&named(ShapeTable::new())),
            Err(MetadataError::EventWithoutShape {
                name: "moved".into()
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
            events: vec!["moved".into(), "moved".into()],
            types: one("moved", TypeShape::U64),
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&metadata),
            Err(MetadataError::EventNamedTwice {
                name: "moved".into()
            })
        );
    }

    /// A slot's element is judged where a declared type is: it names a
    /// type the same table holds, and a slot reaching outside it would
    /// be a leaf nobody could read.
    #[test]
    fn a_slot_reaching_a_type_the_package_lacks_is_refused() {
        let holding = |element| PackageMetadata {
            state: std::iter::once((
                SlotId(17),
                SlotShape {
                    name: "held".into(),
                    kind: SlotKind::Keyed,
                    element,
                },
            ))
            .collect(),
            ..PackageMetadata::default()
        };
        assert_eq!(
            check_metadata(&holding(LeafForm::Value(TypeShape::Ref("absent".into())))),
            Err(MetadataError::Slot {
                slot: SlotId(17),
                source: ShapeFault::Unresolved("absent".into()),
            })
        );
        // Bytes name no type, so there is nothing for them to reach.
        assert_eq!(check_metadata(&holding(LeafForm::Bytes)), Ok(()));
    }

    /// The state table is what a package declares, and the protocol's
    /// own cells are declared by nobody — so a row for one is refused
    /// where the authoring macro refuses the field.
    #[test]
    fn a_slot_outside_the_package_band_is_refused() {
        let at = |slot| PackageMetadata {
            state: std::iter::once((
                SlotId(slot),
                SlotShape {
                    name: "held".into(),
                    kind: SlotKind::Cell,
                    element: LeafForm::Value(TypeShape::U64),
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
                ("forge".to_owned(), forge),
                ("withdraw".to_owned(), withdraw),
            ]
            .into_iter()
            .collect(),
            ..PackageMetadata::default()
        };
        let disagreed = |slot| MetadataError::SlotHoldsTwoThings {
            slot,
            denominating: "withdraw".into(),
            plain: "forge".into(),
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

    /// The protocol's name for an address describes an address, in every
    /// package that declares one — which is what lets a consumer resolve
    /// by the name at all.
    #[test]
    fn a_reserved_name_over_a_foreign_shape_is_refused() {
        let pinned = reserved_shape("resource-address").expect("the protocol pins it");
        assert_eq!(
            check_metadata(&declaring(one("resource-address", pinned.clone()))),
            Ok(())
        );
        assert_eq!(
            check_metadata(&declaring(one("resource-address", TypeShape::Text))),
            Err(MetadataError::ReservedType {
                name: "resource-address".into(),
            })
        );
        // A name the protocol does not hold is the package's own to spend.
        assert_eq!(
            check_metadata(&declaring(one("outcome", TypeShape::Text))),
            Ok(())
        );
    }
}
