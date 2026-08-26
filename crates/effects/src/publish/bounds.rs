//! The bounds gate: what a signature and a package's tables may hold
//! before anything walks them.
//!
//! Structural caps rather than meaning — nesting depth, branch width,
//! table sizes, the band a slot number may name. Judged first of the
//! three, because every walk below it is bounded by what this admits: a
//! gate judges metadata before any fee is assured, so the work each
//! later pass can be made to do is fixed here.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Resolution, ShapeFault};
use hyperscale_vm_types::{MAX_ERROR_CODES, MAX_EVENT_TYPES};

use crate::dsl::{
    Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, ModeExpr,
    TargetExpr, slot_of,
};
use crate::instance::MAX_CONFIG_FIELDS;
use crate::metadata::{LeafForm, MAX_SHAPE_DEPTH, PackageMetadata, reserved_shape};
use crate::resource::GrantsExpr;
use crate::rule::{
    GrantClaim, MAX_RULE_BRANCHES, MAX_RULE_DEPTH, RuleExpr, RuleLeaf, always, never,
};
use crate::signature::{AbiParam, MAX_ISSUANCES_PER_SIGNATURE, MethodSignature};
use crate::types::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_ITEMS, SlotId, value_within_width};
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

/// Why metadata is past a bound the vocabulary fixes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetadataBoundsError {
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

/// Why one signature is past a bound the vocabulary fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureBoundsError {
    /// A granted entry spelled a way its behaviour does not admit.
    #[error("a granted behaviour does not admit the spelling its entry was written with")]
    UnadmittedGrant,
    /// More issuances than one signature may carry.
    #[error("a method issues more than {MAX_ISSUANCES_PER_SIGNATURE} resources")]
    TooManyIssuances,
    /// A granted rule naming a badge whose own rules name a badge.
    #[error("a granted rule names a badge whose own rules name a badge")]
    BadgeChainTooDeep,
    /// A declared rule past the caps a stored one is decoded under.
    #[error(
        "a declared rule nests past {MAX_RULE_DEPTH}, branches past {MAX_RULE_BRANCHES}, or \
         holds a threshold nobody meant"
    )]
    RuleCaps,
    /// An expression nested past the evaluator's own recursion bound.
    #[error("expression nests deeper than {MAX_EXPR_DEPTH}")]
    ExprDepth,
    /// A literal nested past the value depth admission bounds.
    #[error("literal nests deeper than {MAX_VALUE_DEPTH}")]
    LiteralDepth,
    /// `for-each` clauses nested past the evaluator's bound.
    #[error("for-each clauses nest deeper than {MAX_CLAUSE_DEPTH}")]
    ClauseDepth,
    /// More effect clauses than one signature may declare.
    #[error("signature declares more than {MAX_EFFECTS_PER_SIGNATURE} effects")]
    TooManyEffects,
    /// A value wider than the bound every walk over one is charged
    /// against — a literal past it, or a list the evaluator would build
    /// past it.
    #[error("a value is wider than {MAX_VALUE_ITEMS} items or {MAX_VALUE_BYTES} bytes")]
    ValueWidth,
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
/// [`MetadataBoundsError`]; verdicts are deterministic and identical on
/// every node.
pub fn check_metadata(metadata: &PackageMetadata) -> Result<(), MetadataBoundsError> {
    if metadata.events.len() > MAX_EVENT_TYPES as usize {
        return Err(MetadataBoundsError::EventTable(metadata.events.len()));
    }
    if metadata.errors.len() > MAX_ERROR_CODES as usize {
        return Err(MetadataBoundsError::ErrorTable(metadata.errors.len()));
    }
    if metadata.config.len() > MAX_CONFIG_FIELDS {
        return Err(MetadataBoundsError::ConfigTable(metadata.config.len()));
    }
    for (name, signature) in &metadata.methods {
        check_signature_bounds(signature).map_err(|source| MetadataBoundsError::Method {
            name: name.clone(),
            source,
        })?;
    }
    let mut named = BTreeSet::new();
    for name in &metadata.events {
        if !metadata.types.contains_key(name) {
            return Err(MetadataBoundsError::EventWithoutShape { name: name.clone() });
        }
        if !named.insert(name.as_str()) {
            return Err(MetadataBoundsError::EventNamedTwice { name: name.clone() });
        }
    }
    // One resolution for the whole metadata: a name two shapes reach is
    // one answer, and asking the table per shape would be the same walk
    // multiplied by the number of shapes that ask.
    let mut resolved = Resolution::of(&metadata.types);
    check_types(&mut resolved)?;
    for (slot, declared) in &metadata.state {
        if !(PACKAGE_SLOT_BASE..KERNEL_SLOT_BASE).contains(&slot.0) {
            return Err(MetadataBoundsError::SlotOutsideBand { slot: *slot });
        }
        let LeafForm::Value(shape) = &declared.element else {
            continue;
        };
        resolved
            .readable(shape, MAX_SHAPE_DEPTH)
            .map_err(|source| MetadataBoundsError::Slot {
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
fn check_slot_contents(metadata: &PackageMetadata) -> Result<(), MetadataBoundsError> {
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
                return Err(MetadataBoundsError::SlotHoldsTwoThings {
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
fn check_types(resolved: &mut Resolution<'_>) -> Result<(), MetadataBoundsError> {
    for (name, shape) in resolved.types() {
        resolved
            .readable(shape, MAX_SHAPE_DEPTH)
            .map_err(|source| MetadataBoundsError::Type {
                name: name.clone(),
                source,
            })?;
        if reserved_shape(name).is_some_and(|reserved| reserved != shape) {
            return Err(MetadataBoundsError::ReservedType { name: name.clone() });
        }
    }
    Ok(())
}

/// A declared rule under the caps a stored one is decoded under, and
/// every leaf under the expression caps.
fn check_rule_bounds(rule: &RuleExpr) -> Result<(), SignatureBoundsError> {
    if !rule.within_caps(0) {
        return Err(SignatureBoundsError::RuleCaps);
    }
    match rule {
        RuleExpr::Require(RuleLeaf::Claim(claim)) => check_expr_bounds(claim, 0),
        RuleExpr::Require(RuleLeaf::Stored { cell, .. }) => check_expr_bounds(cell, 0),
        RuleExpr::Require(RuleLeaf::Presence { target, .. }) => check_target_bounds(target),
        RuleExpr::CountOf { rules, .. } => rules.iter().try_for_each(check_rule_bounds),
    }
}

pub(super) fn check_signature_bounds(
    signature: &MethodSignature,
) -> Result<(), SignatureBoundsError> {
    for output in &signature.outputs {
        check_expr_bounds(output, 0)?;
    }
    for denomination in signature.denominations.iter().flatten() {
        check_expr_bounds(denomination, 0)?;
    }
    for param in &signature.abi {
        if let AbiParam::Derived(expr) = param {
            check_expr_bounds(expr, 0)?;
        }
    }
    if signature.issues.len() > MAX_ISSUANCES_PER_SIGNATURE {
        return Err(SignatureBoundsError::TooManyIssuances);
    }
    for issuance in &signature.issues {
        check_grants_bounds(&issuance.grants)?;
    }
    let mut declared = 0usize;
    check_clause_bounds(&signature.effects, 0, &mut declared)
}

fn check_clause_bounds(
    clauses: &[Clause],
    depth: usize,
    declared: &mut usize,
) -> Result<(), SignatureBoundsError> {
    if depth > MAX_CLAUSE_DEPTH {
        return Err(SignatureBoundsError::ClauseDepth);
    }
    for clause in clauses {
        match clause {
            Clause::Effect {
                guard,
                target,
                mode,
                denomination,
                reach: _,
            } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                check_target_bounds(target)?;
                check_mode_bounds(mode)?;
                if let Some(denomination) = denomination {
                    check_expr_bounds(denomination, 0)?;
                }
            }
            Clause::ForEach { guard, list, body } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                check_expr_bounds(list, 0)?;
                check_clause_bounds(body, depth + 1, declared)?;
            }
            Clause::Requires { guard, rule } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                check_rule_bounds(rule)?;
            }
            Clause::Mints { guard, claim } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                check_expr_bounds(claim, 0)?;
            }
        }
    }
    Ok(())
}

fn check_target_bounds(target: &TargetExpr) -> Result<(), SignatureBoundsError> {
    match target {
        TargetExpr::Point(key) => check_expr_bounds(key, 0),
        TargetExpr::Entry {
            owner,
            material,
            order,
            ..
        } => {
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(order, 0)
        }
        TargetExpr::Range {
            owner,
            material,
            lo,
            hi,
            cap,
            ..
        } => {
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(lo, 0)?;
            check_expr_bounds(hi, 0)?;
            check_expr_bounds(cap, 0)
        }
    }
}

fn check_mode_bounds(mode: &ModeExpr) -> Result<(), SignatureBoundsError> {
    match mode {
        ModeExpr::Read | ModeExpr::Delta | ModeExpr::Credit | ModeExpr::Write { .. } => Ok(()),
        ModeExpr::Reserve(amount) => check_expr_bounds(amount, 0),
    }
}

fn check_expr_bounds(expr: &Expr, depth: usize) -> Result<(), SignatureBoundsError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(SignatureBoundsError::ExprDepth);
    }
    if let Expr::Literal(literal) = expr {
        if literal.depth() > MAX_VALUE_DEPTH {
            return Err(SignatureBoundsError::LiteralDepth);
        }
        value_within_width(literal).map_err(|_| SignatureBoundsError::ValueWidth)?;
    }
    // A list or tuple the evaluator *builds* rather than decodes: its
    // arity is the expression's own, so the codec's width bound has
    // nothing to say about it, and what it produces is a value every
    // walk downstream pays for by the element.
    if let Expr::List(elements) | Expr::Tuple(elements) = expr
        && elements.len() > MAX_VALUE_ITEMS
    {
        return Err(SignatureBoundsError::ValueWidth);
    }
    // The granted set is not a child — its leaves hold no expression at
    // all — so it is walked here rather than reached by the recursion.
    if let Expr::SelfResource { grants, .. } = expr {
        check_grants_bounds(grants)?;
    }
    expr.children()
        .try_for_each(|child| check_expr_bounds(child, depth + 1))
}

/// Every rule a declaration grants, under the caps a stored rule is
/// decoded under.
///
/// Held here as well as at resolution because a resolved rule is what a
/// holder judges: a set past the caps would derive an address whose
/// rules nothing could decode, and refusing at publish is the verdict a
/// package author can read.
fn check_grants_bounds(grants: &GrantsExpr) -> Result<(), SignatureBoundsError> {
    grants.iter().try_for_each(|(behaviour, rule)| {
        // The constant a behaviour's own absence already says is a second
        // spelling of nothing, and saying so at publish is what keeps the
        // sealed table to one spelling per state. Which side a rule's
        // leaves read is the resolver's, because the sealed leaf a
        // declared one becomes is chosen there.
        if *rule
            == if behaviour.asks_about_the_actor() {
                never()
            } else {
                always()
            }
        {
            return Err(SignatureBoundsError::UnadmittedGrant);
        }
        // A movement entry naming a badge through configuration seals as
        // both shapes a holding takes, because a configuration field
        // carries no kind — so the rule the address folds sits one level
        // below the rule the author wrote, and is held to the caps there.
        let widens = !behaviour.asks_about_the_actor()
            && rule
                .leaves()
                .any(|leaf| matches!(leaf, GrantClaim::Config(_)));
        if !rule.within_caps(usize::from(widens)) {
            return Err(SignatureBoundsError::RuleCaps);
        }
        rule.leaves().try_for_each(check_grant_leaf)
    })
}

/// One grant leaf, held to the one link a badge chain may be.
///
/// A badge carries the rules its own address grants, and those rules name
/// no badge: the chain a resource's address folds is one link long, so
/// the depth of a derivation is a property of the resource rather than of
/// how deeply its author nested. The verdict is here as well as at
/// resolution because publish is where a package author can read it.
fn check_grant_leaf(claim: &GrantClaim) -> Result<(), SignatureBoundsError> {
    let rules = match claim {
        GrantClaim::SelfAddr | GrantClaim::Config(_) => return Ok(()),
        GrantClaim::SelfBadge { rules, .. } | GrantClaim::SelfInstance { rules, .. } => rules,
    };
    rules.iter().try_for_each(|(_, rule)| {
        if !rule.within_caps(0) {
            return Err(SignatureBoundsError::RuleCaps);
        }
        rule.leaves().try_for_each(|leaf| match leaf {
            GrantClaim::SelfAddr | GrantClaim::Config(_) => Ok(()),
            GrantClaim::SelfBadge { .. } | GrantClaim::SelfInstance { .. } => {
                Err(SignatureBoundsError::BadgeChainTooDeep)
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::{ShapeFault, ShapeField, ShapeTable, TypeShape};
    use hyperscale_vm_types::Moves;

    use super::super::fixtures::{a_resource, one_clause, own_interval, own_point};
    use super::*;
    use crate::dsl::{
        Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, ModeExpr,
        SlotRef, TargetExpr,
    };
    use crate::metadata::{
        LeafForm, MAX_SHAPE_DEPTH, PackageMetadata, SlotKind, SlotShape, reserved_shape,
    };
    use crate::rule::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, RuleExpr};
    use crate::signature::{AbiParam, MethodSignature};
    use crate::types::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_ITEMS, SlotId};
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
            Err(MetadataBoundsError::Type {
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
            Err(MetadataBoundsError::Type {
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
            Err(MetadataBoundsError::Type {
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
            Err(MetadataBoundsError::EventWithoutShape {
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
            Err(MetadataBoundsError::EventNamedTwice {
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
            Err(MetadataBoundsError::Slot {
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
            Err(MetadataBoundsError::SlotOutsideBand { slot: VAULT })
        );
        // The kernel's own band at the top, which no signature reaches.
        assert_eq!(
            check_metadata(&at(KERNEL_SLOT_BASE)),
            Err(MetadataBoundsError::SlotOutsideBand {
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
        let disagreed = |slot| MetadataBoundsError::SlotHoldsTwoThings {
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
            Err(MetadataBoundsError::ReservedType {
                name: "resource-address".into(),
            })
        );
        // A name the protocol does not hold is the package's own to spend.
        assert_eq!(
            check_metadata(&declaring(one("outcome", TypeShape::Text))),
            Ok(())
        );
    }

    use crate::signature::Totality;
    use crate::types::Value;

    /// A signature whose only effect points at `expr`.
    fn signature_over(expr: Expr) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(expr),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
            ..MethodSignature::default()
        }
    }

    fn one_method(signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert("m".into(), signature);
        metadata
    }

    /// Both sides of a bound: the structure at it is admitted, the one
    /// past it refused.
    fn assert_bounded(admitted: &PackageMetadata, refused: &PackageMetadata) {
        assert_eq!(check_metadata(admitted), Ok(()));
        assert!(
            check_metadata(refused).is_err(),
            "the checker admitted a structure past the bound"
        );
    }

    /// A left-nested projection chain, the shape the evaluator's own
    /// depth test uses.
    fn nested_projection(depth: usize) -> Expr {
        let mut expr = Expr::Arg(0);
        for _ in 0..depth {
            expr = Expr::Field(Box::new(expr), 0);
        }
        expr
    }

    fn nested_foreach(depth: usize) -> Clause {
        let mut clause = Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        for _ in 0..depth {
            clause = Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        clause
    }

    #[test]
    fn expression_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH))),
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH + 1))),
        );
    }

    #[test]
    fn abi_expressions_are_bounded_like_every_other_walk() {
        let derived = |depth: usize| MethodSignature {
            totality: Totality::Fallible,
            abi: vec![AbiParam::Derived(nested_projection(depth))],
            ..MethodSignature::default()
        };
        assert_bounded(
            &one_method(derived(MAX_EXPR_DEPTH)),
            &one_method(derived(MAX_EXPR_DEPTH + 1)),
        );
    }

    #[test]
    fn clause_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH)],
                ..MethodSignature::default()
            }),
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH + 1)],
                ..MethodSignature::default()
            }),
        );
    }

    #[test]
    fn a_range_cap_is_an_expression_under_the_expression_bounds() {
        // No magnitude bound stands here: what bounds an evaluated cap
        // is the depth `footprint` charges for it. The expression itself
        // walks the same structural bounds as the bounds beside it.
        let capped = |cap: Expr| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                        material: vec![],
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(u128::MAX)),
                        cap,
                    },
                    mode: ModeExpr::Read,
                    denomination: None,
                }],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &capped(nested_projection(MAX_EXPR_DEPTH)),
            &capped(nested_projection(MAX_EXPR_DEPTH + 1)),
        );
    }

    #[test]
    fn a_clause_tree_wider_than_a_signature_can_declare_is_refused() {
        let effect = Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let with = |count: usize| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![effect.clone(); count],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &with(MAX_EFFECTS_PER_SIGNATURE),
            &with(MAX_EFFECTS_PER_SIGNATURE + 1),
        );
    }

    #[test]
    fn literal_nesting_is_bounded_where_admission_bounds_it() {
        let literal = |depth: usize| {
            let mut value = Value::U64(0);
            for _ in 1..depth {
                value = Value::Tuple(vec![value]);
            }
            Expr::Literal(value)
        };
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_DEPTH))),
            &one_method(signature_over(literal(MAX_VALUE_DEPTH + 1))),
        );
    }

    /// A value's width is bounded wherever one comes from.
    ///
    /// The codec refuses an over-wide value on the way in, so a literal
    /// that arrived is already inside the bound; this holds the two
    /// cases no decoder saw — a declaration assembled in memory, and a
    /// list the evaluator would build from the expression's own arity.
    /// What the bound buys is that a walk over a value costs something
    /// the per-clause charge can pay for.
    #[test]
    fn a_value_wider_than_a_walk_is_charged_for_is_refused() {
        let literal = |items: usize| Expr::Literal(Value::List(vec![Value::U64(0); items]));
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_ITEMS))),
            &one_method(signature_over(literal(MAX_VALUE_ITEMS + 1))),
        );

        let built = |items: usize| Expr::List(vec![Expr::Literal(Value::U64(0)); items]);
        assert_bounded(
            &one_method(signature_over(built(MAX_VALUE_ITEMS))),
            &one_method(signature_over(built(MAX_VALUE_ITEMS + 1))),
        );

        let bytes = |len: usize| Expr::Literal(Value::Bytes(vec![0; len]));
        assert_bounded(
            &one_method(signature_over(bytes(MAX_VALUE_BYTES))),
            &one_method(signature_over(bytes(MAX_VALUE_BYTES + 1))),
        );
    }

    /// A declared threshold sits under the caps a stored one is decoded
    /// under, so a signature that publishes cannot evaluate into a rule
    /// the decode gate would refuse.
    #[test]
    fn a_declared_rule_is_held_to_the_stored_rules_caps() {
        let guarded = |rule: RuleExpr| PackageMetadata {
            methods: BTreeMap::from([(
                "m".to_owned(),
                MethodSignature {
                    effects: vec![Clause::Requires { guard: None, rule }],
                    ..MethodSignature::default()
                },
            )]),
            ..PackageMetadata::default()
        };
        let leaf = || RuleExpr::claim(Expr::Config(0));
        let nest = |levels: usize| {
            let mut rule = leaf();
            for _ in 0..levels {
                rule = RuleExpr::CountOf {
                    count: 1,
                    rules: vec![rule],
                };
            }
            rule
        };

        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH - 1))).is_ok());
        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH))).is_err());
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES],
            }))
            .is_ok()
        );
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES + 1],
            }))
            .is_err()
        );

        // The degenerate thresholds a stored rule is refused for: one
        // that admits anyone, and one that admits no one.
        for count in [0, 3] {
            assert!(
                check_metadata(&guarded(RuleExpr::CountOf {
                    count,
                    rules: vec![leaf(), leaf()],
                }))
                .is_err()
            );
        }
    }
}
