//! The declaration gate: the shape rules a method's declared accesses,
//! conditions and issuances are held to.
//!
//! The largest of the three gates and the one an author meets most,
//! because it is where the vocabulary's own sentences are enforced —
//! the per-slot shape table, the agreement two clauses reaching one
//! cell owe each other, what a total mark may carry, and what a reach
//! into a foreign prefix pays in shape.

use std::collections::BTreeMap;

use hyperscale_vm_types::{AddressClass, Moves, Presence};

use crate::dsl::{Clause, Expr, ModeExpr, SlotRef, TargetExpr, slot_of, supports};
use crate::resource::{GrantedBehaviour, ReachedCell, holdings_entry};
use crate::rule::{Rule, RuleLeaf};
use crate::signature::{AbiParam, Issuance, MethodSignature};
use crate::types::{SlotId, Value};
use crate::vocabulary::{AUTH, CONFIG, HALT, INSTANCE, NF_VAULT, RESOURCE, VAULT};
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

/// Why a signature's declared effects are not its to declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    /// A clause targeting a prefix the declaring instance does not own.
    #[error("effect clause {clause} targets a prefix the instance does not own")]
    ForeignPrefix {
        /// The clause's position in a preorder walk of the signature's
        /// effects, `for-each` bodies counted in place.
        clause: u32,
    },
    /// A method claiming totality over a guarded clause. A total leg
    /// runs with every declared handle materialized, and a guarded-out
    /// clause materializes none.
    #[error("a total method materialises every handle it declares, and a guard leaves one absent")]
    GuardedTotality,
    /// A method claiming totality beside a precondition: a condition
    /// clause, or a reservation. Either is a verdict some caller hears,
    /// which is exactly what the mark promises cannot happen.
    #[error("a total method admits every state, and this one declares a precondition")]
    ConditionalTotality,
    /// Two writes on one target requiring opposite presences.
    ///
    /// Refused here as well as where the set is built, because metadata
    /// can be authored rather than derived: the macro sees the body and
    /// refuses at the second call site, and this sees only what was
    /// published.
    #[error("two write clauses on one target require opposite presences")]
    PresenceConflict,
    /// A condition naming a target no access declares under a mode that
    /// can carry the judgment.
    ///
    /// The one check that replaces recovering a gate's cell by shape:
    /// what a condition reads is declared, and therefore provisioned to
    /// every participating shard, by a clause that fires whenever the
    /// condition does.
    #[error("condition clause {clause} names a target no access declares under `Read` or `Write`")]
    ConditionUndeclared {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A presence condition requiring `Either`, which nothing can fail.
    #[error("condition clause {clause} requires `Either` of a leaf, which requires nothing")]
    VacuousCondition {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// An issuance whose mark names nothing.
    #[error("the issued resource carries no mark, and a mark is a resource's own name")]
    UnmarkedIssuance,
    /// One mark issued twice by one method, which would give its body two
    /// indices for one resource.
    #[error("this method issues one mark twice, and a mark names one grant")]
    IssuanceNamedTwice,
    /// A reach declared under a behaviour that governs no foreign
    /// prefix — a movement entry, which is about the holder rather than
    /// about somebody reaching them.
    #[error("clause {clause} reaches a foreign prefix under {behaviour:?}, which governs none")]
    UnreachingBehaviour {
        /// The offending clause.
        clause: u32,
        /// The behaviour named.
        behaviour: GrantedBehaviour,
    },
    /// A reach whose target is the declaring instance's own prefix,
    /// which needs no authority and would take the movement entries off
    /// an ordinary access.
    #[error("clause {clause} reaches under an authority and names its own prefix")]
    ReachesItself {
        /// The offending clause.
        clause: u32,
    },
    /// A reach naming a cell the behaviour admitting it does not govern:
    /// a freeze somewhere other than the holder's halt flag, or a recall
    /// of a cell that holds no value.
    #[error("clause {clause} reaches under {behaviour:?} and names a cell it does not govern")]
    ReachesAnotherCell {
        /// The clause's index in the signature's preorder.
        clause: u32,
        /// The behaviour the reach was declared under.
        behaviour: GrantedBehaviour,
    },
    /// A slot named by an argument on a clause that reaches nothing —
    /// where the shape table has a constant to dispatch on and expects
    /// one. Only a reach makes [`SlotRef::Reached`] admissible.
    ///
    /// [`SlotRef::Reached`]: crate::dsl::SlotRef::Reached
    #[error("clause {clause} takes its slot from an argument and reaches no foreign prefix")]
    SlotWithoutReach {
        /// The clause's index in the signature's preorder.
        clause: u32,
    },
    /// A reach whose target is not keyed first by a resource, so there is
    /// nothing whose entry could admit it.
    #[error(
        "clause {clause} reaches a foreign prefix and is not keyed first by the resource \
         whose entry would admit it"
    )]
    UnkeyedReach {
        /// The offending clause.
        clause: u32,
    },
    /// A total method that brings supply into or out of existence.
    #[error(
        "a total method promises a caller has nothing to hear back, and the entry admitting \
         an issuance or a destruction is a verdict they would"
    )]
    SupplyTotality,
    /// A destroyed parameter that carries no value edge, so there is no
    /// resource for the grant to be over.
    #[error("parameter {param} is declared destroyed and carries no value edge")]
    DestroysNoEdge {
        /// The offending parameter.
        param: u32,
    },
    /// One parameter destroyed twice, which would be two grants over one
    /// bucket.
    #[error("parameter {param} is declared destroyed twice, and one edge is one grant")]
    DestroyedTwice {
        /// The offending parameter.
        param: u32,
    },
    /// A frame issuing a resource whose own grants withhold the
    /// direction it takes. Absence withholds, so a resource nothing may
    /// mint is spelled by granting no `Mint` entry — and a body minting
    /// one is an author who wrote the withholding and the mint together.
    #[error(
        "this method's body reaches {0:?}, and the resource it names grants no entry for it \
         — an absent entry withholds the capability, so a resource that is issued carries a \
         rule saying who may"
    )]
    IssuanceUnadmitted(GrantedBehaviour),
    /// A mint no condition justifies: minting one's own identity takes
    /// satisfying one's own stored rule, and letting a declaration mint
    /// without one would be forgeable identity.
    #[error("mint clause {clause} is justified by no stored-rule condition beside it")]
    UnjustifiedMint {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A badge mint whose possession read is missing, or keyed by a
    /// different expression than the claim — which would let the claim
    /// minted and the thing held name different resources.
    #[error(
        "mint clause {clause} mints a badge without the possession condition keyed by the \
         same expression"
    )]
    MintUnheld {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A granted gate over a resource this method does not move.
    #[error(
        "condition clause {clause} reads a granted rule of a resource this method never \
         denominates, so a caller satisfies it with a resource of their own over value it \
         says nothing about"
    )]
    GrantOverAnother {
        /// The offending clause.
        clause: u32,
    },
    /// A condition whose rule reads what the caller supplies.
    #[error(
        "condition clause {clause} requires authority the caller names, and would admit everyone"
    )]
    CallerNamedCondition {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A denomination list that does not line up with the parameters it
    /// indexes.
    #[error("{found} denominations against {expected} parameters")]
    DenominationArity {
        /// The socket count.
        expected: usize,
        /// The denomination count.
        found: usize,
    },
    /// A denomination at a parameter that carries no value.
    #[error("parameter {param} is declared {kind} and carries no value to denominate")]
    DenominationKind {
        /// The offending position.
        param: u32,
        /// The kind declared there.
        kind: &'static str,
    },
    /// A clause naming a protocol cell in a shape that cell does not
    /// have.
    #[error("effect clause {clause} names slot {slot}, which {wanted}")]
    ProtocolSlotShape {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
        /// The slot named.
        slot: u16,
        /// The shape that slot does have.
        wanted: &'static str,
    },
    /// A denomination that is not the key the cell is reached by.
    ///
    /// A value cell is keyed by what it holds, so a declaration naming a
    /// resource names the key again — which is what makes two clauses
    /// reaching one leaf agree about its contents by construction rather
    /// than by comparison. Disagreeing about what a cell holds is naming
    /// a different cell.
    #[error("effect clause {clause} denominates a cell in something its key does not name")]
    DenominationNotKeyed {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A commutative movement that does not say what it moves.
    ///
    /// `Delta` and `Reserve` move value and do nothing else, so the cell
    /// they name holds value and the declaration owes an answer about
    /// what. Refused again at materialization, which has the evaluated
    /// key to name it by; this is the same verdict where an author can
    /// hear it.
    #[error("effect clause {clause} moves value without saying what it moves")]
    UndenominatedMovement {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A denomination written down as an address of a class that names
    /// no resource.
    ///
    /// Routing refuses every such denomination when it evaluates one;
    /// this is the same verdict at publish, for the cases decidable
    /// there — a literal, or the instance's own address, which is a
    /// component's — so an author hears it about their package rather
    /// than a caller about their manifest.
    #[error("effect clause {clause} denominates in a {found} address, which names no resource")]
    NotAResource {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
        /// The class the expression is decided to carry.
        found: AddressClass,
    },
    /// A parameter's denomination written down as an address of a class
    /// that names no resource — [`DeclarationError::NotAResource`]'s
    /// verdict, at the position a signature denominates an edge.
    #[error("parameter {param}'s denomination is a {found} address, which names no resource")]
    ParamNotAResource {
        /// The parameter position the denomination indexes.
        param: u32,
        /// The class the expression is decided to carry.
        found: AddressClass,
    },
    /// An output projection written down as an address of a class that
    /// names no resource — the same verdict, at the position a signature
    /// says what its edges carry.
    #[error("output {output} projects a {found} address, which names no resource")]
    OutputNotAResource {
        /// The output's position in the signature's projection list.
        output: u32,
        /// The class the expression is decided to carry.
        found: AddressClass,
    },
    /// A clause naming a slot no cell is assigned: unassigned below
    /// [`PACKAGE_SLOT_BASE`], or the kernel's own band at the top.
    #[error("effect clause {clause} names slot {slot}, which no cell is assigned")]
    ReservedSlot {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
        /// The slot named.
        slot: u16,
    },
    /// A mode and target pairing the world hands out no handle for.
    ///
    /// Every declared access is a capability a body borrows, and which
    /// one is a function of the target's shape and the mode: a leaf is
    /// read, rewritten or moved through, and an interval is read or
    /// rewritten. A pairing outside that materializes nothing, so it
    /// is a clause every call aborts at — and a declaration stating an
    /// access no execution can hold is worse than one that never
    /// published. Refused again at materialization, which is where the
    /// abort would have come from.
    #[error("effect clause {clause} pairs a mode and a target no handle is built for")]
    UnsupportedAccess {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// Two clauses reaching one cell and disagreeing about what it holds.
    ///
    /// A denomination chooses which handle the clause materializes, so a
    /// leaf one clause denominates and another does not is a leaf a body
    /// holds twice: once as the cell value moves through, once as the
    /// cell bytes are written to. Writing a balance through the second
    /// and debiting it through the first is value from nowhere.
    ///
    /// Refused again at materialization, which has the evaluated keys;
    /// this is the same verdict where an author can hear it.
    #[error("effect clause {clause} names a cell another clause says holds something else")]
    MixedContents {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
}

/// Whether a target names the declaring instance's own prefix.
///
/// The owner half of a key is either written as `SelfAddr` or derived
/// under it: a fresh key is minted under the instance that creates it, and
/// a child key names its owner outright. Everything else — an argument, a
/// configuration slot, a `for-each` binding, a literal — is another
/// object's prefix, whatever the author meant by it.
/// Judge a clause that reaches a prefix that is not the declaring
/// instance's own.
///
/// Three things make the reach safe, and all three are shape rather
/// than review. **The owner is not this instance**, because a reach into
/// one's own prefix is an ordinary access wearing an authority it does
/// not need — and admitting it would put an injected entry where the
/// movement entries belong. **The target is keyed first by a
/// resource**, which is the resource whose entry admits the reach: the
/// key is derived from it, so naming a slot cannot name a cell holding
/// something else, and the entry judged is always the entry of the thing
/// actually reached. And **the cell is the one the behaviour is about**,
/// because an entry admits a reach for what that entry governs — a
/// freeze entry says who may raise the holder's flag, not who may write
/// anything at all under their prefix.
///
/// Which cell that is is the behaviour's answer. A halt flag is one
/// slot the vocabulary fixes, so it is named by its slot; a holding is
/// wherever the holder keeps it, so it is named by its denomination —
/// the only thing that says a cell holds value, and the thing every
/// value cell already has to say.
///
/// The entry itself is injected at admission rather than declared here.
/// A package will not gate itself on a rule it does not want, so the
/// requirement comes from the resource — which is what makes omission
/// inexpressible, on the same terms a movement requirement is.
fn judge_reach(
    clause: u32,
    target: &TargetExpr,
    denomination: Option<&Expr>,
    behaviour: GrantedBehaviour,
) -> Result<(), DeclarationError> {
    let Some(reached) = behaviour.reaches() else {
        return Err(DeclarationError::UnreachingBehaviour { clause, behaviour });
    };
    if targets_own_prefix(target) {
        return Err(DeclarationError::ReachesItself { clause });
    }
    let Some((slot, material)) = slot_of(target) else {
        return Err(DeclarationError::UnkeyedReach { clause });
    };
    let keyed_by_a_resource = material.first().is_some_and(|first| {
        decided_class(first)
            .is_none_or(|found| matches!(found, AddressClass::Resource | AddressClass::Restricted))
    });
    if !keyed_by_a_resource {
        return Err(DeclarationError::UnkeyedReach { clause });
    }
    let names_its_cell = match reached {
        ReachedCell::Halt => slot.fixed() == Some(HALT),
        ReachedCell::Holding => denomination.is_some(),
    };
    if !names_its_cell {
        return Err(DeclarationError::ReachesAnotherCell { clause, behaviour });
    }
    Ok(())
}

fn targets_own_prefix(target: &TargetExpr) -> bool {
    match target {
        TargetExpr::Point(key) => match key {
            Expr::ChildKey { owner, .. } => matches!(**owner, Expr::SelfAddr),
            Expr::FreshKey { .. } => true,
            _ => false,
        },
        TargetExpr::Entry { owner, .. } | TargetExpr::Range { owner, .. } => {
            matches!(owner, Expr::SelfAddr)
        }
    }
}

/// What a target names as the thing whose contents are one fact: the
/// leaf a point names, or the collection an entry or an interval sits in.
///
/// Not the target itself, because two intervals of one collection are two
/// targets over one set of entries — so an interval saying its entries
/// are instances and an overlapping one saying they are bytes are two
/// answers about the same entries, and comparing targets would let them
/// both through.
///
/// The declared half of the pair the vocabulary keeps everywhere else —
/// `ModeExpr` beside `Mode`, [`TargetExpr`] beside `EffectTarget`. This
/// one is over expressions and asks whether a *signature* is
/// self-consistent; the kernel's `Contents` is over evaluated keys and
/// asks whether one transaction's clauses are. Two tiers of one
/// question, and neither can stand for the other: two expressions that
/// differ can evaluate to one cell, and two that agree are one answer
/// before anything runs.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum ContentsExpr<'a> {
    /// One leaf, as the expression naming it.
    Leaf(&'a Expr),
    /// Every entry of one collection, as the owner and identity it hangs
    /// under.
    Entries(&'a Expr, &'a SlotRef, &'a [Expr]),
}

/// Which cell's contents a clause is an answer about.
fn contents(target: &TargetExpr) -> ContentsExpr<'_> {
    match target {
        TargetExpr::Point(key) => ContentsExpr::Leaf(key),
        TargetExpr::Entry {
            owner,
            collection,
            material,
            ..
        }
        | TargetExpr::Range {
            owner,
            collection,
            material,
            ..
        } => ContentsExpr::Entries(owner, collection, material),
    }
}

/// Judge a clause naming a cell the protocol derives keys for.
///
/// The vocabulary below [`PACKAGE_SLOT_BASE`] is the set of cells an
/// engine finds without consulting any metadata, which is what makes
/// their values protocol facts rather than one package's business. A
/// fact has a shape: a vault holds an amount keyed by the resource it
/// holds, a record is written when the thing it describes comes into
/// being, a configuration leaf is written once. So the shape is not the
/// declaring package's to choose either, and a clause naming one of
/// these cells any other way is a clause whose leaf would be read as
/// something it does not hold.
///
/// Judgeable at all because the slot is authenticated by the derivation
/// that consumes it: [`child_key`] hashes the slot into the key, and
/// [`targets_own_prefix`] admits no point target that reaches a leaf
/// without spelling one. A declaration landing on a vault therefore
/// *says* `VAULT`, and cannot be written to land there while saying
/// something else.
///
/// The kernel's own band at the top is refused outright, as is any slot
/// below the base the vocabulary has not assigned. Neither names a cell,
/// and a slot naming no cell has no shape to be held to.
fn protocol_shape(
    clause: u32,
    target: &TargetExpr,
    mode: &ModeExpr,
    denomination: Option<&Expr>,
    requires: Option<Presence>,
) -> Result<(), DeclarationError> {
    let Some((slot, material)) = slot_of(target) else {
        return Ok(());
    };
    // A slot an argument names has no constant to dispatch on, so the
    // table has nothing to say about it here. What it would have said is
    // said where the argument has a value, narrowed to the one sentence
    // that survives not knowing which cell is meant: a reach names a
    // cell value is kept at.
    let Some(slot) = slot.fixed() else {
        return Ok(());
    };
    let reserved = || DeclarationError::ReservedSlot {
        clause,
        slot: slot.0,
    };
    if slot.0 >= KERNEL_SLOT_BASE {
        return Err(reserved());
    }
    if slot.0 >= PACKAGE_SLOT_BASE {
        return Ok(());
    }
    let Some((shaped, wanted)) =
        vocabulary_shape(slot, target, material, mode, denomination, requires)
    else {
        return Err(reserved());
    };
    if shaped {
        Ok(())
    } else {
        Err(DeclarationError::ProtocolSlotShape {
            clause,
            slot: slot.0,
            wanted,
        })
    }
}

/// Whether a clause's target, mode and denomination are the shape the
/// vocabulary fixes for `slot`, and the sentence saying what that shape
/// is. `None` where the vocabulary assigns the slot no cell at all.
///
/// One arm per cell, and the sentence beside each is what an author is
/// told: a refusal naming only the slot number would leave them to read
/// this table out of the source.
fn vocabulary_shape(
    slot: SlotId,
    target: &TargetExpr,
    material: &[Expr],
    mode: &ModeExpr,
    denomination: Option<&Expr>,
    requires: Option<Presence>,
) -> Option<(bool, &'static str)> {
    let point = matches!(target, TargetExpr::Point(_));
    // A value cell is keyed by what it holds, so where the declaration
    // names a resource it names the key again. The key is what makes one
    // leaf hold one resource; a second answer beside it would be the
    // leaf and the declaration disagreeing about what came out of it.
    //
    // Named in every mode the cell is reached in, a read included. Which
    // handle a clause materializes turns on the denomination, and a
    // clause that says nothing gets the one bytes come through — so a
    // silent read of a vault would be the one place a balance is still
    // read as bytes, which is the whole of what these types exist to
    // stop.
    let keyed_by_what_it_holds =
        matches!((material, denomination), ([held], Some(named)) if named == held);
    let bare = material.is_empty() && denomination.is_none();
    let keyed = |terms: usize| material.len() == terms && denomination.is_none();
    // A write that creates carries its one-way door as a condition
    // beside it: a `Holds { .., Absent }` on the same target, firing
    // whenever the write does — which is what `requires` says.
    let writes_where = |presence: Option<Presence>| {
        matches!(mode, ModeExpr::Read)
            || (matches!(mode, ModeExpr::Write { .. })
                && (presence.is_none() || requires == presence))
    };
    let creates = writes_where(Some(Presence::Absent));
    // A cell whose lifetime one owner runs is written at both ends of
    // it, and which end this is stands beside the write: absent where
    // the cell begins, present where it changes or ends. Stated either
    // way, because a write that said neither would be a body reaching a
    // leaf without knowing whether anything is there.
    let lifetime = writes_where(None) && (matches!(mode, ModeExpr::Read) || requires.is_some());

    let (shaped, wanted) = match slot {
        VAULT => (
            point
                && keyed_by_what_it_holds
                && matches!(
                    mode,
                    ModeExpr::Read
                        | ModeExpr::Write { .. }
                        | ModeExpr::Delta
                        | ModeExpr::Credit
                        | ModeExpr::Reserve(_)
                ),
            "holds a fungible balance: one leaf, keyed by the resource it holds, \
             denominated in that resource",
        ),
        // Instances are a quantity too, and the interval they sit in is
        // the holdings of exactly one resource.
        NF_VAULT => (
            !point
                && keyed_by_what_it_holds
                && matches!(mode, ModeExpr::Read | ModeExpr::Write { .. }),
            "holds a resource's instances: an interval or one of its entries, keyed by \
             that resource and denominated in it",
        ),
        CONFIG => (
            point && bare && creates,
            "is the creation-fixed configuration leaf: one leaf, no material, \
             written where absent and never rewritten",
        ),
        AUTH => (
            point && bare && matches!(mode, ModeExpr::Read | ModeExpr::Write { .. }),
            "is the stored authority cell: one leaf, no material, read or rewritten whole",
        ),
        // The halt flag's whole content is whether it is there, so it is
        // written and ended rather than rewritten, and read by the
        // condition every movement of a freezable resource carries. Keyed
        // by the resource it halts and denominated in nothing: it holds a
        // fact, not value.
        HALT => (
            point && keyed(1) && matches!(mode, ModeExpr::Read | ModeExpr::Write { .. }),
            "is a holder's halt flag for one resource: one leaf, keyed by that resource, \
             holding no value",
        ),
        // A record and an instance's data are written when the thing
        // they describe comes into existence and not again, so creating
        // one and overwriting one are different declarations and the
        // shard holding the leaf tells them apart before any body runs.
        RESOURCE => (
            point && keyed(1) && creates,
            "is a resource's record under its issuer: one leaf, keyed by the resource, \
             written where absent",
        ),
        INSTANCE => (
            point && keyed(2) && lifetime,
            "is an instance's data under its issuer: one leaf, keyed by the resource and \
             the id, written where the leaf's presence is stated — absent at the mint, \
             present at a rewrite or a retirement",
        ),
        // Below the base and spoken for by nothing: the vocabulary
        // reserves room for a cell it has not defined yet, and a slot
        // naming no cell has no shape to be held to.
        _ => return None,
    };
    Some((shaped, wanted))
}

/// Whether two clauses' guards are each other's negation, so no
/// evaluation declares both.
///
/// Syntactic, because this runs at publish where no arguments exist —
/// the same standard the target comparison beside it holds to. An
/// unguarded clause is complementary to nothing: it fires always, so it
/// meets whatever else lands on its target.
fn complementary(left: Option<&Expr>, right: Option<&Expr>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    matches!(left, Expr::Not(inner) if inner.as_ref() == right)
        || matches!(right, Expr::Not(inner) if inner.as_ref() == left)
}

/// The class a denomination-position expression is already known to
/// carry at publish, if it is decidable there: a literal address carries
/// its own class, and the declaring instance's address is a component's.
/// Everything else is an expression over inputs, evaluated — and class
/// checked — at admission and routing.
const fn decided_class(expr: &Expr) -> Option<AddressClass> {
    match expr {
        Expr::Literal(Value::Address(address)) => Some(address.class()),
        Expr::SelfAddr => Some(AddressClass::Component),
        _ => None,
    }
}

/// Refuse an output projection decided to carry a class that names no
/// resource.
///
/// An output projects what an edge carries, so a projection of the wrong
/// class is a method no manifest can consume — the same verdict admission
/// reaches by evaluating it, where it is decidable at publish. A
/// non-fungible projection is judged at the resource it names.
fn judge_outputs(outputs: &[Expr]) -> Result<(), DeclarationError> {
    for (slot, output) in outputs.iter().enumerate() {
        let resource = match output {
            Expr::NfBucket { resource, .. } => resource,
            expr => expr,
        };
        if let Some(found) = decided_class(resource)
            && found != AddressClass::Resource
        {
            return Err(DeclarationError::OutputNotAResource {
                output: u32::try_from(slot).unwrap_or(u32::MAX),
                found,
            });
        }
    }
    Ok(())
}

/// Judge one access clause: whose prefix it names, which cell under that
/// prefix, whether the world hands out a handle for reaching it that way,
/// what that cell holds, and what it requires of the leaf.
///
/// Ordered as an author would want to hear it. A clause reaching a
/// stranger's leaf is wrong about more than its shape, and a clause
/// naming a protocol cell hears that cell's own sentence before the
/// general rules the sentence is a special case of.
fn judge_access(clause: u32, access: &Clause, flat: &[&Clause]) -> Result<(), DeclarationError> {
    let Clause::Effect {
        guard,
        target,
        mode,
        denomination,
        reach,
    } = access
    else {
        return Ok(());
    };
    let denomination = denomination.as_deref();
    // A reach is the one thing that lets a declaration name a prefix
    // that is not its own, and it pays for it in shape: the target is
    // keyed first by a resource, which is what the injected entry
    // resolves against and what makes naming a slot unable to name a
    // cell holding something else.
    if let Some(behaviour) = reach {
        judge_reach(clause, target, denomination, *behaviour)?;
    } else {
        if !targets_own_prefix(target) {
            return Err(DeclarationError::ForeignPrefix { clause });
        }
        // A slot an argument names is what makes a reach total over the
        // slots a holder keeps value at, and it is that and nothing
        // else: everywhere else the slot is the constant the per-slot
        // shape table dispatches on.
        if slot_of(target).is_some_and(|(slot, _)| slot.fixed().is_none()) {
            return Err(DeclarationError::SlotWithoutReach { clause });
        }
    }
    // What this write says about the leaf's presence: a `Holds` on the
    // same target, firing whenever the write does. The one-way door a
    // creation carries is the `Absent` case of it.
    //
    // The first such clause is the answer, because any two that both
    // match this write already agree. Matching takes an absent guard or
    // the write's own, so no two matches are complementary; the presence
    // fold makes every non-complementary pair on one target meet, and
    // `Either` — the one presence that meets a disagreeing partner — is
    // refused outright as a condition nothing can fail.
    let requires = flat.iter().find_map(|beside| match beside {
        Clause::Requires {
            guard: condition_guard,
            rule:
                Rule::Require(RuleLeaf::Presence {
                    target: required,
                    expect: presence,
                }),
        } if **required == *target
            && (condition_guard.is_none() || condition_guard.as_deref() == guard.as_deref()) =>
        {
            Some(*presence)
        }
        _ => None,
    });
    protocol_shape(clause, target, mode, denomination, requires)?;
    // And whether the world hands out anything for this pairing at all.
    // Asked of the clause through the same function routing asks, so
    // publish refuses exactly what materialization could not have built.
    if !supports(access) {
        return Err(DeclarationError::UnsupportedAccess { clause });
    }
    // What a cell holds is part of the key it is reached by, so the two
    // are one expression written twice. A fresh key carries no material
    // and so holds no value: nothing could find it again to take any
    // out.
    if let Some(held) = denomination
        && slot_of(target).is_none_or(|(_, material)| material.first() != Some(held))
    {
        return Err(DeclarationError::DenominationNotKeyed { clause });
    }
    if denomination.is_none() && matches!(mode, ModeExpr::Delta | ModeExpr::Reserve(_)) {
        return Err(DeclarationError::UndenominatedMovement { clause });
    }
    // The class is decidable at publish only where the denomination is
    // written down; an expression over inputs meets the same refusal at
    // routing, where it is evaluated.
    if let Some(expr) = denomination
        && let Some(found) = decided_class(expr)
        && found != AddressClass::Resource
    {
        return Err(DeclarationError::NotAResource { clause, found });
    }
    Ok(())
}

/// Whether a method writes the component's own configuration leaf — the
/// one write the `CONFIG` slot admits, and so the seal that makes a
/// component actual.
///
/// Two readers. The publish gate refuses a package declaring no such
/// method, whose components could never be called; and admission admits
/// a presented record for a seal's own node and nowhere else, because
/// the seal is the one call whose target has no committed record to
/// resolve against.
///
/// The `Absent` door beside it is not asked about here: the slot's shape
/// admits no `CONFIG` write without one.
#[must_use]
pub fn seals(signature: &MethodSignature) -> bool {
    signature
        .effects
        .iter()
        .flat_map(Clause::effects)
        .any(|clause| {
            matches!(
                clause,
                Clause::Effect {
            reach: None,
                    target: TargetExpr::Point(Expr::ChildKey { owner, slot, material }),
                    mode: ModeExpr::Write { .. },
                    ..
                } if **owner == Expr::SelfAddr
                    && slot.fixed() == Some(CONFIG)
                    && material.is_empty()
            )
        })
}

/// The clauses a component's seal declares: the write of its own
/// configuration leaf, under the one-way door its absence is.
#[must_use]
pub fn seal_clauses() -> Vec<Clause> {
    let leaf = || {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(CONFIG),
            material: Vec::new(),
        })
    };
    vec![
        Clause::Requires {
            guard: None,
            rule: Rule::Require(RuleLeaf::Presence {
                target: Box::new(leaf()),
                expect: Presence::Absent,
            }),
        },
        Clause::Effect {
            guard: None,
            target: leaf(),
            mode: ModeExpr::Write { moves: Moves::Both },
            denomination: None,
            reach: None,
        },
    ]
}

/// What a total mark cannot stand beside, read off the declaration.
fn check_totality(signature: &MethodSignature, flat: &[&Clause]) -> Result<(), DeclarationError> {
    if !signature.totality.is_total() {
        return Ok(());
    }
    // The mark promises a caller may commit without waiting to hear
    // back, so every verdict the frame carries has to land before any
    // leg does. Admission answers a rule reading the node's own evidence
    // and materialization answers one reading committed state, and both
    // land before anything commits; a rule reaching a *stored* rule
    // needs the session, which only the declaring node's own walk holds
    // — after a caller may already have committed.
    //
    // A reservation stays refused for a different reason, and it is the
    // one the mark is actually about: a reservation is a verdict on the
    // caller's own request. An injected fence is a verdict on the
    // target's standing state, which the caller was never promised
    // anything about.
    if flat.iter().any(|clause| {
        matches!(clause, Clause::Requires { rule, .. }
                if rule.leaves().any(|leaf| matches!(leaf, RuleLeaf::Stored { .. })))
            || matches!(
                clause,
                Clause::Effect {
                    reach: None,
                    mode: ModeExpr::Reserve(_),
                    ..
                }
            )
    }) {
        return Err(DeclarationError::ConditionalTotality);
    }
    // Supply is the settlement model's question rather than placement's.
    // An issuance entry reads the node's own evidence, so admission
    // answers it before any leg runs and the mark would survive it — but
    // what a leg nothing waits on may do to a shard's supply
    // accumulator is attested with that leg, and the answer is owed
    // there rather than here.
    if !(signature.issues.is_empty() && signature.destroys.is_empty()) {
        return Err(DeclarationError::SupplyTotality);
    }
    Ok(())
}

/// Judge a signature's declared effects against the prefix and the cells
/// they are the signature's to declare.
///
/// A declaration bounds what execution may touch, and this bounds what a
/// declaration may claim. Two questions, and the answers are independent.
/// Whose prefix: an object's cells are reachable by calling it, never by
/// naming them — refused here so an author hears about it, and again on
/// the evaluated effect at routing, where no expression shape can be
/// overlooked. Which cell under that prefix: everything an engine derives
/// a key for without reading metadata has a shape, and a package reaching
/// one of those leaves reaches it in that shape or not at all.
///
/// # Errors
///
/// [`DeclarationError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_declarations(signature: &MethodSignature) -> Result<(), DeclarationError> {
    // The tree is walked once; every judgment below reads this preorder,
    // which is the numbering a clause index names.
    let flat: Vec<&Clause> = signature.effects.iter().flat_map(Clause::effects).collect();
    check_agreement(&flat)?;
    // Trap freedom for a total leg rests on every handle being
    // materialized from the declared effect set, and an absent
    // capability is precisely a change to that. Precision is what a
    // total method trades for the mark, and it trades it in the one
    // direction that keeps both properties true.
    if signature.totality.is_total()
        && (flat.iter().any(|clause| clause.guard().is_some())
            || signature
                .abi
                .iter()
                .any(|binding| matches!(binding, AbiParam::Guard(_))))
    {
        return Err(DeclarationError::GuardedTotality);
    }
    check_totality(signature, &flat)?;
    // A denomination is read at the position it indexes, so a list that
    // does not cover the parameters is one whose entries name positions
    // nobody agrees on. An empty list is the method that denominates
    // nothing, which is most of them.
    if !signature.denominations.is_empty()
        && signature.denominations.len() != signature.params.len()
    {
        return Err(DeclarationError::DenominationArity {
            expected: signature.params.len(),
            found: signature.denominations.len(),
        });
    }
    for (position, denomination) in signature.denominations.iter().enumerate() {
        let param = u32::try_from(position).unwrap_or(u32::MAX);
        if denomination.is_some()
            && let Some(kind) = signature
                .params
                .get(position)
                .filter(|kind| !kind.is_edge())
        {
            return Err(DeclarationError::DenominationKind {
                param,
                kind: kind.name(),
            });
        }
        // The class verdict a clause denomination gets, at this position:
        // admission refuses the evaluated expression, and one already
        // written down is that refusal decidable where the author is.
        if let Some(expr) = denomination
            && let Some(found) = decided_class(expr)
            && found != AddressClass::Resource
        {
            return Err(DeclarationError::ParamNotAResource { param, found });
        }
    }
    // A mark is the name a resource is declared under, and the
    // derivation folds it as one part of the material. An empty one
    // names nothing and folds to no material at all, which is an address
    // reached by saying less rather than by saying something.
    if signature
        .issues
        .iter()
        .any(|issuance| issuance.mark.is_empty())
    {
        return Err(DeclarationError::UnmarkedIssuance);
    }
    // One mark names one grant, so a method naming a mark twice would
    // hand its body two indices for one resource and two entries to
    // answer for. The list is the body's own order and nothing sorts it,
    // so distinctness is what makes an index name one thing.
    for (position, issuance) in signature.issues.iter().enumerate() {
        if signature.issues[..position]
            .iter()
            .any(|earlier| earlier.mark == issuance.mark && earlier.kind == issuance.kind)
        {
            return Err(DeclarationError::IssuanceNamedTwice);
        }
    }
    // A destroyed edge is a value edge, and named once: the grant is per
    // bucket, so naming a parameter twice would be two grants over one
    // and a position naming a value the method was never handed is a
    // grant over nothing.
    for (position, param) in signature.destroys.iter().enumerate() {
        let kind = usize::try_from(*param)
            .ok()
            .and_then(|at| signature.params.get(at));
        if !kind.is_some_and(|kind| kind.is_edge()) {
            return Err(DeclarationError::DestroysNoEdge { param: *param });
        }
        if signature.destroys[..position].contains(param) {
            return Err(DeclarationError::DestroyedTwice { param: *param });
        }
    }
    // And a resource is issued only where its own address says who may.
    // Decidable here because the grants a mint derives through ride the
    // declaration itself, so the author is told where they wrote the
    // pair rather than a caller told where they met it.
    for issuance in &signature.issues {
        if founding(issuance, &flat) {
            continue;
        }
        for behaviour in issuance.direction.behaviours() {
            if issuance.grants.get(*behaviour).is_none() {
                return Err(DeclarationError::IssuanceUnadmitted(*behaviour));
            }
        }
    }
    // And at the third position a signature names resources.
    judge_outputs(&signature.outputs)?;
    for (index, clause) in flat.iter().enumerate() {
        judge_access(u32::try_from(index).unwrap_or(u32::MAX), clause, &flat)?;
    }
    check_conditions(&flat)
}

/// Whether this frame is the one that brings its issued resource into
/// existence.
///
/// Founding is not minting. A resource's record is written where the
/// resource comes into being and never again — the `RESOURCE` slot
/// admits no second write, held by the shape table above — so a supply
/// stated at that one call is the supply the resource comes up holding
/// and the door is what caps it. That is what makes capped supply an
/// *absent* `Mint` entry rather than an unspellable one: without the
/// exemption, creating the supply would itself be the minting the
/// absence forbids, and a capped resource could only ever hold nothing.
///
/// Read off the declaration rather than declared, on the terms the
/// instantiation fence is read off one: the frame that writes the leaf
/// is the creation, and a frame cannot claim to be it without doing it.
#[must_use]
pub fn founds_its_resource(issuance: &Issuance, signature: &MethodSignature) -> bool {
    let flat: Vec<&Clause> = signature.effects.iter().flat_map(Clause::effects).collect();
    founding(issuance, &flat)
}

/// The same over a preorder already walked.
fn founding(issuance: &Issuance, flat: &[&Clause]) -> bool {
    flat.iter().any(|clause| {
        let Clause::Effect {
            reach: None,
            target:
                TargetExpr::Point(Expr::ChildKey {
                    owner,
                    slot,
                    material,
                }),
            mode: ModeExpr::Write { .. },
            ..
        } = clause
        else {
            return false;
        };
        matches!(**owner, Expr::SelfAddr)
            && slot.fixed() == Some(RESOURCE)
            && matches!(
                material.as_slice(),
                [Expr::SelfResource { kind, material, grants }]
                    if *kind == issuance.kind
                        && *grants == issuance.grants
                        && matches!(
                            material.as_slice(),
                            [Expr::Literal(Value::Bytes(mark))] if *mark == issuance.mark
                        )
            )
    })
}

/// The agreement pass: two clauses reaching one target say the same
/// thing about it — what has to be there, and whether it holds value —
/// or the declaration names a leaf no execution has.
fn check_agreement(flat: &[&Clause]) -> Result<(), DeclarationError> {
    // Two presence conditions on one target that can both fire, each
    // way, are a requirement nothing satisfies.
    //
    // Compared by target expression rather than by evaluated key,
    // because this runs at publish where no arguments exist — which
    // catches the contradiction an author wrote and leaves the one two
    // different expressions happen to evaluate onto for the set to fold.
    //
    // Two clauses that cannot both fire are not a contradiction, and
    // "create it if absent, otherwise update it" is exactly the shape
    // that takes. So the comparison reads guards beside targets and lets
    // complementary ones through — syntactically complementary, one the
    // `Not` of the other, which is what an `if`/`else` emits and the
    // same standard the target comparison beside it already holds to.
    // The evaluated conflict in `EffectSet::insert` is untouched: two
    // clauses that cannot both fire never both land.
    //
    // Grouped by target, and every pair within a group rather than a
    // fold into one requirement per target, because co-firing is a
    // relation between two clauses and not a property of the target they
    // share: a clause complementary to one of the others still meets all
    // the rest, and a fold that stopped at the first meeting would never
    // ask about them. Nothing is lost by comparing originals — `Either`
    // meets everything, so an accumulated requirement is only ever one
    // of the two it came from, and a contradiction a fold could reach is
    // one some pair already has.
    let mut required: BTreeMap<&TargetExpr, Vec<(Option<&Expr>, Presence)>> = BTreeMap::new();
    for clause in flat {
        if let Clause::Requires {
            guard,
            rule:
                Rule::Require(RuleLeaf::Presence {
                    target,
                    expect: presence,
                }),
        } = clause
        {
            required
                .entry(target)
                .or_default()
                .push((guard.as_deref(), *presence));
        }
    }
    for shared in required.values() {
        for (index, (guard, requires)) in shared.iter().enumerate() {
            for (seen_guard, prior) in &shared[..index] {
                if !complementary(*seen_guard, *guard) {
                    prior
                        .meet(*requires)
                        .ok_or(DeclarationError::PresenceConflict)?;
                }
            }
        }
    }
    // What a cell holds is a fact about the cell rather than about the
    // clause that reached it, and the denomination is what chooses which
    // handle a clause materializes — so a leaf one clause denominates
    // and another does not is a leaf a body holds as a vault and as a
    // byte cell at once. Writing a balance through the byte handle and
    // debiting it through the value one is a balance nothing moved.
    //
    // Folded by container rather than by target: two intervals of one
    // collection are two targets over one set of entries, and the
    // disagreement is about the entries.
    //
    // No guard exemption, unlike the presence fold above. A presence is
    // a question one execution answers, and complementary arms answer it
    // differently on purpose; what a cell holds is not a question an
    // execution answers at all.
    let mut contents_hold_value: BTreeMap<ContentsExpr<'_>, bool> = BTreeMap::new();
    for (index, clause) in flat.iter().enumerate() {
        let Clause::Effect {
            reach: None,
            target,
            denomination,
            ..
        } = clause
        else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let value = denomination.is_some();
        if *contents_hold_value.entry(contents(target)).or_insert(value) != value {
            return Err(DeclarationError::MixedContents { clause });
        }
    }
    Ok(())
}

/// The condition pass: every target a condition names is declared as
/// an access — under `Read` or `Write`, which is what makes the
/// judgment coherent, by a clause that fires whenever the condition
/// does. The one check that replaces recovering a gate's cell by
/// shape. Guards compare syntactically, the same standard the
/// presence pass holds to: an unguarded access backs any condition, a
/// guarded one backs a condition under the same guard.
fn check_conditions(flat: &[&Clause]) -> Result<(), DeclarationError> {
    let declares =
        |target: &TargetExpr, under: Option<&Expr>, admits: &dyn Fn(&ModeExpr) -> bool| {
            flat.iter().any(|clause| {
                matches!(
                        clause,
                        Clause::Effect {
                reach: None,
                            guard,
                            target: declared,
                            mode,
                            ..
                        } if declared == target
                            && admits(mode)
                            && (guard.is_none() || guard.as_deref() == under)
                    )
            })
        };
    let coherent = |mode: &ModeExpr| matches!(mode, ModeExpr::Read | ModeExpr::Write { .. });
    for (index, clause) in flat.iter().enumerate() {
        let Clause::Requires { guard, rule } = clause else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let under = guard.as_deref();
        if rule.names_caller_authority() {
            return Err(DeclarationError::CallerNamedCondition { clause });
        }
        for leaf in rule.leaves() {
            match leaf {
                RuleLeaf::Presence { target, expect } => {
                    if *expect == Presence::Either {
                        return Err(DeclarationError::VacuousCondition { clause });
                    }
                    if !declares(target, under, &coherent) {
                        return Err(DeclarationError::ConditionUndeclared { clause });
                    }
                }
                RuleLeaf::Stored { cell, .. } => {
                    let point = TargetExpr::Point(cell.clone());
                    if !declares(&point, under, &coherent) {
                        return Err(DeclarationError::ConditionUndeclared { clause });
                    }
                }
                RuleLeaf::Claim(_) => {}
            }
        }
    }
    check_mints(flat)
}

/// The mint pass: a mint is justified by a condition the same
/// declaration carries. Minting one's own identity takes satisfying
/// one's own stored rule; minting a badge takes that plus holding it,
/// the possession read keyed by the same expressions the mint names —
/// so the claim minted and the thing held are one resource because one
/// expression writes both.
fn check_mints(flat: &[&Clause]) -> Result<(), DeclarationError> {
    // Minting one's own identity takes satisfying one's own stored rule;
    // minting a badge takes that plus holding it, the possession read
    // keyed by the same expressions the mint names — so the claim minted
    // and the thing held are one resource because one expression writes
    // both.
    for (index, clause) in flat.iter().enumerate() {
        let Clause::Mints { guard, claim } = clause else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let under = guard.as_deref();
        let justified = flat.iter().any(|beside| {
            matches!(
                beside,
                Clause::Requires {
                    guard: condition_guard,
                    rule,
                } if rule
                    .leaves()
                    .any(|leaf| matches!(leaf, RuleLeaf::Stored { .. }))
                    && (condition_guard.is_none() || condition_guard.as_deref() == under)
            )
        });
        if !justified {
            return Err(DeclarationError::UnjustifiedMint { clause });
        }
        let possession = match claim {
            // The target's own identity: the stored rule alone is the
            // justification.
            Expr::SelfAddr => continue,
            // One instance: held when the badge-keyed holdings entry at
            // the id is there.
            Expr::Tuple(parts) if parts.len() == 2 => {
                holdings_entry(parts[0].clone(), parts[1].clone())
            }
            // A fungible badge: held when the badge-keyed vault is.
            badge => TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(VAULT),
                material: vec![badge.clone()],
            }),
        };
        let held = flat.iter().any(|beside| {
            matches!(
                beside,
                Clause::Requires {
                    guard: condition_guard,
                    rule: Rule::Require(RuleLeaf::Presence {
                        target,
                        expect: Presence::Present,
                    }),
                } if **target == possession
                    && (condition_guard.is_none() || condition_guard.as_deref() == under)
            )
        });
        if !held {
            return Err(DeclarationError::MintUnheld { clause });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use hyperscale_vm_types::{Address, AddressClass, Moves, Presence};

    use super::super::fixtures::{a_resource, one_clause, own_interval, own_point};
    use super::*;
    use crate::dsl::{Clause, Expr, ModeExpr, SlotRef, TargetExpr};
    use crate::envelope::NULLIFIER_SLOT;
    use crate::metadata::PACKAGE_SLOT;
    use crate::resource::{GrantsExpr, ResourceKind};
    use crate::rule::{GrantClaim, GrantRuleExpr, RuleExpr, RuleLeaf};
    use crate::signature::{AbiParam, Issuance, Issued, MethodSignature, ParamType, Totality};
    use crate::types::{SlotId, package_slot};
    use crate::vocabulary::{AUTH, CONFIG, HALT, INSTANCE, NF_VAULT, RESOURCE, VAULT};
    use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

    /// A condition names its own target, and one check replaces the gate
    /// shapes: every target it names is declared as an access under
    /// `Read` or `Write`, by a clause that fires whenever the condition
    /// does.
    #[test]
    fn a_condition_over_an_undeclared_or_incoherent_target_is_refused() {
        // Keyed by the resource it holds, so the movement below can
        // denominate it: a movement names what it moves.
        let cell = || {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material: vec![a_resource()],
            })
        };
        let access = |guard: Option<Expr>, mode| Clause::Effect {
            reach: None,
            guard: guard.map(Box::new),
            target: cell(),
            mode,
            denomination: None,
        };
        // The incoherent mode: a movement declares the cell, but a
        // movement cannot carry a judgment.
        let movement = || Clause::Effect {
            reach: None,
            guard: None,
            target: cell(),
            mode: ModeExpr::Delta,
            denomination: Some(Box::new(a_resource())),
        };
        let requires = |guard: Option<Expr>, rule| Clause::Requires {
            guard: guard.map(Box::new),
            rule,
        };
        let holds = |expect| {
            RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(cell()),
                expect,
            })
        };
        let satisfies = || {
            RuleExpr::Require(RuleLeaf::Stored {
                cell: match cell() {
                    TargetExpr::Point(expr) => expr,
                    _ => unreachable!(),
                },
            })
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };
        let guard = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        let other = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(1)));

        // Backed under a coherent mode: admitted, guarded or not — an
        // unguarded access fires whenever the condition does, and one
        // under the same guard fires exactly when it does.
        assert_eq!(
            declared(vec![
                access(None, ModeExpr::Read),
                requires(None, holds(Presence::Present)),
            ]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                access(None, ModeExpr::Read),
                requires(Some(guard()), satisfies()),
            ]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                access(Some(guard()), ModeExpr::Read),
                requires(Some(guard()), holds(Presence::Absent)),
            ]),
            Ok(())
        );

        // Nothing declares the target, a mode that cannot carry the
        // judgment declares it, or the access is guarded where the
        // condition is not: all one refusal.
        assert_eq!(
            declared(vec![requires(None, holds(Presence::Present))]),
            Err(DeclarationError::ConditionUndeclared { clause: 0 })
        );
        assert_eq!(
            declared(vec![movement(), requires(None, holds(Presence::Present))]),
            Err(DeclarationError::ConditionUndeclared { clause: 1 })
        );
        assert_eq!(
            declared(vec![
                access(Some(guard()), ModeExpr::Read),
                requires(None, satisfies()),
            ]),
            Err(DeclarationError::ConditionUndeclared { clause: 1 })
        );
        assert_eq!(
            declared(vec![
                access(Some(other()), ModeExpr::Read),
                requires(Some(guard()), holds(Presence::Present)),
            ]),
            Err(DeclarationError::ConditionUndeclared { clause: 1 })
        );
    }

    /// A condition that requires nothing, or names authority its own
    /// caller supplies, is refused on its own terms.
    #[test]
    fn a_degenerate_or_caller_named_condition_is_refused() {
        let cell = || {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material: vec![],
            })
        };
        let access = |guard: Option<Expr>, mode| Clause::Effect {
            reach: None,
            guard: guard.map(Box::new),
            target: cell(),
            mode,
            denomination: None,
        };
        let requires = |guard: Option<Expr>, rule| Clause::Requires {
            guard: guard.map(Box::new),
            rule,
        };
        let holds = |presence| {
            RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(cell()),
                expect: presence,
            })
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // A condition requiring nothing.
        assert_eq!(
            declared(vec![
                access(None, ModeExpr::Read),
                requires(None, holds(Presence::Either)),
            ]),
            Err(DeclarationError::VacuousCondition { clause: 1 })
        );

        // Authority the caller names admits everyone — at a claim leaf
        // and at a stored leaf's cell alike.
        assert_eq!(
            declared(vec![requires(None, RuleExpr::claim(Expr::Arg(0)))]),
            Err(DeclarationError::CallerNamedCondition { clause: 0 })
        );
        assert_eq!(
            declared(vec![requires(
                None,
                RuleExpr::Require(RuleLeaf::Stored { cell: Expr::Arg(0) })
            )]),
            Err(DeclarationError::CallerNamedCondition { clause: 0 })
        );
    }

    /// A mark is a resource's own name, and the derivation folds it as
    /// one part of the material. An unmarked issuance would fold to no
    /// material at all — an address reached by saying less rather than
    /// by naming something — so publish refuses it and the mark's
    /// encoding stays one rule with no case in it.
    #[test]
    fn an_issuance_under_no_mark_is_refused() {
        let issues = |mark: &[u8]| {
            check_declarations(&MethodSignature {
                issues: vec![Issuance {
                    mark: mark.to_vec(),
                    kind: ResourceKind::Fungible,
                    direction: Issued::Minted,
                    grants: minting(),
                }],
                ..MethodSignature::default()
            })
        };
        assert_eq!(issues(b"unit"), Ok(()));
        assert_eq!(issues(b""), Err(DeclarationError::UnmarkedIssuance));
    }

    /// The entry a resource grants for the direction its issuer takes.
    fn minting() -> GrantsExpr {
        let mut grants = GrantsExpr::new();
        grants.set(
            GrantedBehaviour::Mint,
            GrantRuleExpr::Require(GrantClaim::SelfAddr),
        );
        grants
    }

    /// Absence withholds, so a resource nobody may mint is one granting
    /// no `Mint` entry — and a body that mints one is an author who
    /// wrote the withholding and the mint together. Refused here, where
    /// they wrote it, rather than left for a caller to meet.
    ///
    /// Exhaustive over the directions on purpose: issuance acts through
    /// no site, so it inherits nothing from the capability matrix and
    /// every arm this refusal has is one this case has to name.
    #[test]
    fn issuing_a_resource_whose_entry_withholds_it_is_refused() {
        let issues = |direction, grants: GrantsExpr| {
            check_declarations(&MethodSignature {
                issues: vec![Issuance {
                    mark: b"unit".to_vec(),
                    kind: ResourceKind::Fungible,
                    direction,
                    grants,
                }],
                ..MethodSignature::default()
            })
        };
        let burning = || {
            let mut grants = GrantsExpr::new();
            grants.set(
                GrantedBehaviour::Burn,
                GrantRuleExpr::Require(GrantClaim::SelfAddr),
            );
            grants
        };
        let both = || {
            let mut grants = minting();
            grants.set(
                GrantedBehaviour::Burn,
                GrantRuleExpr::Require(GrantClaim::SelfAddr),
            );
            grants
        };

        assert_eq!(issues(Issued::Minted, minting()), Ok(()));
        assert_eq!(issues(Issued::Burned, burning()), Ok(()));
        assert_eq!(issues(Issued::Either, both()), Ok(()));

        // A capped supply is exactly the absent `Mint` entry, so a body
        // minting one meets the refusal however else the resource is
        // granted.
        for grants in [GrantsExpr::new(), burning()] {
            assert_eq!(
                issues(Issued::Minted, grants),
                Err(DeclarationError::IssuanceUnadmitted(GrantedBehaviour::Mint))
            );
        }
        for grants in [GrantsExpr::new(), minting()] {
            assert_eq!(
                issues(Issued::Burned, grants),
                Err(DeclarationError::IssuanceUnadmitted(GrantedBehaviour::Burn))
            );
        }
        // A body reaching both ways answers to both entries, and the
        // first one missing is the one it hears about.
        assert_eq!(
            issues(Issued::Either, minting()),
            Err(DeclarationError::IssuanceUnadmitted(GrantedBehaviour::Burn))
        );
        assert_eq!(
            issues(Issued::Either, burning()),
            Err(DeclarationError::IssuanceUnadmitted(GrantedBehaviour::Mint))
        );
    }

    /// A mint is justified by a condition the same declaration carries,
    /// or it does not publish: identity takes the stored rule, a badge
    /// takes that plus possession keyed by the same expression.
    #[test]
    fn a_mint_no_condition_justifies_is_refused() {
        let auth_cell = || Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(AUTH),
            material: vec![],
        };
        let read = |target| Clause::Effect {
            reach: None,
            guard: None,
            target,
            mode: ModeExpr::Read,
            denomination: None,
        };
        let satisfies = || Clause::Requires {
            guard: None,
            rule: RuleExpr::Require(RuleLeaf::Stored { cell: auth_cell() }),
        };
        let vault = |badge: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(VAULT),
                material: vec![badge],
            })
        };
        let read_vault = |badge: Expr| Clause::Effect {
            reach: None,
            guard: None,
            target: vault(badge.clone()),
            mode: ModeExpr::Read,
            denomination: Some(Box::new(badge)),
        };
        let holds = |target| Clause::Requires {
            guard: None,
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(target),
                expect: Presence::Present,
            }),
        };
        let mints = |claim| Clause::Mints { guard: None, claim };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // Identity: the stored rule alone justifies it.
        assert_eq!(
            declared(vec![
                read(TargetExpr::Point(auth_cell())),
                satisfies(),
                mints(Expr::SelfAddr),
            ]),
            Ok(())
        );
        // No stored-rule condition beside it: forgeable identity.
        assert_eq!(
            declared(vec![mints(Expr::SelfAddr)]),
            Err(DeclarationError::UnjustifiedMint { clause: 0 })
        );
        assert_eq!(
            declared(vec![
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::claim(Expr::Config(0)),
                },
                mints(Expr::SelfAddr),
            ]),
            Err(DeclarationError::UnjustifiedMint { clause: 1 }),
            "a claim-only rule verifies no stored authority"
        );

        // A badge: the possession condition, keyed by the same
        // expression the claim names.
        let badge_mint = |possession_key: Expr| {
            declared(vec![
                read(TargetExpr::Point(auth_cell())),
                read_vault(Expr::Config(0)),
                read_vault(possession_key.clone()),
                satisfies(),
                holds(vault(possession_key)),
                mints(Expr::Config(0)),
            ])
        };
        assert_eq!(badge_mint(Expr::Config(0)), Ok(()));
        assert_eq!(
            badge_mint(Expr::Config(1)),
            Err(DeclarationError::MintUnheld { clause: 5 }),
            "possession of some other cell holds nothing about this claim"
        );
        // Possession required, but never stated at all.
        assert_eq!(
            declared(vec![
                read(TargetExpr::Point(auth_cell())),
                satisfies(),
                mints(Expr::Config(0)),
            ]),
            Err(DeclarationError::MintUnheld { clause: 2 })
        );
    }

    /// What a total mark cannot survive, read off the declaration rather
    /// than off the code.
    ///
    /// A leg reads the mark and commits without waiting, so what it has
    /// to exclude is every verdict that could still land *inside* its
    /// own execution. The artifact scan covers the one that leaves the
    /// type system — a trap — and this is the one it cannot see: a
    /// condition no earlier stage can answer.
    ///
    /// Which conditions those are is the placement's answer rather than
    /// this check's. A claim reads the node's own signed evidence, so
    /// admission decides it; a presence reads committed state, so
    /// materialization does; both land before anything commits. A
    /// *stored* rule needs the session, and only the declaring node's
    /// own walk holds one.
    #[test]
    fn a_total_mark_survives_every_verdict_reached_before_its_leg() {
        let total = |signature: MethodSignature| MethodSignature {
            totality: Totality::Total,
            ..signature
        };
        let leaf = || {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material: vec![],
            })
        };
        let requiring = |rule| {
            total(MethodSignature {
                effects: vec![
                    Clause::Effect {
                        reach: None,
                        guard: None,
                        target: leaf(),
                        mode: ModeExpr::Read,
                        denomination: None,
                    },
                    Clause::Requires { guard: None, rule },
                ],
                ..MethodSignature::default()
            })
        };

        // The shape that admits: public, and answering for itself.
        assert_eq!(
            check_declarations(&total(MethodSignature::default())),
            Ok(())
        );

        // A claim admission decides, and a presence materialization
        // does: both land before this method's leg runs, so the mark
        // stands beside either.
        assert_eq!(
            check_declarations(&requiring(RuleExpr::claim(Expr::SelfAddr))),
            Ok(())
        );
        assert_eq!(
            check_declarations(&requiring(RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(leaf()),
                expect: Presence::Present,
            }))),
            Ok(())
        );

        // A stored rule needs the session, so the verdict is this
        // method's own walk's — reached after a caller may already have
        // committed on the strength of the mark.
        assert_eq!(
            check_declarations(&requiring(RuleExpr::Require(RuleLeaf::Stored {
                cell: Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                    material: vec![],
                },
            }))),
            Err(DeclarationError::ConditionalTotality),
        );

        // And a reservation, for the reason the mark is actually about:
        // it is a verdict on the caller's own request.
        assert_eq!(
            check_declarations(&total(MethodSignature {
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: leaf(),
                    mode: ModeExpr::Reserve(Expr::Literal(Value::U128(5))),
                    denomination: Some(Box::new(Expr::Config(0))),
                }],
                ..MethodSignature::default()
            })),
            Err(DeclarationError::ConditionalTotality),
        );
    }

    /// A presence is about whether the state a target names holds
    /// anything, and each of the three shapes answers that: a cell is
    /// there or is not, an entry is there or is not, and an interval
    /// holds an entry or holds none.
    #[test]
    fn a_presence_is_asked_of_every_shape_a_target_names() {
        let declared = |target: TargetExpr, requires| {
            check_declarations(&MethodSignature {
                effects: vec![
                    Clause::Effect {
                        reach: None,
                        guard: None,
                        target: target.clone(),
                        mode: ModeExpr::Write { moves: Moves::Both },
                        denomination: None,
                    },
                    Clause::Requires {
                        guard: None,
                        rule: RuleExpr::Require(RuleLeaf::Presence {
                            target: Box::new(target),
                            expect: requires,
                        }),
                    },
                ],
                ..MethodSignature::default()
            })
        };
        let point = TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
            material: vec![],
        });
        let entry = TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
            material: vec![],
            order: Expr::Literal(Value::U128(7)),
        };
        let range = TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
            material: vec![],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: Expr::Literal(Value::U64(4)),
        };

        for requires in [Presence::Absent, Presence::Present] {
            assert_eq!(declared(point.clone(), requires), Ok(()), "{requires:?}");
            assert_eq!(declared(entry.clone(), requires), Ok(()), "{requires:?}");
            assert_eq!(declared(range.clone(), requires), Ok(()), "{requires:?}");
        }
    }

    /// "Create it if absent, otherwise update it" is two writes on one
    /// cell requiring opposite presences, and it is not a contradiction:
    /// no evaluation declares both. Complementarity is syntactic,
    /// because publish has no arguments — the same standard the target
    /// comparison beside it holds to.
    #[test]
    fn complementary_guards_carry_opposite_presences_and_nothing_else_does() {
        let cond = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        let target = || {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material: vec![],
            })
        };
        let write = |guard: Option<Expr>, presence| Clause::Requires {
            guard: guard.map(Box::new),
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(target()),
                expect: presence,
            }),
        };
        // The one access every condition above is backed by: unguarded,
        // so it fires whenever any of them does.
        let declared = |conditions: Vec<Clause>| {
            let mut effects = vec![Clause::Effect {
                reach: None,
                guard: None,
                target: target(),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }];
            effects.extend(conditions);
            check_declarations(&MethodSignature {
                effects,
                ..MethodSignature::default()
            })
        };

        // What an `if`/`else` emits, in either order.
        let negated = Expr::Not(Box::new(cond()));
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(negated.clone()), Presence::Present),
            ]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                write(Some(negated), Presence::Present),
                write(Some(cond()), Presence::Absent),
            ]),
            Ok(())
        );

        // Two guards that are merely different can both hold, so the
        // contradiction stands.
        let other = Expr::Eq(Box::new(Expr::Arg(1)), Box::new(Expr::Config(0)));
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(other), Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );

        // And a guard is complementary to nothing when the other clause
        // fires always.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(None, Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
    }

    /// Every pair of writes that can both fire is compared, not just the
    /// first that meets.
    ///
    /// Complementarity is a relation between two clauses rather than a
    /// property of the target they share, so a clause complementary to
    /// one of the others still meets all the rest — and a fold that
    /// stopped at the first meeting would carry a contradiction past the
    /// gate for the evaluated set to find later, where an author cannot
    /// hear it.
    #[test]
    fn a_write_meets_every_other_write_it_can_fire_beside() {
        let cond = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        let write = |guard: Option<Expr>, presence| Clause::Requires {
            guard: guard.map(Box::new),
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(own_point(package_slot(0), vec![])),
                expect: presence,
            }),
        };
        let declared = |conditions: Vec<Clause>| {
            let mut effects = vec![Clause::Effect {
                reach: None,
                guard: None,
                target: own_point(package_slot(0), vec![]),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }];
            effects.extend(conditions);
            check_declarations(&MethodSignature {
                effects,
                ..MethodSignature::default()
            })
        };

        // The arms of one branch, and a third clause that fires always.
        // It meets the first, which agrees with it — and contradicts the
        // second, which is the pair the fold would never have asked
        // about.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
                write(None, Presence::Absent),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
        // The same three in the order that hides it best: the always-
        // firing clause is written first, so the arm that agrees with it
        // is met before the arm that does not.
        assert_eq!(
            declared(vec![
                write(None, Presence::Absent),
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
        // And the shape that is not a contradiction still stands beside
        // a third clause nothing disagrees with.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
            ]),
            Ok(())
        );
    }

    /// A declaration states an access some execution can hold, or it does
    /// not publish.
    ///
    /// The world hands out one handle per declared access and reads its
    /// type off the target's shape and the mode. A pairing it has no
    /// handle for is a clause every call aborts at — and the gate that
    /// exists to answer an author is the place to say so, rather than
    /// leaving a package published and unusable.
    #[test]
    fn a_pairing_no_handle_is_built_for_does_not_publish() {
        let declared = |target, mode, denomination: Option<Expr>| {
            check_declarations(&MethodSignature {
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target,
                    mode,
                    denomination: denomination.map(Box::new),
                }],
                ..MethodSignature::default()
            })
        };
        let entry = || TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(package_slot(0)),
            material: vec![a_resource()],
            order: Expr::Literal(Value::U128(1)),
        };
        let interval = || own_interval(package_slot(1), vec![a_resource()]);
        let refused = Err(DeclarationError::UnsupportedAccess { clause: 0 });

        // Value moves through a leaf, never through an interval: a
        // collection's entries move by being named, which is what a
        // rewrite of the interval is.
        for target in [entry(), interval()] {
            for mode in [ModeExpr::Delta, ModeExpr::Reserve(Expr::Arg(0))] {
                assert_eq!(
                    declared(target.clone(), mode.clone(), Some(a_resource())),
                    refused,
                    "{target:?} {mode:?}"
                );
            }
            // The two it does have.
            assert_eq!(declared(target.clone(), ModeExpr::Read, None), Ok(()));
            assert_eq!(
                declared(
                    target,
                    ModeExpr::Write { moves: Moves::Both },
                    Some(a_resource()),
                ),
                Ok(())
            );
        }
    }

    /// Trap freedom for a total leg rests on every declared handle being
    /// materialized, and a guarded-out clause materializes none. The
    /// mark and the precision are the trade.
    #[test]
    fn a_total_method_carries_no_guard() {
        let guarded = Clause::Effect {
            reach: None,
            guard: Some(Box::new(Expr::Eq(
                Box::new(Expr::Arg(0)),
                Box::new(Expr::Config(0)),
            ))),
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        assert_eq!(
            check_declarations(&MethodSignature {
                totality: Totality::Total,
                effects: vec![guarded],
                ..MethodSignature::default()
            }),
            Err(DeclarationError::GuardedTotality)
        );

        // The binding alone is enough: it is the parameter an absent
        // capability travels beside.
        assert_eq!(
            check_declarations(&MethodSignature {
                totality: Totality::Total,
                abi: vec![AbiParam::Guard(0)],
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(Expr::SelfAddr),
                    mode: ModeExpr::Read,
                    denomination: None,
                }],
                ..MethodSignature::default()
            }),
            Err(DeclarationError::GuardedTotality)
        );
    }

    /// Metadata can be authored rather than derived, so the
    /// contradiction the macro refuses at the second call site is
    /// refused here too — against the target expressions, since publish
    /// has no arguments to evaluate them with.
    #[test]
    fn opposite_presence_requirements_on_one_target_do_not_publish() {
        let cell = |material| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material,
            })
        };
        let write = |presence| Clause::Requires {
            guard: None,
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(cell(vec![])),
                expect: presence,
            }),
        };
        let access = |material| Clause::Effect {
            reach: None,
            guard: None,
            target: cell(material),
            mode: ModeExpr::Write { moves: Moves::Both },
            denomination: None,
        };
        let declared = |conditions: Vec<Clause>| {
            let mut effects = vec![access(vec![])];
            effects.extend(conditions);
            check_declarations(&MethodSignature {
                effects,
                ..MethodSignature::default()
            })
        };

        assert_eq!(
            declared(vec![write(Presence::Absent), write(Presence::Present)]),
            Err(DeclarationError::PresenceConflict)
        );
        assert_eq!(
            declared(vec![write(Presence::Present), write(Presence::Absent)]),
            Err(DeclarationError::PresenceConflict)
        );

        // A requirement still meets its opposite across an agreeing one
        // written between them.
        assert_eq!(
            declared(vec![
                write(Presence::Absent),
                write(Presence::Absent),
                write(Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );

        // What is not a contradiction: the same requirement twice, and
        // two requirements on targets that are not the same expression.
        assert_eq!(
            declared(vec![write(Presence::Absent), write(Presence::Absent)]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                access(vec![Expr::Config(0)]),
                write(Presence::Absent),
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(cell(vec![Expr::Config(0)])),
                        expect: Presence::Present,
                    }),
                },
            ]),
            Ok(())
        );
    }

    /// A denomination list is read at the positions it indexes, so the
    /// two ways it can fail to index anything are refused at publish.
    ///
    /// A published package could carry a hand-written metadata section,
    /// so neither is a fact about what the tracer emits: what admission
    /// reads has to line up with the parameters whatever wrote it.
    #[test]
    fn a_denomination_names_a_parameter_that_carries_value() {
        let denominating = |params: Vec<ParamType>, denominations: Vec<Option<Expr>>| {
            check_declarations(&MethodSignature {
                params,
                denominations,
                ..MethodSignature::default()
            })
        };

        // No list at all is the method that fixes nothing, which is most
        // of them.
        assert_eq!(denominating(vec![ParamType::Bucket], vec![]), Ok(()));
        // A list covering the parameters, fixing the one that carries
        // value and leaving the other open.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![Some(Expr::Config(0)), None]
            ),
            Ok(())
        );

        // A list that does not cover them indexes positions nobody agrees
        // on.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![Some(Expr::Config(0))]
            ),
            Err(DeclarationError::DenominationArity {
                expected: 2,
                found: 1
            })
        );
        // A denomination on a position that carries no value denominates
        // nothing.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![None, Some(Expr::Config(0))]
            ),
            Err(DeclarationError::DenominationKind {
                param: 1,
                kind: "u128"
            })
        );
        // Both edge kinds carry value, so both take one.
        assert_eq!(
            denominating(vec![ParamType::NfBucket], vec![Some(Expr::Config(0))]),
            Ok(())
        );
    }

    /// Whether a signature is refused for naming a protocol cell in a
    /// shape that cell does not have.
    fn misshapen(signature: &MethodSignature) -> bool {
        matches!(
            check_declarations(signature),
            Err(DeclarationError::ProtocolSlotShape { .. })
        )
    }

    /// The protocol's value cells, and the shape each one has.
    ///
    /// Exhaustive over the three on purpose. The corpus declares a vault
    /// in two of its four modes and reaches the claims cell without ever
    /// opening it, so a rule about the rest would be a rule nothing
    /// holds.
    #[test]
    fn a_value_cell_is_keyed_by_what_it_holds() {
        let moves = [
            ModeExpr::Write { moves: Moves::Both },
            ModeExpr::Delta,
            ModeExpr::Reserve(Expr::Arg(0)),
        ];
        // A vault is keyed by the resource it holds and says so in
        // every mode it is reached in — a read included, because a read
        // of a cell that says nothing is a read of bytes, and a vault
        // has no byte surface for one to come through.
        for slot in [VAULT] {
            for mode in moves.clone() {
                let keyed = || own_point(slot, vec![a_resource()]);
                assert_eq!(
                    check_declarations(&one_clause(keyed(), mode.clone(), Some(a_resource()))),
                    Ok(()),
                    "{slot:?} {mode:?}"
                );
                // Keyed by one resource and denominated in another: two
                // answers to what one leaf holds.
                assert!(misshapen(&one_clause(
                    keyed(),
                    mode.clone(),
                    Some(Expr::Arg(0))
                )));
                // And no answer at all.
                assert!(misshapen(&one_clause(keyed(), mode, None)));
            }
            // A read says it too: which handle a clause materializes
            // turns on the denomination, so a read that said nothing
            // would come back as bytes.
            let read = |target, denomination| one_clause(target, ModeExpr::Read, denomination);
            assert_eq!(
                check_declarations(&read(
                    own_point(slot, vec![a_resource()]),
                    Some(a_resource())
                )),
                Ok(())
            );
            assert!(misshapen(&read(own_point(slot, vec![a_resource()]), None)));
            // Value is never keyed by nothing, and never a collection.
            assert!(misshapen(&read(own_point(slot, vec![]), None)));
            assert!(misshapen(&read(
                own_interval(slot, vec![a_resource()]),
                Some(a_resource())
            )));
        }

        // Holdings are the same statement in collection form: one
        // resource's instances, in the interval narrowed by it.
        let holdings = || own_interval(NF_VAULT, vec![a_resource()]);
        let write = || ModeExpr::Write { moves: Moves::Both };
        assert_eq!(
            check_declarations(&one_clause(holdings(), write(), Some(a_resource()))),
            Ok(())
        );
        assert!(misshapen(&one_clause(
            own_point(NF_VAULT, vec![a_resource()]),
            write(),
            Some(a_resource())
        )));
        assert!(misshapen(&one_clause(
            holdings(),
            ModeExpr::Delta,
            Some(a_resource())
        )));
    }

    /// The protocol's cells that hold no value, and the shape each one
    /// has.
    ///
    /// Exhaustive over the rest of the vocabulary, on the same terms as
    /// the value cells beside it.
    #[test]
    fn a_protocol_cell_holding_no_value_is_declared_in_its_own_shape() {
        let write = || ModeExpr::Write { moves: Moves::Both };
        let plain = |target, mode| one_clause(target, mode, None);
        // A write that creates: the access, and the one-way door beside
        // it as the condition it now is.
        let creating = |target: TargetExpr, denomination: Option<Expr>| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![
                Clause::Effect {
                    reach: None,
                    guard: None,
                    target: target.clone(),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: denomination.map(Box::new),
                },
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(target),
                        expect: Presence::Absent,
                    }),
                },
            ],
            ..MethodSignature::default()
        };

        // A configuration leaf is read, written once where absent, and
        // never rewritten; a stored authority cell is read or rewritten
        // whole. Neither is keyed by anything and neither holds value.
        assert_eq!(
            check_declarations(&plain(own_point(CONFIG, vec![]), ModeExpr::Read)),
            Ok(())
        );
        assert_eq!(
            check_declarations(&creating(own_point(CONFIG, vec![]), None)),
            Ok(())
        );
        assert!(misshapen(&plain(own_point(CONFIG, vec![]), write())));
        for mode in [ModeExpr::Read, write()] {
            assert_eq!(
                check_declarations(&plain(own_point(AUTH, vec![]), mode)),
                Ok(())
            );
        }
        assert_eq!(
            check_declarations(&creating(own_point(AUTH, vec![]), None)),
            Ok(())
        );
        assert!(misshapen(&plain(own_point(AUTH, vec![]), ModeExpr::Delta)));
        assert!(misshapen(&plain(
            own_point(AUTH, vec![a_resource()]),
            write()
        )));

        // A record and an instance's data are written where the thing
        // they describe is not there yet, and not again.
        for (slot, material) in [
            (RESOURCE, vec![a_resource()]),
            (INSTANCE, vec![a_resource(), Expr::Arg(0)]),
        ] {
            let keyed = || own_point(slot, material.clone());
            assert_eq!(
                check_declarations(&creating(keyed(), None)),
                Ok(()),
                "{slot:?}"
            );
            assert_eq!(
                check_declarations(&plain(keyed(), ModeExpr::Read)),
                Ok(()),
                "{slot:?}"
            );
            assert!(misshapen(&plain(keyed(), write())));
            // Nothing here holds value, so nothing here denominates.
            assert!(misshapen(&creating(keyed(), Some(a_resource()))));
        }
        // Keyed by the wrong number of terms: an instance is a resource
        // and an id, and a record is a resource.
        assert!(misshapen(&creating(own_point(RESOURCE, vec![]), None)));
        assert!(misshapen(&creating(
            own_point(INSTANCE, vec![a_resource()]),
            None
        )));
    }

    /// A value cell is keyed by what it holds, so no leaf holds two
    /// resources.
    ///
    /// The property this buys is not the comparison itself but what
    /// follows from it: the denomination is in the material, the
    /// material is in the key, so two clauses reaching one leaf name one
    /// resource however differently they spell it. A cell that could be
    /// filled under one name and emptied under another would convert
    /// value by holding it.
    #[test]
    fn a_value_cell_is_reached_by_the_name_of_what_it_holds() {
        let other = || {
            Expr::Literal(Value::Address(Address::new(
                [8; 31],
                AddressClass::Resource,
            )))
        };
        let own = |material: Vec<Expr>| own_point(package_slot(0), material);

        // Keyed by what it holds, in the modes that move it.
        for mode in [
            ModeExpr::Delta,
            ModeExpr::Reserve(Expr::Arg(0)),
            ModeExpr::Write { moves: Moves::Both },
        ] {
            assert_eq!(
                check_declarations(&one_clause(
                    own(vec![a_resource()]),
                    mode.clone(),
                    Some(a_resource())
                )),
                Ok(()),
                "{mode:?}"
            );
            // Named as something the key does not.
            assert_eq!(
                check_declarations(&one_clause(
                    own(vec![a_resource()]),
                    mode.clone(),
                    Some(other())
                )),
                Err(DeclarationError::DenominationNotKeyed { clause: 0 }),
                "{mode:?}"
            );
            // Or keyed by nothing at all, which names no cell to hold it.
            assert_eq!(
                check_declarations(&one_clause(own(vec![]), mode, Some(a_resource()))),
                Err(DeclarationError::DenominationNotKeyed { clause: 0 })
            );
        }

        // A collection is the same statement: the resource is the term
        // its entries hang under.
        let interval = |material| own_interval(package_slot(1), material);
        assert_eq!(
            check_declarations(&one_clause(
                interval(vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                Some(a_resource())
            )),
            Ok(())
        );
        assert_eq!(
            check_declarations(&one_clause(
                interval(vec![other()]),
                ModeExpr::Write { moves: Moves::Both },
                Some(a_resource())
            )),
            Err(DeclarationError::DenominationNotKeyed { clause: 0 })
        );

        // A fresh key carries no material, so nothing could find it
        // again to take value out of it.
        assert_eq!(
            check_declarations(&one_clause(
                TargetExpr::Point(Expr::FreshKey { slot: 0 }),
                ModeExpr::Write { moves: Moves::Both },
                Some(a_resource())
            )),
            Err(DeclarationError::DenominationNotKeyed { clause: 0 })
        );
    }

    /// A commutative movement says what it moves.
    ///
    /// `Delta` and `Reserve` move value and do nothing else, so the cell
    /// is one that holds value whether or not the declaration says which.
    /// Refused at materialization too, which has the evaluated key to
    /// name; this is the same verdict where an author hears it.
    #[test]
    fn a_movement_that_names_no_resource_does_not_publish() {
        let own = |material: Vec<Expr>| own_point(package_slot(0), material);
        for mode in [ModeExpr::Delta, ModeExpr::Reserve(Expr::Arg(0))] {
            assert_eq!(
                check_declarations(&one_clause(own(vec![a_resource()]), mode.clone(), None)),
                Err(DeclarationError::UndenominatedMovement { clause: 0 }),
                "{mode:?}"
            );
        }
        // A write is the mode a byte cell takes too, so it says nothing
        // by saying nothing — which is what makes it a byte cell.
        assert_eq!(
            check_declarations(&one_clause(
                own(vec![]),
                ModeExpr::Write { moves: Moves::Both },
                None
            )),
            Ok(())
        );
        assert_eq!(
            check_declarations(&one_clause(own(vec![]), ModeExpr::Read, None)),
            Ok(())
        );
    }

    /// A denomination written down is a resource, judged at publish.
    ///
    /// The class check runs wherever a denomination is evaluated; a
    /// literal is the case an author can hear about their own package,
    /// before any manifest names it.
    #[test]
    fn a_literal_denomination_of_another_class_does_not_publish() {
        let component = Expr::Literal(Value::Address(Address::new(
            [7; 31],
            AddressClass::Component,
        )));
        assert_eq!(
            check_declarations(&one_clause(
                own_point(package_slot(0), vec![component.clone()]),
                ModeExpr::Delta,
                Some(component)
            )),
            Err(DeclarationError::NotAResource {
                clause: 0,
                found: AddressClass::Component
            })
        );
        // An expression over inputs is not decidable here; routing
        // evaluates it and applies the same refusal there.
        assert_eq!(
            check_declarations(&one_clause(
                own_point(package_slot(0), vec![Expr::Arg(0)]),
                ModeExpr::Delta,
                Some(Expr::Arg(0))
            )),
            Ok(())
        );
        // The instance's own address is decided without evaluating
        // anything: a component names no resource, so a self-addressed
        // denomination is a method every call would be refused at.
        assert_eq!(
            check_declarations(&one_clause(
                own_point(package_slot(0), vec![Expr::SelfAddr]),
                ModeExpr::Delta,
                Some(Expr::SelfAddr)
            )),
            Err(DeclarationError::NotAResource {
                clause: 0,
                found: AddressClass::Component
            })
        );
    }

    /// The same class verdict at the other two positions a signature
    /// names resources: a parameter's denomination and an output
    /// projection.
    #[test]
    fn a_decided_non_resource_is_refused_at_every_denominating_position() {
        let component = || {
            Expr::Literal(Value::Address(Address::new(
                [7; 31],
                AddressClass::Component,
            )))
        };
        let resource = || {
            Expr::Literal(Value::Address(Address::new(
                [8; 31],
                AddressClass::Resource,
            )))
        };

        let denominated = |expr: Expr| MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Bucket],
            denominations: vec![Some(expr)],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&denominated(component())),
            Err(DeclarationError::ParamNotAResource {
                param: 0,
                found: AddressClass::Component
            })
        );
        assert_eq!(check_declarations(&denominated(resource())), Ok(()));

        let projecting = |expr: Expr| MethodSignature {
            totality: Totality::Fallible,
            outputs: vec![expr],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&projecting(Expr::SelfAddr)),
            Err(DeclarationError::OutputNotAResource {
                output: 0,
                found: AddressClass::Component
            })
        );
        // A non-fungible projection is judged at the resource it names.
        assert_eq!(
            check_declarations(&projecting(Expr::NfBucket {
                resource: Box::new(component()),
                ids: Box::new(Expr::Arg(0)),
            })),
            Err(DeclarationError::OutputNotAResource {
                output: 0,
                found: AddressClass::Component
            })
        );
        assert_eq!(check_declarations(&projecting(resource())), Ok(()));
        // An expression over inputs waits for admission, which evaluates
        // it.
        assert_eq!(check_declarations(&projecting(Expr::Arg(0))), Ok(()));
    }

    /// One cell holds one thing, and a signature says so once.
    ///
    /// The denomination chooses which handle a clause materializes, so a
    /// leaf denominated by one clause and not by another is a leaf a body
    /// holds as a vault and as a byte cell at once — and a balance
    /// written through the byte handle and debited through the value one
    /// is value from nowhere. What makes this the whole of the property
    /// is that the two clauses need not agree on anything else: a mode, a
    /// presence and a guard are all free.
    #[test]
    fn one_cell_is_not_a_vault_and_a_byte_cell_at_once() {
        let held = || Some(a_resource());
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };
        let write = || ModeExpr::Write { moves: Moves::Both };
        let effect = |target, mode, denomination: Option<Expr>| Clause::Effect {
            reach: None,
            guard: None,
            target,
            mode,
            denomination: denomination.map(Box::new),
        };

        // One leaf, two answers — the shape that would mint.
        let leaf = || own_point(package_slot(0), vec![a_resource()]);
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(leaf(), write(), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // The reading modes are no exception: a read of a vault and a
        // byte read of the same leaf still disagree about what came out.
        assert_eq!(
            declared(vec![
                effect(leaf(), ModeExpr::Delta, held()),
                effect(leaf(), ModeExpr::Read, None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // Nor does a guard make them arms of one answer: what a cell
        // holds is not a question an execution answers.
        let guarded = |cond, denomination| Clause::Effect {
            reach: None,
            guard: Some(Box::new(cond)),
            target: leaf(),
            mode: write(),
            denomination,
        };
        let cond = Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        assert_eq!(
            declared(vec![
                guarded(cond.clone(), Some(Box::new(a_resource()))),
                guarded(Expr::Not(Box::new(cond)), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );

        // Two intervals of one collection are two targets over one set of
        // entries, so the disagreement is about the entries and comparing
        // targets would let it through. Overlapping or not: what the
        // collection holds is the collection's.
        let interval = |hi| TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(package_slot(1)),
            material: vec![a_resource()],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(hi)),
            cap: Expr::Literal(Value::U64(4)),
        };
        assert_eq!(
            declared(vec![
                effect(interval(u128::MAX), write(), held()),
                effect(interval(10), write(), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // And an entry of it is the same statement at width one.
        assert_eq!(
            declared(vec![
                effect(interval(u128::MAX), write(), held()),
                effect(
                    TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: SlotRef::Fixed(package_slot(1)),
                        material: vec![a_resource()],
                        order: Expr::Literal(Value::U128(3)),
                    },
                    write(),
                    None,
                ),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );

        // Agreeing clauses are what a body that reads and writes one cell
        // declares, and they stand — in both directions.
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(leaf(), ModeExpr::Read, held()),
            ]),
            Ok(())
        );
        let bytes = || own_point(package_slot(2), vec![]);
        assert_eq!(
            declared(vec![
                effect(bytes(), write(), None),
                effect(bytes(), ModeExpr::Read, None),
            ]),
            Ok(())
        );
        // Two different cells answer for themselves.
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(bytes(), write(), None),
            ]),
            Ok(())
        );
    }

    /// A slot naming no cell has no shape to be held to, so it is not a
    /// slot a signature may name at all: the unassigned part of the
    /// vocabulary's band, and the kernel's own at the top.
    #[test]
    fn a_slot_the_protocol_assigns_no_cell_is_not_a_signature_to_name() {
        let declaring = |slot| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(slot),
                    material: vec![],
                }),
                mode: ModeExpr::Read,
                denomination: None,
            }],
            ..MethodSignature::default()
        };
        // Everything below the base the vocabulary has not spoken for.
        let assigned = [VAULT, CONFIG, AUTH, RESOURCE, NF_VAULT, INSTANCE, HALT];
        for slot in (0..PACKAGE_SLOT_BASE).map(SlotId) {
            if assigned.contains(&slot) {
                continue;
            }
            assert_eq!(
                check_declarations(&declaring(slot)),
                Err(DeclarationError::ReservedSlot {
                    clause: 0,
                    slot: slot.0
                }),
                "{slot:?}"
            );
        }
        // The kernel's own band: the publish path's cell and the
        // envelope's, neither of which any signature declares.
        for slot in [PACKAGE_SLOT, NULLIFIER_SLOT] {
            assert_eq!(
                check_declarations(&declaring(slot)),
                Err(DeclarationError::ReservedSlot {
                    clause: 0,
                    slot: slot.0
                }),
                "{slot:?}"
            );
        }
        // And the band between them is a package's own, where the
        // vocabulary has nothing to say.
        assert_eq!(check_declarations(&declaring(package_slot(0))), Ok(()));
        assert_eq!(
            check_declarations(&declaring(SlotId(KERNEL_SLOT_BASE - 1))),
            Ok(())
        );
    }

    /// Every way a signature can write somebody else's prefix, refused
    /// where its author can see it.
    #[test]
    fn a_signature_reaching_another_prefix_is_refused() {
        // Each target in a mode it has a handle for: value moves through
        // a leaf, and an entry of a collection is rewritten.
        let declaring = |target: TargetExpr, mode: ModeExpr| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target,
                mode,
                denomination: Some(Box::new(a_resource())),
            }],
            ..MethodSignature::default()
        };
        let child_of = |owner: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(owner),
                slot: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                material: vec![a_resource()],
            })
        };
        let entry_of = |slot: u16, order: u128| TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(SlotId(slot)),
            material: vec![a_resource()],
            order: Expr::Literal(Value::U128(order)),
        };
        let write = || ModeExpr::Write { moves: Moves::Both };

        // Its own prefix, however the key under it is derived.
        assert_eq!(
            check_declarations(&declaring(child_of(Expr::SelfAddr), ModeExpr::Delta)),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(entry_of(PACKAGE_SLOT_BASE + 2, 1), write())),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(entry_of(PACKAGE_SLOT_BASE + 1, 0), write())),
            Ok(())
        );

        // An argument, a configuration slot, and a literal: three ways of
        // naming an object that never agreed to be named.
        for owner in [
            Expr::Arg(0),
            Expr::Config(0),
            Expr::Literal(Value::Address(Address::new(
                [9; 31],
                AddressClass::Component,
            ))),
        ] {
            assert_eq!(
                check_declarations(&declaring(child_of(owner), ModeExpr::Delta)),
                Err(DeclarationError::ForeignPrefix { clause: 0 })
            );
        }

        // And inside a `for-each` body, where the element is the owner.
        let looped = MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: child_of(Expr::Binding(0)),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(a_resource())),
                }],
            }],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&looped),
            Err(DeclarationError::ForeignPrefix { clause: 1 })
        );
    }

    /// A signature declaring exactly one reaching clause.
    fn one_reach(
        behaviour: GrantedBehaviour,
        target: TargetExpr,
        mode: ModeExpr,
        denomination: Option<Expr>,
    ) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: Some(behaviour),
                guard: None,
                target,
                mode,
                denomination: denomination.map(Box::new),
            }],
            ..MethodSignature::default()
        }
    }

    /// A leaf under `owner`, at `slot` and keyed by `material`.
    fn point_under(owner: Expr, slot: SlotRef, material: Vec<Expr>) -> TargetExpr {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(owner),
            slot,
            material,
        })
    }

    /// The slot an argument names, which only a reach may take.
    fn told() -> SlotRef {
        SlotRef::Reached(Box::new(Expr::Arg(1)))
    }

    /// What a reach may say: the halt flag at the slot the vocabulary
    /// keeps it at, and value wherever the holder keeps it.
    ///
    /// An entry admits a reach for what that entry is about, so the cell
    /// is named two different ways — a halt flag by its slot, a holding
    /// by its denomination, which is the only thing that says a cell
    /// holds value at all.
    #[test]
    fn a_reach_names_the_cell_its_authority_governs() {
        let holder = || Expr::Arg(0);
        let take = || ModeExpr::Reserve(Expr::Arg(2));

        assert_eq!(
            check_declarations(&one_reach(
                GrantedBehaviour::Freeze,
                point_under(holder(), SlotRef::Fixed(HALT), vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                None,
            )),
            Ok(())
        );
        // Value at the vocabulary's vault, or at whatever slot the
        // caller says the holder keeps it in.
        for slot in [SlotRef::Fixed(VAULT), told()] {
            assert_eq!(
                check_declarations(&one_reach(
                    GrantedBehaviour::Recall,
                    point_under(holder(), slot, vec![a_resource()]),
                    take(),
                    Some(a_resource()),
                )),
                Ok(())
            );
        }
        // Instances the same way, over the interval holding them.
        assert_eq!(
            check_declarations(&one_reach(
                GrantedBehaviour::Recall,
                TargetExpr::Range {
                    owner: holder(),
                    collection: told(),
                    material: vec![a_resource()],
                    lo: Expr::Literal(Value::U128(0)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Literal(Value::U64(4)),
                },
                ModeExpr::Write { moves: Moves::Both },
                Some(a_resource()),
            )),
            Ok(())
        );

        // A freeze entry admits raising the holder's flag, not writing
        // whatever else sits under their prefix.
        assert_eq!(
            check_declarations(&one_reach(
                GrantedBehaviour::Freeze,
                point_under(holder(), told(), vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                None,
            )),
            Err(DeclarationError::ReachesAnotherCell {
                clause: 0,
                behaviour: GrantedBehaviour::Freeze
            })
        );
        // And a recall entry admits taking value, so the cell it names
        // has to be one that holds some.
        assert_eq!(
            check_declarations(&one_reach(
                GrantedBehaviour::Recall,
                point_under(holder(), SlotRef::Fixed(HALT), vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                None,
            )),
            Err(DeclarationError::ReachesAnotherCell {
                clause: 0,
                behaviour: GrantedBehaviour::Recall
            })
        );
    }

    /// The three things a reach has to be, refused one at a time.
    ///
    /// An authority that governs reaching at all, a prefix that is not
    /// the declarer's own, and a key derived from the resource whose
    /// entry admits it — plus the slot an argument names, which is the
    /// reach's alone.
    #[test]
    fn a_reach_that_is_not_one_is_refused() {
        let holder = || Expr::Arg(0);
        let take = || ModeExpr::Reserve(Expr::Arg(2));

        // A behaviour that is about the holder's own movement governs
        // nobody reaching them.
        for behaviour in [
            GrantedBehaviour::Mint,
            GrantedBehaviour::Burn,
            GrantedBehaviour::Withdraw,
            GrantedBehaviour::Deposit,
        ] {
            assert_eq!(
                check_declarations(&one_reach(
                    behaviour,
                    point_under(holder(), SlotRef::Fixed(VAULT), vec![a_resource()]),
                    take(),
                    Some(a_resource()),
                )),
                Err(DeclarationError::UnreachingBehaviour {
                    clause: 0,
                    behaviour
                })
            );
        }
        // Its own prefix is an ordinary access wearing an authority it
        // does not need.
        assert_eq!(
            check_declarations(&one_reach(
                GrantedBehaviour::Freeze,
                point_under(Expr::SelfAddr, SlotRef::Fixed(HALT), vec![a_resource()]),
                ModeExpr::Write { moves: Moves::Both },
                None,
            )),
            Err(DeclarationError::ReachesItself { clause: 0 })
        );
        // A key derived from nothing, and one derived from something
        // that is not a resource: neither names an entry that could
        // admit the reach.
        for material in [
            vec![],
            vec![Expr::Literal(Value::Address(Address::new(
                [9; 31],
                AddressClass::Component,
            )))],
        ] {
            assert_eq!(
                check_declarations(&one_reach(
                    GrantedBehaviour::Freeze,
                    point_under(holder(), SlotRef::Fixed(HALT), material),
                    ModeExpr::Write { moves: Moves::Both },
                    None,
                )),
                Err(DeclarationError::UnkeyedReach { clause: 0 })
            );
        }
        // And a slot an argument names, on a clause that reaches
        // nothing: everywhere but a reach the shape table has a constant
        // to dispatch on.
        let untold = MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: point_under(Expr::SelfAddr, told(), vec![a_resource()]),
                mode: take(),
                denomination: Some(Box::new(a_resource())),
            }],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&untold),
            Err(DeclarationError::SlotWithoutReach { clause: 0 })
        );
    }
}
