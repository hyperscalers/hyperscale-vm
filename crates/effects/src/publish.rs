//! Publish-time judging: the ABI binding, the declaration shape rules
//! (including the protocol-slot shape table), and the metadata bounds.
//!
//! Every verdict is a pure function of the metadata, identical on every
//! node: refused at publish, and refused again at routing for a package
//! that reached the cache without one.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Resolution, ShapeFault};
use hyperscale_vm_types::{AddressClass, MAX_ERROR_CODES, MAX_EVENT_TYPES, Presence};

use crate::auth::MAX_PACKAGE_ROLES;
use crate::dsl::{
    Clause, ConditionExpr, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH,
    ModeExpr, TargetExpr, materialized_kind,
};
use crate::instance::MAX_CONFIG_FIELDS;
use crate::metadata::{LeafForm, MAX_SHAPE_DEPTH, PackageMetadata, reserved_shape};
use crate::resource::{GrantExpr, GrantsExpr, holdings_entry};
use crate::rule::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, RuleExpr, RuleLeaf};
use crate::signature::{AbiParam, MethodSignature};
use crate::types::{
    MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_ITEMS, SlotId, Value, value_within_width,
};
use crate::vocabulary::{AUTH, CLAIMS, CONFIG, INSTANCE, NF_VAULT, RESOURCE, VAULT};
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

/// Why a signature is refused at publish: the composed verdict of every
/// judgment the vocabulary makes of one.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// Past a structural bound.
    #[error(transparent)]
    Bounds(#[from] SignatureBoundsError),
    /// A declaration rule refused it.
    #[error(transparent)]
    Declaration(#[from] DeclarationError),
    /// The ABI binding refused it — the gate shape included.
    #[error(transparent)]
    Abi(#[from] AbiError),
}

/// A signature every publish-time judgment has passed.
///
/// The witness [`check_signature`] mints, and the only thing the checked
/// judgments hand out: a consumer holding one no longer has to know the
/// list of checks, and a fold that forgot one is unrepresentable rather
/// than an ordering nothing states.
#[derive(Clone, Copy, Debug)]
pub struct CheckedSignature<'a> {
    signature: &'a MethodSignature,
}

impl<'a> CheckedSignature<'a> {
    /// Mint the witness without judging — for the cache, whose invariant
    /// is that everything behind its door already passed.
    pub(crate) const fn trusted(signature: &'a MethodSignature) -> Self {
        Self { signature }
    }

    /// The signature itself.
    #[must_use]
    pub const fn signature(&self) -> &'a MethodSignature {
        self.signature
    }
}

impl std::ops::Deref for CheckedSignature<'_> {
    type Target = MethodSignature;

    fn deref(&self) -> &Self::Target {
        self.signature
    }
}

/// Judge one signature as the publish gate does: the structural bounds,
/// the declaration rules, and the ABI binding, whose shape check covers
/// the gate.
///
/// # Errors
///
/// [`SignatureError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_signature(
    signature: &MethodSignature,
) -> Result<CheckedSignature<'_>, SignatureError> {
    check_signature_bounds(signature)?;
    check_declarations(signature)?;
    check_abi(signature)?;
    Ok(CheckedSignature::trusted(signature))
}

/// Why a signature's ABI binding cannot be honoured.
///
/// Every clause is a pure function of the metadata, so the verdict is the
/// same wherever it is reached: at publish, where it refuses the artifact,
/// and at routing, where it refuses a call to a package that reached the
/// cache without one.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// An issuance grant bound by a method that declares no issued
    /// resource. The walk grants one from the declaration, so there would
    /// be nothing to hand over.
    #[error("ABI parameter {position} takes an issuance grant, but nothing is issued")]
    IssuerWithoutIssuedOutput {
        /// The ABI parameter position.
        position: u32,
    },
    /// A handle binding naming an effect clause the signature does not
    /// declare.
    #[error("ABI parameter {position} names effect clause {clause}, past the {declared} declared")]
    NoSuchClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
        /// How many clauses the signature declares.
        declared: u32,
    },
    /// A guard binding naming a clause that carries no guard. Its
    /// verdict is the constant true, which no export needs told.
    #[error("ABI parameter {position} takes the verdict of clause {clause}, which has no guard")]
    UnguardedClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A handle binding naming a clause that is not a single access.
    ///
    /// A `for-each` clause expands over configuration, so it backs no
    /// fixed export parameter — a refusal routing would otherwise reach
    /// by arity, made here where the signature is judged.
    #[error("ABI parameter {position} borrows clause {clause}, which is not a single access")]
    NotAnAccess {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A run binding naming a clause that is not a `for-each`.
    ///
    /// A run covers a site's expansions, and a clause that does not
    /// expand has none — its capability is the single handle a
    /// [`AbiParam::Handle`] binding names.
    #[error("ABI parameter {position} runs clause {clause}, which is not a `for-each`")]
    NotALoop {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A run binding naming a body position that declares no access.
    ///
    /// A condition declares no capability, and a nested loop's own
    /// expansions are not addressable by an index over the outer one's
    /// elements — so neither backs a run.
    #[error("ABI parameter {position} runs site {site} of clause {clause}, which is not an access")]
    NotALoopedAccess {
        /// The ABI parameter position.
        position: u32,
        /// The `for-each` clause it names.
        clause: u32,
        /// The body position it names.
        site: u32,
    },
    /// A bucket binding naming a parameter the signature does not declare.
    #[error("ABI parameter {position} names parameter {param}, past the {declared} declared")]
    NoSuchParam {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// How many parameters the signature declares.
        declared: u32,
    },
    /// A bucket binding naming a parameter that is not a bucket.
    ///
    /// A bucket's amount is the one value a signature cannot derive,
    /// which is the whole reason the variant exists; naming any other
    /// parameter through it asks for bytes that are already static.
    #[error("ABI parameter {position} takes the amount of parameter {param}, which is {kind}")]
    NotABucket {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// What that parameter actually is.
        kind: &'static str,
    },
    /// One bucket parameter carried by more than one ABI parameter.
    ///
    /// A bucket carried by *none* is well-formed: a method that forwards
    /// its funds to a callee never reads the amount itself, so nothing in
    /// its own ABI carries it. Carrying it twice has no such reading —
    /// the guest would receive one edge's bytes under two names.
    #[error("parameter {param} is a bucket carried by {carried} ABI parameters")]
    BucketCarriedTwice {
        /// The declared parameter.
        param: u32,
        /// How many ABI parameters name it.
        carried: u32,
    },
}

/// Judge one run binding: a run names a site inside a loop, so both
/// halves of the name are checked.
///
/// Anything else is a binding nothing could resolve — a condition
/// declares no capability, and a nested loop's own expansions are not
/// addressable by an index over the outer one's elements.
fn check_run(
    signature: &MethodSignature,
    position: u32,
    clause: u32,
    site: u32,
) -> Result<(), AbiError> {
    let declared = usize::try_from(clause)
        .ok()
        .and_then(|index| signature.effects.get(index));
    let Some(Clause::ForEach { body, .. }) = declared else {
        return Err(AbiError::NotALoop { position, clause });
    };
    let inside = usize::try_from(site).ok().and_then(|index| body.get(index));
    if matches!(inside, Some(Clause::Effect { .. })) {
        Ok(())
    } else {
        Err(AbiError::NotALoopedAccess {
            position,
            clause,
            site,
        })
    }
}

/// Judge a signature's ABI binding against the declaration it is a
/// binding for.
///
/// A binding says where each of the guest's arguments comes from, and a
/// caller that cannot resolve one cannot invoke the method at all — so an
/// unresolvable binding is a package that publishes and then traps for
/// everyone.
///
/// What this cannot judge is the binding against the component's real
/// ABI: that needs the artifact, and it belongs with whoever holds one.
///
/// # Errors
///
/// Any [`AbiError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_abi(signature: &MethodSignature) -> Result<(), AbiError> {
    let bound = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
    let mut carried = vec![0u32; signature.params.len()];
    for (index, binding) in signature.abi.iter().enumerate() {
        let position = bound(index);
        match binding {
            AbiParam::Handle(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let Some(declared) = declared else {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                };
                if !matches!(declared, Clause::Effect { .. }) {
                    return Err(AbiError::NotAnAccess {
                        position,
                        clause: *clause,
                    });
                }
            }
            AbiParam::Guard(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let Some(declared) = declared else {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                };
                if declared.guard().is_none() {
                    return Err(AbiError::UnguardedClause {
                        position,
                        clause: *clause,
                    });
                }
            }
            AbiParam::Run { clause, site } => {
                check_run(signature, position, *clause, *site)?;
            }
            // The grant is the method's own declaration, so a binding
            // that names one where nothing is issued asks for a handle
            // the walk would not hand over.
            AbiParam::Issuer => {
                if signature.issues.is_none() {
                    return Err(AbiError::IssuerWithoutIssuedOutput { position });
                }
            }
            AbiParam::Bucket(param) => {
                let slot = usize::try_from(*param).map_err(|_| AbiError::NoSuchParam {
                    position,
                    param: *param,
                    declared: bound(signature.params.len()),
                })?;
                match signature.params.get(slot) {
                    Some(kind) if kind.is_edge() => carried[slot] += 1,
                    Some(other) => {
                        return Err(AbiError::NotABucket {
                            position,
                            param: *param,
                            kind: other.name(),
                        });
                    }
                    None => {
                        return Err(AbiError::NoSuchParam {
                            position,
                            param: *param,
                            declared: bound(signature.params.len()),
                        });
                    }
                }
            }
            // A derived binding is an expression over the same inputs the
            // effect clauses read, so its argument and configuration
            // references are bounded by the same evaluation every node
            // runs at routing. Repeating that walk here would be a second
            // opinion on it.
            AbiParam::Derived(_) => {}
        }
    }
    for (param, count) in carried.iter().enumerate() {
        if *count > 1 {
            return Err(AbiError::BucketCarriedTwice {
                param: bound(param),
                carried: *count,
            });
        }
    }
    Ok(())
}

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
    /// A presence requirement on a target that names no single leaf.
    ///
    /// `Absent` and `Present` are what a write requires of *the leaf it
    /// lands on*, and an interval has none: it stays valid whatever
    /// entries enter or leave it, which is the property that makes it
    /// declarable ahead of execution at all. A point and a collection
    /// entry each name one leaf and carry the requirement; a range
    /// carries only the indifferent one.
    #[error("effect clause {clause} requires a presence of an interval, which names no leaf")]
    PresenceOnInterval {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
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
        /// The declared parameter count.
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
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Contents<'a> {
    /// One leaf, as the expression naming it.
    Leaf(&'a Expr),
    /// Every entry of one collection, as the owner and identity it hangs
    /// under.
    Entries(&'a Expr, SlotId, &'a [Expr]),
}

/// Which cell's contents a clause is an answer about.
fn contents(target: &TargetExpr) -> Contents<'_> {
    match target {
        TargetExpr::Point(key) => Contents::Leaf(key),
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
        } => Contents::Entries(owner, *collection, material),
    }
}

/// The slot a target names, and the material keying it there.
///
/// Both point shapes and both collection shapes carry one: a child key
/// spells the slot beside its material, and a collection carries it as
/// the identity its entries hang under. A fresh key is the exception and
/// answers `None` — it is a local id minted under the owner rather than
/// a child of any slot, so there is nothing for the vocabulary to be
/// about.
fn slot_of(target: &TargetExpr) -> Option<(SlotId, &[Expr])> {
    match target {
        TargetExpr::Point(Expr::ChildKey { slot, material, .. }) => Some((*slot, material)),
        TargetExpr::Point(_) => None,
        TargetExpr::Entry {
            collection,
            material,
            ..
        }
        | TargetExpr::Range {
            collection,
            material,
            ..
        } => Some((*collection, material)),
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
            || (matches!(mode, ModeExpr::Write) && (presence.is_none() || requires == presence))
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
                        | ModeExpr::Write
                        | ModeExpr::Delta
                        | ModeExpr::Credit
                        | ModeExpr::Reserve(_)
                ),
            "holds a fungible balance: one leaf, keyed by the resource it holds, \
             denominated in that resource",
        ),
        CLAIMS => (
            point
                && keyed_by_what_it_holds
                && matches!(
                    mode,
                    ModeExpr::Read
                        | ModeExpr::Write
                        | ModeExpr::Delta
                        | ModeExpr::Credit
                        | ModeExpr::Reserve(_)
                ),
            "is the delivery fallback beside a vault, and holds value on the same \
             terms: one leaf, keyed by the resource it holds and denominated in it",
        ),
        // Instances are a quantity too, and the interval they sit in is
        // the holdings of exactly one resource.
        NF_VAULT => (
            !point && keyed_by_what_it_holds && matches!(mode, ModeExpr::Read | ModeExpr::Write),
            "holds a resource's instances: an interval or one of its entries, keyed by \
             that resource and denominated in it",
        ),
        CONFIG => (
            point && bare && creates,
            "is the creation-fixed configuration leaf: one leaf, no material, \
             written where absent and never rewritten",
        ),
        AUTH => (
            point && bare && matches!(mode, ModeExpr::Read | ModeExpr::Write),
            "is the stored authority cell: one leaf, no material, read or rewritten whole",
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

/// Whether `resource` is a denomination this signature states — at a
/// parameter position, or on one of its own clauses.
///
/// What ties a granted gate to the value it governs. Syntactic, because
/// this runs at publish where no arguments exist: the same standard the
/// target comparison holds to, and what keeps a caller's choice of
/// resource a choice of which rule governs rather than of what it says.
fn denominates(signature: &MethodSignature, flat: &[&Clause], resource: &Expr) -> bool {
    signature
        .denominations
        .iter()
        .flatten()
        .any(|named| named == resource)
        || flat.iter().any(|clause| {
            matches!(
                clause,
                Clause::Effect {
                    denomination: Some(named),
                    ..
                } if named.as_ref() == resource
            )
        })
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
    } = access
    else {
        return Ok(());
    };
    let denomination = denomination.as_deref();
    if !targets_own_prefix(target) {
        return Err(DeclarationError::ForeignPrefix { clause });
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
            condition:
                ConditionExpr::Holds {
                    target: required,
                    presence,
                },
        } if **required == *target
            && (condition_guard.is_none() || condition_guard.as_deref() == guard.as_deref()) =>
        {
            Some(*presence)
        }
        _ => None,
    });
    protocol_shape(clause, target, mode, denomination, requires)?;
    // And whether the world hands out anything for this pairing at all.
    // Asked of the clause through the same function an engine reads a
    // handle's type off, so publish refuses exactly what materialization
    // could not have built.
    if materialized_kind(access).is_none() {
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
                    target: TargetExpr::Point(Expr::ChildKey { owner, slot, material }),
                    mode: ModeExpr::Write,
                    ..
                } if **owner == Expr::SelfAddr && *slot == CONFIG && material.is_empty()
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
            slot: CONFIG,
            material: Vec::new(),
        })
    };
    vec![
        Clause::Requires {
            guard: None,
            condition: ConditionExpr::Holds {
                target: Box::new(leaf()),
                presence: Presence::Absent,
            },
        },
        Clause::Effect {
            guard: None,
            target: leaf(),
            mode: ModeExpr::Write,
            denomination: None,
        },
    ]
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
    // The mark promises a caller has nothing to hear back, and a
    // precondition is a verdict some caller hears: a total method
    // declares no condition and no reservation.
    if signature.totality.is_total()
        && flat.iter().any(|clause| {
            matches!(clause, Clause::Requires { .. })
                || matches!(
                    clause,
                    Clause::Effect {
                        mode: ModeExpr::Reserve(_),
                        ..
                    }
                )
        })
    {
        return Err(DeclarationError::ConditionalTotality);
    }
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
        .as_ref()
        .is_some_and(|issuance| issuance.mark.is_empty())
    {
        return Err(DeclarationError::UnmarkedIssuance);
    }
    // And at the third position a signature names resources.
    judge_outputs(&signature.outputs)?;
    for (index, clause) in flat.iter().enumerate() {
        judge_access(u32::try_from(index).unwrap_or(u32::MAX), clause, &flat)?;
    }
    check_conditions(signature, &flat)
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
            condition: ConditionExpr::Holds { target, presence },
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
    let mut holds: BTreeMap<Contents<'_>, bool> = BTreeMap::new();
    for (index, clause) in flat.iter().enumerate() {
        let Clause::Effect {
            target,
            denomination,
            ..
        } = clause
        else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let value = denomination.is_some();
        if *holds.entry(contents(target)).or_insert(value) != value {
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
fn check_conditions(signature: &MethodSignature, flat: &[&Clause]) -> Result<(), DeclarationError> {
    let declares =
        |target: &TargetExpr, under: Option<&Expr>, admits: &dyn Fn(&ModeExpr) -> bool| {
            flat.iter().any(|clause| {
                matches!(
                    clause,
                    Clause::Effect {
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
    let coherent = |mode: &ModeExpr| matches!(mode, ModeExpr::Read | ModeExpr::Write);
    for (index, clause) in flat.iter().enumerate() {
        let Clause::Requires { guard, condition } = clause else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let under = guard.as_deref();
        match condition {
            ConditionExpr::Holds { target, presence } => {
                if *presence == Presence::Either {
                    return Err(DeclarationError::VacuousCondition { clause });
                }
                // A presence is about the leaf it names, and an interval
                // has none — the same refusal a presence-requiring write
                // meets.
                if matches!(**target, TargetExpr::Range { .. }) {
                    return Err(DeclarationError::PresenceOnInterval { clause });
                }
                if !declares(target, under, &coherent) {
                    return Err(DeclarationError::ConditionUndeclared { clause });
                }
            }
            ConditionExpr::Satisfies { rule } => {
                // An identity a caller names is one that caller can
                // always present, and a caller-named cell is one holding
                // whatever admits them.
                if rule.reads_call_inputs() {
                    return Err(DeclarationError::CallerNamedCondition { clause });
                }
                for leaf in rule.leaves() {
                    // A grant leaf is the one condition a caller may
                    // name, because the rule is the resource's own
                    // commitment and naming it chooses which rule
                    // governs rather than what it says. That holds only
                    // while the resource governed is the resource
                    // moved: a gate over one argument beside an effect
                    // denominated in another is a rule a caller
                    // satisfies with a resource of their own, over
                    // value it says nothing about.
                    if let RuleLeaf::Granted { resource, .. } = leaf {
                        if !denominates(signature, flat, resource) {
                            return Err(DeclarationError::GrantOverAnother { clause });
                        }
                        continue;
                    }
                    let RuleLeaf::Stored { cell, .. } = leaf else {
                        continue;
                    };
                    let point = TargetExpr::Point(cell.clone());
                    if declares(&point, under, &coherent) {
                        continue;
                    }
                    return Err(DeclarationError::ConditionUndeclared { clause });
                }
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
                    condition: ConditionExpr::Satisfies { rule },
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
                slot: VAULT,
                material: vec![badge.clone()],
            }),
        };
        let held = flat.iter().any(|beside| {
            matches!(
                beside,
                Clause::Requires {
                    guard: condition_guard,
                    condition: ConditionExpr::Holds {
                        target,
                        presence: Presence::Present,
                    },
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

/// Why metadata is past a bound the vocabulary fixes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetadataBoundsError {
    /// An event table longer than the index an emitted event can carry.
    #[error("event table names {0} types, past the {MAX_EVENT_TYPES} an event index can reach")]
    EventTable(usize),
    /// A role table longer than the band a package's own roles occupy.
    #[error("role table names {0} roles, past the {MAX_PACKAGE_ROLES} a package's band holds")]
    RoleTable(usize),
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
    if metadata.roles.len() > MAX_PACKAGE_ROLES {
        return Err(MetadataBoundsError::RoleTable(metadata.roles.len()));
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
    let (slot, _) = slot_of(target)?;
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
        RuleExpr::Require(
            RuleLeaf::Stored { cell, .. } | RuleLeaf::Granted { resource: cell, .. },
        ) => check_expr_bounds(cell, 0),
        RuleExpr::CountOf { rules, .. } => rules.iter().try_for_each(check_rule_bounds),
    }
}

fn check_signature_bounds(signature: &MethodSignature) -> Result<(), SignatureBoundsError> {
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
    if let Some(issuance) = &signature.issues {
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
            Clause::Requires { guard, condition } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                match condition {
                    ConditionExpr::Holds { target, .. } => check_target_bounds(target)?,
                    ConditionExpr::Satisfies { rule } => check_rule_bounds(rule)?,
                }
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
        ModeExpr::Read | ModeExpr::Delta | ModeExpr::Credit | ModeExpr::Write => Ok(()),
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
    grants.iter().try_for_each(|(behaviour, entry)| {
        // The spelling first: an arm the behaviour does not admit is a
        // second way of saying what an absent entry already says, and
        // saying it at publish is what keeps the sealed table to one
        // spelling per state.
        if !behaviour.admits_expr(entry) {
            return Err(SignatureBoundsError::UnadmittedGrant);
        }
        match entry {
            // Neither states a rule, so neither has a depth.
            GrantExpr::Open | GrantExpr::Never | GrantExpr::Credential(_) => Ok(()),
            GrantExpr::Rule(rule) => rule
                .within_caps(0)
                .then_some(())
                .ok_or(SignatureBoundsError::RuleCaps),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::{ShapeField, ShapeTable, TypeShape};
    use hyperscale_vm_types::{Address, AddressClass};

    use super::*;
    use crate::metadata::{SlotKind, SlotShape};

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
                ModeExpr::Write,
                denomination,
            )
        };
        let entries = |denomination| {
            one_clause(
                own_interval(slot, vec![a_resource()]),
                ModeExpr::Write,
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

    use crate::auth::PRIMARY;
    use crate::envelope::NULLIFIER_SLOT;
    use crate::metadata::PACKAGE_SLOT;
    use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};
    use crate::signature::{Issuance, ParamType, Totality};
    use crate::types::{Value, package_slot};

    /// A signature whose only effect points at `expr`.
    fn signature_over(expr: Expr) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(expr),
                mode: ModeExpr::Write,
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
                    guard: None,
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: SlotId(PACKAGE_SLOT_BASE),
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

    /// Every name table is bounded by what reaches an entry: the kernel
    /// checks an emitted event type and a returned error code without
    /// holding the metadata, and a gate carries a role's band offset —
    /// so a table longer than its ceiling names entries nothing could
    /// ever refer to.
    #[test]
    fn a_name_table_past_the_index_the_kernel_accepts_is_refused() {
        // A name of its own per entry, each with a shape under it, so the
        // table's length is the only thing under test here.
        let events = |len: usize| {
            let named: Vec<String> = (0..len).map(|index| format!("e{index}")).collect();
            PackageMetadata {
                types: named
                    .iter()
                    .map(|name| (name.clone(), TypeShape::Tuple(Vec::new())))
                    .collect(),
                events: named,
                ..PackageMetadata::default()
            }
        };
        assert_bounded(
            &events(MAX_EVENT_TYPES as usize),
            &events(MAX_EVENT_TYPES as usize + 1),
        );

        let errors = |len: usize| PackageMetadata {
            errors: vec![String::new(); len],
            ..PackageMetadata::default()
        };
        assert_bounded(
            &errors(MAX_ERROR_CODES as usize),
            &errors(MAX_ERROR_CODES as usize + 1),
        );

        let roles = |len: usize| PackageMetadata {
            roles: vec![String::new(); len],
            ..PackageMetadata::default()
        };
        assert_bounded(&roles(MAX_PACKAGE_ROLES), &roles(MAX_PACKAGE_ROLES + 1));
    }

    fn clause() -> Clause {
        Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Delta,
            denomination: None,
        }
    }

    fn signature(params: Vec<ParamType>, abi: Vec<AbiParam>) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            params,
            abi,
            effects: vec![clause()],
            ..MethodSignature::default()
        }
    }

    #[test]
    fn a_binding_resolves_against_its_own_signature() {
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        assert!(matches!(
            check_abi(&signature(vec![], vec![AbiParam::Handle(1)])),
            Err(AbiError::NoSuchClause { clause: 1, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![ParamType::U64], vec![AbiParam::Bucket(0)])),
            Err(AbiError::NotABucket { param: 0, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![], vec![AbiParam::Bucket(3)])),
            Err(AbiError::NoSuchParam { param: 3, .. })
        ));
    }

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
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![a_resource()],
            })
        };
        let access = |guard: Option<Expr>, mode| Clause::Effect {
            guard: guard.map(Box::new),
            target: cell(),
            mode,
            denomination: None,
        };
        // The incoherent mode: a movement declares the cell, but a
        // movement cannot carry a judgment.
        let movement = || Clause::Effect {
            guard: None,
            target: cell(),
            mode: ModeExpr::Delta,
            denomination: Some(Box::new(a_resource())),
        };
        let requires = |guard: Option<Expr>, condition| Clause::Requires {
            guard: guard.map(Box::new),
            condition,
        };
        let holds = |presence| ConditionExpr::Holds {
            target: Box::new(cell()),
            presence,
        };
        let satisfies = || ConditionExpr::Satisfies {
            rule: RuleExpr::Require(RuleLeaf::Stored {
                cell: match cell() {
                    TargetExpr::Point(expr) => expr,
                    _ => unreachable!(),
                },
                role: PRIMARY,
            }),
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

    /// A condition that requires nothing, names an interval, or names
    /// authority its own caller supplies is refused on its own terms.
    #[test]
    fn a_degenerate_or_caller_named_condition_is_refused() {
        let cell = || {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![],
            })
        };
        let access = |guard: Option<Expr>, mode| Clause::Effect {
            guard: guard.map(Box::new),
            target: cell(),
            mode,
            denomination: None,
        };
        let requires = |guard: Option<Expr>, condition| Clause::Requires {
            guard: guard.map(Box::new),
            condition,
        };
        let holds = |presence| ConditionExpr::Holds {
            target: Box::new(cell()),
            presence,
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // A condition requiring nothing, and one about an interval,
        // which names no leaf.
        assert_eq!(
            declared(vec![
                access(None, ModeExpr::Read),
                requires(None, holds(Presence::Either)),
            ]),
            Err(DeclarationError::VacuousCondition { clause: 1 })
        );
        assert_eq!(
            declared(vec![requires(
                None,
                ConditionExpr::Holds {
                    target: Box::new(TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: SlotId(PACKAGE_SLOT_BASE),
                        material: vec![],
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(10)),
                        cap: Expr::Literal(Value::U64(4)),
                    }),
                    presence: Presence::Present,
                },
            )]),
            Err(DeclarationError::PresenceOnInterval { clause: 0 })
        );

        // Authority the caller names admits everyone — at a claim leaf
        // and at a stored leaf's cell alike.
        assert_eq!(
            declared(vec![requires(
                None,
                ConditionExpr::Satisfies {
                    rule: RuleExpr::claim(Expr::Arg(0)),
                },
            )]),
            Err(DeclarationError::CallerNamedCondition { clause: 0 })
        );
        assert_eq!(
            declared(vec![requires(
                None,
                ConditionExpr::Satisfies {
                    rule: RuleExpr::Require(RuleLeaf::Stored {
                        cell: Expr::Arg(0),
                        role: PRIMARY,
                    }),
                },
            )]),
            Err(DeclarationError::CallerNamedCondition { clause: 0 })
        );
    }

    /// A grant leaf is the one condition a caller may name, and what
    /// makes that safe is the resource governed being the resource
    /// moved. Naming one the method never denominates lets a caller
    /// bring a resource of their own — granting themselves — and
    /// satisfy a gate over value it says nothing about.
    #[test]
    fn a_sealed_gate_over_a_resource_the_method_never_moves_is_refused() {
        let vault = |resource: Expr| Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: VAULT,
                material: vec![resource.clone()],
            }),
            mode: ModeExpr::Delta,
            denomination: Some(Box::new(resource)),
        };
        let granted = |resource: Expr| Clause::Requires {
            guard: None,
            condition: ConditionExpr::Satisfies {
                rule: RuleExpr::Require(RuleLeaf::Granted {
                    resource,
                    behaviour: GrantedBehaviour::Recall,
                }),
            },
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                params: vec![ParamType::Resource, ParamType::Resource],
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // The account's own recall: the gate and the movement name one
        // argument, so the caller chooses which rule governs and the
        // rule governs what they chose.
        assert_eq!(
            declared(vec![granted(Expr::Arg(0)), vault(Expr::Arg(0))]),
            Ok(())
        );

        // The same gate over value it does not govern.
        assert_eq!(
            declared(vec![granted(Expr::Arg(0)), vault(Expr::Arg(1))]),
            Err(DeclarationError::GrantOverAnother { clause: 0 })
        );

        // And a gate beside no movement at all: a granted behaviour is
        // about what happens to the resource, so a method that touches
        // none of it has nothing for the rule to be read over.
        assert_eq!(
            declared(vec![granted(Expr::Arg(0))]),
            Err(DeclarationError::GrantOverAnother { clause: 0 })
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
                issues: Some(Issuance {
                    mark: mark.to_vec(),
                    kind: ResourceKind::Fungible,
                    grants: GrantsExpr::new(),
                }),
                ..MethodSignature::default()
            })
        };
        assert_eq!(issues(b"unit"), Ok(()));
        assert_eq!(issues(b""), Err(DeclarationError::UnmarkedIssuance));
    }

    /// A mint is justified by a condition the same declaration carries,
    /// or it does not publish: identity takes the stored rule, a badge
    /// takes that plus possession keyed by the same expression.
    #[test]
    fn a_mint_no_condition_justifies_is_refused() {
        let auth_cell = || Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotId(4),
            material: vec![],
        };
        let read = |target| Clause::Effect {
            guard: None,
            target,
            mode: ModeExpr::Read,
            denomination: None,
        };
        let satisfies = || Clause::Requires {
            guard: None,
            condition: ConditionExpr::Satisfies {
                rule: RuleExpr::Require(RuleLeaf::Stored {
                    cell: auth_cell(),
                    role: PRIMARY,
                }),
            },
        };
        let vault = |badge: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: VAULT,
                material: vec![badge],
            })
        };
        let read_vault = |badge: Expr| Clause::Effect {
            guard: None,
            target: vault(badge.clone()),
            mode: ModeExpr::Read,
            denomination: Some(Box::new(badge)),
        };
        let holds = |target| Clause::Requires {
            guard: None,
            condition: ConditionExpr::Holds {
                target: Box::new(target),
                presence: Presence::Present,
            },
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
                    condition: ConditionExpr::Satisfies {
                        rule: RuleExpr::claim(Expr::Config(0)),
                    },
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

    /// A declared threshold sits under the caps a stored one is decoded
    /// under, so a signature that publishes cannot evaluate into a rule
    /// the decode gate would refuse.
    #[test]
    fn a_declared_rule_is_held_to_the_stored_rules_caps() {
        let guarded = |rule: RuleExpr| PackageMetadata {
            methods: BTreeMap::from([(
                "m".to_owned(),
                MethodSignature {
                    effects: vec![Clause::Requires {
                        guard: None,
                        condition: ConditionExpr::Satisfies { rule },
                    }],
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

    #[test]
    fn a_bucket_is_carried_at_most_once() {
        // A guest receiving one edge's bytes under two names.
        assert!(matches!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
            )),
            Err(AbiError::BucketCarriedTwice {
                param: 0,
                carried: 2
            })
        ));
        // Two buckets, each carried once, in either order.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket, ParamType::U128, ParamType::Bucket],
                vec![AbiParam::Bucket(2), AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        // A bucket the declaring method forwards to a callee: its own
        // guest never reads the amount, so its own ABI carries nothing.
        // The edge's signed bound is still checked where the edge
        // resolves, which is a property of the node and not of the ABI.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle(0)]
            )),
            Ok(())
        );
    }

    /// What a total mark cannot survive, read off the declaration rather
    /// than off the code.
    ///
    /// A leg reads the mark and commits without waiting, so what it has
    /// to exclude is every way the method could still come back with a
    /// refusal. The artifact scan covers the one that leaves the type
    /// system — a trap — and this is the one it cannot see: a gate that
    /// turns the caller away before the body runs.
    #[test]
    fn a_total_mark_needs_a_body_the_declaration_answers_for() {
        let total = |signature: MethodSignature| MethodSignature {
            totality: Totality::Total,
            ..signature
        };

        // The shape that admits: public, and answering for itself.
        assert_eq!(
            check_declarations(&total(MethodSignature::default())),
            Ok(())
        );

        // Every condition is a caller this method can turn away, and a
        // reservation is a race it can lose.
        assert_eq!(
            check_declarations(&total(MethodSignature {
                effects: vec![Clause::Requires {
                    guard: None,
                    condition: ConditionExpr::Satisfies {
                        rule: RuleExpr::claim(Expr::SelfAddr),
                    },
                }],
                ..MethodSignature::default()
            })),
            Err(DeclarationError::ConditionalTotality),
        );
        assert_eq!(
            check_declarations(&total(MethodSignature {
                effects: vec![Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotId(PACKAGE_SLOT_BASE),
                        material: vec![],
                    }),
                    mode: ModeExpr::Reserve(Expr::Literal(Value::U128(5))),
                    denomination: Some(Box::new(Expr::Config(0))),
                }],
                ..MethodSignature::default()
            })),
            Err(DeclarationError::ConditionalTotality),
        );
    }

    /// A presence requirement is about the leaf a write lands on, so the
    /// targets that name one carry it and the interval does not. Refused
    /// at publish, where an author hears about it — and again at
    /// materialization, which honours the requirement rather than
    /// reading past it.
    #[test]
    fn a_presence_requirement_needs_a_target_that_names_a_leaf() {
        let declared = |target: TargetExpr, requires| {
            check_declarations(&MethodSignature {
                effects: vec![
                    Clause::Effect {
                        guard: None,
                        target: target.clone(),
                        mode: ModeExpr::Write,
                        denomination: None,
                    },
                    Clause::Requires {
                        guard: None,
                        condition: ConditionExpr::Holds {
                            target: Box::new(target),
                            presence: requires,
                        },
                    },
                ],
                ..MethodSignature::default()
            })
        };
        let point = TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
        });
        let entry = TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
            order: Expr::Literal(Value::U128(7)),
        };
        let range = TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: Expr::Literal(Value::U64(4)),
        };

        for requires in [Presence::Absent, Presence::Present] {
            // A cell and one collection entry each name exactly one leaf.
            assert_eq!(declared(point.clone(), requires), Ok(()), "{requires:?}");
            assert_eq!(declared(entry.clone(), requires), Ok(()), "{requires:?}");
            // An interval names none.
            assert_eq!(
                declared(range.clone(), requires),
                Err(DeclarationError::PresenceOnInterval { clause: 1 }),
                "{requires:?}"
            );
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
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![],
            })
        };
        let write = |guard: Option<Expr>, presence| Clause::Requires {
            guard: guard.map(Box::new),
            condition: ConditionExpr::Holds {
                target: Box::new(target()),
                presence,
            },
        };
        // The one access every condition above is backed by: unguarded,
        // so it fires whenever any of them does.
        let declared = |conditions: Vec<Clause>| {
            let mut effects = vec![Clause::Effect {
                guard: None,
                target: target(),
                mode: ModeExpr::Write,
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
            condition: ConditionExpr::Holds {
                target: Box::new(own_point(package_slot(0), vec![])),
                presence,
            },
        };
        let declared = |conditions: Vec<Clause>| {
            let mut effects = vec![Clause::Effect {
                guard: None,
                target: own_point(package_slot(0), vec![]),
                mode: ModeExpr::Write,
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
            collection: package_slot(0),
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
                declared(target, ModeExpr::Write, Some(a_resource()),),
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
                slot: SlotId(PACKAGE_SLOT_BASE),
                material,
            })
        };
        let write = |presence| Clause::Requires {
            guard: None,
            condition: ConditionExpr::Holds {
                target: Box::new(cell(vec![])),
                presence,
            },
        };
        let access = |material| Clause::Effect {
            guard: None,
            target: cell(material),
            mode: ModeExpr::Write,
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
                    condition: ConditionExpr::Holds {
                        target: Box::new(cell(vec![Expr::Config(0)])),
                        presence: Presence::Present,
                    },
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

    /// A resource address, for a value cell to be keyed by.
    fn a_resource() -> Expr {
        Expr::Literal(Value::Address(Address::new(
            [7; 31],
            AddressClass::Resource,
        )))
    }

    /// A leaf under the declaring instance, at `slot` and keyed by
    /// `material`.
    fn own_point(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot,
            material,
        })
    }

    /// The whole order-key space of a collection under the declaring
    /// instance, at a cap no test reaches.
    fn own_interval(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
        TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: slot,
            material,
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: Expr::Literal(Value::U64(4)),
        }
    }

    /// A signature declaring exactly one clause.
    fn one_clause(
        target: TargetExpr,
        mode: ModeExpr,
        denomination: Option<Expr>,
    ) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target,
                mode,
                denomination: denomination.map(Box::new),
            }],
            ..MethodSignature::default()
        }
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
            ModeExpr::Write,
            ModeExpr::Delta,
            ModeExpr::Reserve(Expr::Arg(0)),
        ];
        // A vault and the delivery cell beside it are keyed by the
        // resource they hold and say so in every mode they are reached
        // in — a read included, because a read of a cell that says
        // nothing is a read of bytes, and a vault has no byte surface
        // for one to come through.
        for slot in [VAULT, CLAIMS] {
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
        let write = || ModeExpr::Write;
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
        let write = || ModeExpr::Write;
        let plain = |target, mode| one_clause(target, mode, None);
        // A write that creates: the access, and the one-way door beside
        // it as the condition it now is.
        let creating = |target: TargetExpr, denomination: Option<Expr>| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![
                Clause::Effect {
                    guard: None,
                    target: target.clone(),
                    mode: ModeExpr::Write,
                    denomination: denomination.map(Box::new),
                },
                Clause::Requires {
                    guard: None,
                    condition: ConditionExpr::Holds {
                        target: Box::new(target),
                        presence: Presence::Absent,
                    },
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
            ModeExpr::Write,
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
                ModeExpr::Write,
                Some(a_resource())
            )),
            Ok(())
        );
        assert_eq!(
            check_declarations(&one_clause(
                interval(vec![other()]),
                ModeExpr::Write,
                Some(a_resource())
            )),
            Err(DeclarationError::DenominationNotKeyed { clause: 0 })
        );

        // A fresh key carries no material, so nothing could find it
        // again to take value out of it.
        assert_eq!(
            check_declarations(&one_clause(
                TargetExpr::Point(Expr::FreshKey { slot: 0 }),
                ModeExpr::Write,
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
            check_declarations(&one_clause(own(vec![]), ModeExpr::Write, None)),
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
        let write = || ModeExpr::Write;
        let effect = |target, mode, denomination: Option<Expr>| Clause::Effect {
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
            collection: package_slot(1),
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
                        collection: package_slot(1),
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
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot,
                    material: vec![],
                }),
                mode: ModeExpr::Read,
                denomination: None,
            }],
            ..MethodSignature::default()
        };
        // Everything below the base the vocabulary has not spoken for.
        let assigned = [VAULT, CLAIMS, CONFIG, AUTH, RESOURCE, NF_VAULT, INSTANCE];
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
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![a_resource()],
            })
        };
        let entry_of = |slot: u16, order: u128| TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotId(slot),
            material: vec![a_resource()],
            order: Expr::Literal(Value::U128(order)),
        };
        let write = || ModeExpr::Write;

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
}
