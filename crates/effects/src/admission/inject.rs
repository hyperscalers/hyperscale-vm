//! The entries a resource's own rules put on a frame.
//!
//! One door: an entry is found — derived from a declaration for an
//! issuance, carried by a presented record for a destruction, a reach or
//! a movement — and asked one question three ways. Does it decode, does
//! the frame's own claim already satisfy it, and what is left for the
//! caller to answer.
//!
//! Asking it in one place is what keeps the answer one answer: a
//! composer predicts this to know what to present, and a site that
//! subtracted where another did not would emit a graph admission
//! refuses.

use hyperscale_vm_types::{
    Address, AddressClass, Effect, EffectTarget, Mode, Presence, ResourceAddr,
};

use super::AdmissionError;
use crate::auth::RuleBytes;
use crate::claim::Claim;
use crate::dsl::{Declaration, DeclaredAccess, PresentedGrants, Reach};
use crate::hash::Hasher;
use crate::invoke::IssuanceGrant;
use crate::manifest::{JudgedLeaf, NodeInput};
use crate::publish::founds_its_resource;
use crate::resource::{GrantedBehaviour, granting_issued_resource, holdings_collection};
use crate::rule::{Holding, Rule, SealedLeaf, StoredRule, never};
use crate::signature::{Issued, MethodSignature};
use crate::types::{Value, child_key};
use crate::vocabulary::{HALT, VAULT};

/// The requirement one entry puts on a frame speaking as `speaking_for`,
/// or nothing where it demands nothing of it.
///
/// **A frame speaks for itself.** An entry the executing instance's own
/// claim already satisfies is not appended at all — which reproduces the
/// derivation gate exactly, leaves a rule naming a badge meaning
/// delegated authority, and costs the ordinary issuer nothing. The
/// extension is this entry's alone and never the node's evidence: a
/// claim on the target minted into that set would satisfy every
/// `Claim(SelfAddr)` gate standing beside it, which is the shape an
/// account's own spending gates take.
///
/// The one door every actor question goes through. What separates
/// issuance, destruction and reach is where the entry is found — a
/// declaration derives one, a presented record carries the other two —
/// and from there they are one question asked three times: does the
/// entry decode, does the frame's own claim already satisfy it, and what
/// is left for the caller to answer.
///
/// Asking it in one place is what keeps the answer one answer. A
/// composer predicts this to know what to present, so a site that
/// subtracted where another did not would emit a graph admission
/// refuses — and there is no way to notice that from either site alone.
///
/// # Errors
///
/// [`AdmissionError::Unadmitted`] where no entry admits the behaviour,
/// and [`AdmissionError::EntryMalformed`] where the entry's bytes are
/// not a rule an actor question may carry.
fn injected_entry(
    entry: Option<&RuleBytes>,
    resource: ResourceAddr,
    behaviour: GrantedBehaviour,
    speaking_for: Option<Claim>,
    node_index: u32,
) -> Result<Option<Injected>, AdmissionError> {
    let malformed = || AdmissionError::EntryMalformed {
        node: node_index,
        resource,
        behaviour,
    };
    let sealed = entry.ok_or(AdmissionError::Unadmitted {
        node: node_index,
        resource,
        behaviour,
    })?;
    let Some(rule) = behaviour
        .demanded(sealed, speaking_for)
        .map_err(|_| malformed())?
    else {
        return Ok(None);
    };
    Ok(Some(Injected {
        rule: judged_claims(&rule).ok_or_else(malformed)?,
        asks: Asks::Entry(rule),
        resource,
        behaviour,
    }))
}

/// A requirement the protocol put on a frame, and the entry that put it
/// there.
///
/// Nothing here is declared. A package writes no word about any of it —
/// which is what makes omission inexpressible — so a reader meeting one
/// of these is meeting the protocol speak, and the resource and the
/// behaviour are what it speaks for. That provenance is why these are
/// carried out of the injection rather than pushed into the frame and
/// forgotten: the rule alone says what must hold and cannot say who
/// asked, and a key is a hash that inverts to nothing.
///
/// [`Condition`](crate::dsl::Condition) keeps the same provenance one
/// layer down, where a frame's conditions join every other frame's in
/// the union declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injected {
    /// What must hold, resolved: every holding a key under the party the
    /// question is about.
    pub rule: Rule<JudgedLeaf>,
    /// What was asked, before resolving hashed the subject away.
    pub asks: Asks,
    /// The resource whose entry demands it.
    pub resource: ResourceAddr,
    /// Which of that resource's entries.
    pub behaviour: GrantedBehaviour,
}

/// What an injected requirement asks, in the terms it was asked in.
///
/// Beside the resolved rule rather than derived from it, because
/// resolving is one-way: a holding becomes the presence of a key, and a
/// key is a hash of the party and the badge that inverts to neither. So
/// a reader handed the rule alone can see that some leaf must be there
/// and never which, which is the whole reason a refusal is unreadable
/// without this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asks {
    /// The entry's own sealed rule.
    Entry(StoredRule),
    /// That the party whose cell moves is not halted — which every
    /// movement of a resource granting `Halt` reads, and which no
    /// entry states because it is a fact about the holder rather than a
    /// rule about anyone.
    Unhalted,
}

/// An actor question's rule read as judged leaves.
///
/// Such a rule reads claims and the seal refuses it otherwise, so a
/// holding here is a record that could not have been sealed — `None`,
/// for the caller to name in its own terms.
fn judged_claims(rule: &StoredRule) -> Option<Rule<JudgedLeaf>> {
    rule.map_leaves(&mut |leaf| match leaf {
        SealedLeaf::Claim(claim) => Ok(JudgedLeaf::Claim(*claim)),
        SealedLeaf::Held { .. } => Err(()),
    })
    .ok()
}

/// Resolve the resource this frame issues, and inject the authority
/// entries its direction is held to.
///
/// The entry comes from the declaration rather than from a presented
/// record, and the asymmetry with a movement entry is the honest one: a
/// movement rule governs a resource a *caller* named, so the presented
/// record is what makes it trustworthy; an issuance rule governs one the
/// *declaration* derives, and re-derivation is the address itself.
pub(super) fn inject_issuance_rules(
    hasher: &dyn Hasher,
    signature: &MethodSignature,
    target: Address,
    config: &[Value],
    node_index: u32,
) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
    let mut granted = Vec::with_capacity(signature.issues.len());
    let mut injected = Vec::new();
    for issuance in &signature.issues {
        // The rules the mark grants ride the grant's own address, so what
        // a body issues is what a gate naming the same resource resolves
        // to.
        let rules = issuance
            .grants
            .resolve(hasher, target, config)
            .map_err(|source| AdmissionError::Eval {
                node: node_index,
                source: source.into(),
            })?;
        let resource =
            granting_issued_resource(hasher, target, issuance.kind, &rules, &issuance.mark);
        granted.push(IssuanceGrant {
            resource,
            kind: issuance.kind,
            direction: issuance.direction,
        });
        // A frame that creates the resource's record is the frame
        // founding its supply, and founding is not minting: the record's
        // own absent-door is the cap, so a resource granting no `Mint`
        // entry comes up holding what its creation says and can never
        // hold more.
        //
        // Asked of the signature, which is where publish asks it. The
        // exemption is the one thing standing between an issuance and
        // the entry that governs it, so the two sides deciding it
        // separately is the two sides disagreeing about who may mint:
        // publish holds a founding clause to naming this issuance's own
        // `SelfResource`, and an evaluated key matching the record is a
        // weaker thing to be — a caller-named argument reaches it too.
        if founds_its_resource(issuance, signature) {
            continue;
        }
        // A resource is not an acting identity, so a target that issues
        // one is callable and names a claim.
        let own = Claim::of_address(target).ok_or(AdmissionError::Unadmitted {
            node: node_index,
            resource,
            behaviour: GrantedBehaviour::Mint,
        })?;
        for behaviour in issuance.direction.behaviours() {
            let entry = injected_entry(
                rules.get(*behaviour),
                resource,
                *behaviour,
                Some(own),
                node_index,
            )?;
            injected.extend(entry);
        }
    }
    Ok((granted, injected))
}

/// Resolve the per-bucket grants this frame's declared destructions
/// earn, and inject the entries admitting them.
///
/// The mirror of an issuance and not a case of one. An issuance governs
/// a resource the *declaration* derives, so re-derivation is the address
/// itself; a destruction governs one a **caller** named, so the
/// presented record is what makes the rule trustworthy — the same reason
/// a movement entry needs one.
///
/// Absence withholds, twice over: a resource whose record was not
/// presented grants nothing here, and one granting no `Burn` entry is
/// one nobody may destroy. Neither needs a class byte to tell it from a
/// bypass, because withholding an authority is the safe direction —
/// what the class exists for is the movement a missing record would
/// otherwise let through.
pub(super) fn inject_destruction_rules(
    grants: &PresentedGrants,
    signature: &MethodSignature,
    inputs: &[NodeInput],
    evidence_of: Address,
    node_index: u32,
) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
    let mut granted = Vec::with_capacity(signature.destroys.len());
    let mut injected = Vec::new();
    for param in &signature.destroys {
        let Some(NodeInput::Edge {
            resource, content, ..
        }) = usize::try_from(*param).ok().and_then(|at| inputs.get(at))
        else {
            return Err(AdmissionError::DestroysNoEdge {
                node: node_index,
                param: *param,
            });
        };
        // The frame speaks for itself here too, though it rarely is the
        // party: an account destroying a token it holds is not the
        // token's issuer, so a rule naming the issuer reaches the call
        // and the caller answers for it.
        let entry = injected_entry(
            grants
                .rules(*resource)
                .and_then(|rules| rules.get(GrantedBehaviour::Burn)),
            *resource,
            GrantedBehaviour::Burn,
            Claim::of_address(evidence_of),
            node_index,
        )?;
        granted.push(IssuanceGrant {
            resource: *resource,
            kind: content.kind(),
            direction: Issued::Burned,
        });
        injected.extend(entry);
    }
    Ok((granted, injected))
}

/// Inject the entry admitting each access that reaches a foreign prefix.
///
/// The reach is issuer-initiated by construction — a declaration cannot
/// name a stranger's cell without saying which authority lets it — so
/// what governs it is the reached resource's own sealed rule and nothing
/// else. The resource is the one the key is derived from, which is what
/// makes the entry judged always the entry of the thing actually
/// reached.
///
/// Absence withholds, and here that is the whole of it: a resource
/// granting no entry for the behaviour is one nobody may reach a holder
/// of, which is every resource until its issuer says otherwise.
pub(super) fn inject_reach_rules(
    grants: &PresentedGrants,
    frame: &Declaration,
    reaching: Address,
    node_index: u32,
) -> Result<Vec<Injected>, AdmissionError> {
    let mut injected = Vec::new();
    let mut wanted: Vec<Reach> = Vec::new();
    for access in &frame.ordered {
        let Some(reach) = access.reach else {
            continue;
        };
        if !wanted.contains(&reach) {
            wanted.push(reach);
        }
    }
    for Reach {
        behaviour,
        resource,
    } in wanted
    {
        // The frame speaks for itself here as it does at every other
        // injected authority entry: an issuer whose own entry names it
        // is the authority, and asking it to prove it is asking for a
        // claim on a component, which only that component can mint.
        let entry = injected_entry(
            grants
                .rules(resource)
                .and_then(|rules| rules.get(behaviour)),
            resource,
            behaviour,
            Claim::of_address(reaching),
            node_index,
        )?;
        injected.extend(entry);
    }
    Ok(injected)
}

/// Inject the movement requirements this frame's declared accesses earn.
///
/// A package will not declare a rule it does not want, so the requirement
/// comes from here rather than from the signature — which is what makes
/// omission inexpressible: a component's vault is fenced exactly as an
/// account's is, and neither package wrote a word about it.
///
/// Appended to the frame's own conditions, so everything downstream reads
/// them the way it reads an authored one, and placed where its leaves
/// send it — which for a movement rule is always materialization, since
/// every leaf it holds reads the store.
///
/// One requirement per (owner, resource, behaviour) however many accesses
/// name it, since a rule asked twice is one question. Each holding
/// resolves against the access's own owner, and the read it names is
/// appended so the state is provisioned wherever the call runs — the
/// owner is the frame's own instance, which [`judge_prefixes`] has already
/// held every access to, so nothing here adds a participant.
pub(super) fn inject_movement_rules(
    hasher: &dyn Hasher,
    grants: &PresentedGrants,
    frame: &mut Declaration,
    total: bool,
    node_index: u32,
) -> Result<Vec<Injected>, AdmissionError> {
    let mut injected = Vec::new();
    // Which requirements this frame earns, before any is built: an access
    // whose mode reaches both directions earns both, and only a
    // reservation carries its own.
    let mut wanted: Vec<(Address, ResourceAddr, GrantedBehaviour)> = Vec::new();
    for access in &frame.ordered {
        // A reaching access earns none of them, and the exemption is the
        // whole class rather than one entry: the party reached is by
        // construction the party every injected requirement would fire
        // against. A halt fence would make a frozen holder unrecallable,
        // a withdraw requirement would leave a restricted resource
        // recallable only from parties who did not need recalling, and a
        // soulbound credential would be unrevocable — which would take
        // revocation, the primary brake, with it.
        if access.reach.is_some() {
            continue;
        }
        let Some(resource) = access.holds else {
            continue;
        };
        let owner = access.effect.target.owner();
        let Some(moves) = access.effect.mode.moves() else {
            continue;
        };
        for behaviour in GrantedBehaviour::earned_by(moves) {
            let entry = (owner, resource, *behaviour);
            if !wanted.contains(&entry) {
                wanted.push(entry);
            }
        }
    }

    for (owner, resource, behaviour) in wanted {
        // A resource whose record was not presented grants nothing here,
        // and what tells that apart from a bypass is the address itself:
        // one whose entries can stop a movement carries the class that
        // says so, and moving it with nothing to resolve is refused.
        let Some(rules) = grants.rules(resource) else {
            if resource.address().class() == AddressClass::Restricted {
                return Err(AdmissionError::RecordWithheld {
                    node: node_index,
                    resource,
                });
            }
            continue;
        };
        // A resource whose issuer can halt a holder is one whose every
        // movement reads that holder's flag. Injected here rather than
        // declared, on the same terms the movement entries are: a
        // package will not declare a fence it does not want, and a
        // component holding value declares no halt leaf and cannot be
        // made to. Granting `Halt` is what puts the resource in the
        // class whose record cannot be withheld, so the read fails
        // closed.
        if rules.get(GrantedBehaviour::Halt).is_some() {
            let halted = EffectTarget::Point(child_key(
                hasher,
                owner,
                HALT,
                &[Value::Address(resource.address()).canonical_bytes()],
            ));
            declare_read(frame, halted);
            // Once per party and resource however many directions the
            // access moves in: one flag answers every movement of it.
            let fence = Injected {
                rule: Rule::Require(JudgedLeaf::Presence {
                    target: halted,
                    expect: Presence::Absent,
                }),
                asks: Asks::Unhalted,
                resource,
                behaviour: GrantedBehaviour::Halt,
            };
            if !injected.contains(&fence) {
                injected.push(fence);
            }
        }
        let Some(sealed) = rules.get(behaviour) else {
            continue;
        };
        // No subtraction reaches a movement entry: it resolves against
        // the party whose cell moves, and the executing frame's identity
        // says nothing about them. Asked through the same door anyway,
        // so which entries a frame speaks for itself on is one answer.
        let Some(rule) =
            behaviour
                .demanded(sealed, None)
                .map_err(|_| AdmissionError::EntryMalformed {
                    node: node_index,
                    resource,
                    behaviour,
                })?
        else {
            continue;
        };
        // Nobody may: decidable from the entry, without state and without
        // a body, so the graph is refused rather than admitted to fail
        // later.
        if rule == never() {
            return Err(AdmissionError::MovementForbidden {
                node: node_index,
                resource,
                behaviour,
            });
        }
        // The sealed rule is about the mover, and this is where the mover
        // is known: every holding it names resolves to a leaf under the
        // access's own owner, and the read is appended so the leaf is
        // provisioned wherever the call runs.
        let resolved = rule.map_leaves(&mut |leaf| -> Result<_, AdmissionError> {
            match leaf {
                SealedLeaf::Held { badge, holding } => {
                    let target = holding_target(hasher, owner, *badge, *holding);
                    declare_read(frame, target);
                    Ok(JudgedLeaf::Presence {
                        target,
                        expect: Presence::Present,
                    })
                }
                // A movement entry may also ask whether this transaction was
                // approved, which is a question about the call rather than
                // about the mover — so the claim rides the node's evidence
                // like any other.
                SealedLeaf::Claim(claim) => Ok(JudgedLeaf::Claim(*claim)),
            }
        })?;
        // A rule mixing the two asks about the mover and about the call
        // at once, and no stage before the leg holds both — so it is a
        // verdict the declaring node's own walk reaches, which a frame
        // whose caller commits without waiting may not carry.
        if total && !resolved.judged().before_any_leg() {
            return Err(AdmissionError::MovementUnanswerable {
                node: node_index,
                resource,
                behaviour,
            });
        }
        injected.push(Injected {
            rule: resolved,
            asks: Asks::Entry(rule),
            resource,
            behaviour,
        });
    }
    Ok(injected)
}

/// What `owner`'s holding of `badge` occupies, in the shape the sealed
/// leaf asks about.
///
/// A balance is the one point cell keyed by what it holds, and a balance
/// reaching zero deletes its leaf — so presence and a nonzero holding
/// are the same fact, asked once. Instances are entries of the holder's
/// collection for the badge, so holding one is that entry and holding
/// any is the interval holding something: one seek either way, and the
/// interval is what a holder pays for the question spanning the id
/// space.
fn holding_target(
    hasher: &dyn Hasher,
    owner: Address,
    badge: ResourceAddr,
    holding: Holding,
) -> EffectTarget {
    match holding {
        Holding::Balance => EffectTarget::Point(child_key(
            hasher,
            owner,
            VAULT,
            &[Value::Address(badge.address()).canonical_bytes()],
        )),
        // An instance's id is its order key and an id is a `u64`, so the
        // interval that can hold one is the interval declared.
        Holding::AnyInstance => EffectTarget::Range {
            owner,
            collection: holdings_collection(hasher, owner, badge),
            lo: 0,
            hi: u128::from(u64::MAX),
            // One entry answers whether any is there, whatever else the
            // interval holds.
            cap: 1,
        },
        Holding::Instance(id) => EffectTarget::Entry {
            owner,
            collection: holdings_collection(hasher, owner, badge),
            order: u128::from(id),
        },
    }
}

/// Append a read of `target` to the frame, so a condition over it is
/// provisioned wherever this call runs.
fn declare_read(frame: &mut Declaration, target: EffectTarget) {
    let effect = Effect {
        target,
        mode: Mode::Read,
    };
    // A repeated read is the same effect: the declaration already
    // carries it, and the condition beside it asks the same question. The
    // set answers whether it moved, which is the question — a read can
    // only fail to be novel, never to be inserted.
    if frame.set.insert(effect).is_ok_and(|novel| novel) {
        frame.ordered.push(DeclaredAccess {
            effect,
            holds: None,
            reach: None,
        });
    }
}
