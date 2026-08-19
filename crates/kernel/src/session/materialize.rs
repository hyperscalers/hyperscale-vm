//! Materialization: the judging that turns a declared effect set into
//! the capability table a session hands out.
//!
//! Every verdict here is a pre-execution abort — an infeasible
//! reservation, a presence the leaf does not meet, a pairing no
//! capability is built for — judged over committed state before any
//! guest runs.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::Declaration;
use hyperscale_vm_types::{
    Address, CellKind, CollectionId, Effect, EffectSet, EffectTarget, Mode, Presence, SubstateKey,
    TxHash,
};

use super::buckets::Buckets;
use super::ranges::Ranges;
use super::{EnvInputs, KernelSession};
use crate::ledger::AmountLedger;
use crate::locality::Locality;
use crate::overlay::OverlayStore;
use crate::store::{StoreError, WorkingStore};
use crate::supply::SupplyDelta;

/// The ordered-collection interval a range handle names.
///
/// The two range capabilities carry this and differ only in what they
/// permit, which leaves the mode where it belongs — in whether the
/// handle resolves at all, rather than in a second copy of the bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// The collection's owner.
    pub owner: Address,
    /// The collection's identity under the owner.
    pub collection: CollectionId,
    /// Inclusive lower order-key bound.
    pub lo: u128,
    /// Inclusive upper order-key bound.
    pub hi: u128,
    /// The declared entry cap: a scan truncates at it, and it bounds the
    /// distinct entries a write interval may change — separately, since a
    /// read-modify-write reaches its whole page and an insert adds
    /// entries no scan returned.
    pub cap: u32,
}

impl Interval {
    /// Whether `order` falls inside the declared bounds.
    #[must_use]
    pub const fn holds(&self, order: u128) -> bool {
        self.lo <= order && order <= self.hi
    }
}

/// One materialized capability: what a handle rep grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A fresh read of one cell.
    Read(SubstateKey),
    /// A pinned read of one cell.
    Locked(SubstateKey),
    /// An exclusive read-modify-write of one cell holding bytes.
    Write(SubstateKey),
    /// The same exclusive access to a cell holding value.
    ///
    /// A separate variant rather than a flag, because the two share no
    /// operation: bytes are read and replaced, value is credited and
    /// debited, and a handle that offered both would be one the kernel
    /// had to refuse half of at every call.
    Amount(SubstateKey),
    /// A read of one cell holding value.
    ///
    /// Its own variant beside [`Capability::Read`] for the reason
    /// [`Capability::Amount`] is one beside [`Capability::Write`]: what a
    /// value cell answers is a quantity, and it has no byte surface for a
    /// body to read one through.
    AmountRead(SubstateKey),
    /// Commutative movement on one amount cell.
    Delta(SubstateKey),
    /// A held reservation on one amount cell, at this clause's own
    /// declared amount. The store's hold is the per-transaction fold
    /// over every reservation on the cell, so the clause's share rides
    /// the capability — the one place it still exists after the fold.
    Reserve {
        /// The reserved cell.
        key: SubstateKey,
        /// What this clause declared, not the folded hold.
        amount: u128,
    },
    /// A read interval of an ordered collection.
    RangeRead(Interval),
    /// A read-modify-write interval of an ordered collection whose
    /// entries are the package's own bytes.
    RangeWrite(Interval),
    /// The same interval over entries that are instances of one
    /// resource, on the terms [`Capability::Amount`] states.
    InstanceRange(Interval),
}

impl Capability {
    /// The handle type a materialized capability is passed as.
    #[must_use]
    pub const fn kind(&self) -> CellKind {
        match self {
            Self::Read(_) => CellKind::Read,
            Self::Locked(_) => CellKind::Locked,
            Self::Write(_) => CellKind::Write,
            Self::Amount(_) => CellKind::Amount,
            Self::AmountRead(_) => CellKind::AmountRead,
            Self::Delta(_) => CellKind::Delta,
            Self::Reserve { .. } => CellKind::Reserve,
            Self::RangeRead(..) => CellKind::RangeRead,
            Self::RangeWrite(..) => CellKind::RangeWrite,
            Self::InstanceRange(..) => CellKind::InstanceRange,
        }
    }
}

/// Why materialization refused a declared effect set — each an abort
/// before any guest execution.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaterializeError {
    /// A declared mode/target combination the world cannot yet hand out.
    #[error("no capability form for {0:?}")]
    Unsupported(Box<Effect>),
    /// A mutation declared on a permanently locked substate.
    #[error("declared mutation of locked substate {0:?}")]
    MutationOfLocked(SubstateKey),
    /// A locked read declared on a substate that is not locked. The mode
    /// reads without coherence and without making a participant, which is
    /// sound only where no version of the target differs.
    #[error("declared locked read of unlocked substate {0:?}")]
    UnlockedTarget(SubstateKey),
    /// A write requiring the leaf absent, on a target the store holds.
    ///
    /// The same class of verdict as an infeasible reservation, and at
    /// the same seam: a precondition on committed state, judged by the
    /// shard that holds the leaf, before any body observes anything.
    /// Carries the target rather than a key, because the two shapes that
    /// name one leaf are a cell and a collection entry, and only one of
    /// them is a key.
    #[error("a write requiring an absent leaf lands on occupied {0:?}")]
    Occupied(EffectTarget),
    /// A write requiring the leaf there, on a target the store does not
    /// hold.
    #[error("a write requiring a present leaf lands on absent {0:?}")]
    Absent(EffectTarget),
    /// A declared reservation the committed balance cannot cover.
    #[error("reservation of {amount} on {key:?} is infeasible")]
    Infeasible {
        /// The cell reserved against.
        key: SubstateKey,
        /// The declared amount.
        amount: u128,
    },
    /// One transaction declaring an exclusive and a commutative mode on
    /// the same cell — absolute and movement semantics cannot compose
    /// within one receipt.
    #[error("write and delta/reserve declared on the same cell {0:?}")]
    SelfConflicting(SubstateKey),
    /// A commutative movement declared on a cell that denominates
    /// nothing.
    ///
    /// `Delta` and `Reserve` move value and nothing else, so a cell they
    /// name is a cell that holds value — and what it holds is the
    /// declaration's to say, since a key is a hash and nothing inverts
    /// it. A movement through a cell that says nothing would hand out an
    /// edge no destination could disagree with.
    #[error("a movement declared on {0:?}, which denominates nothing")]
    UndenominatedMovement(SubstateKey),
    /// Two clauses reaching one cell and disagreeing about what it holds.
    ///
    /// The denomination chooses which handle a clause materializes, so a
    /// leaf one clause denominates and another does not would be handed
    /// out twice — as the cell value moves through and as the cell bytes
    /// are written to. A balance written through the second and debited
    /// through the first is value from nowhere, so the pair is refused
    /// before either handle exists.
    ///
    /// Refused at publish too, against the target expressions; this is
    /// the verdict two expressions that evaluate onto one cell reach.
    #[error("clauses disagree about what {0:?} holds")]
    MixedContents(EffectTarget),
    /// An already-held reservation whose amount differs from the declared
    /// one — a batch bookkeeping defect, surfaced rather than adopted.
    #[error("held reservation on {0:?} does not match the declaration")]
    HeldMismatch(SubstateKey),
    /// A store failure while judging reservations.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl KernelSession {
    /// Materialize capabilities for a declared effect set over the
    /// overlay's state, judging and holding the declared reservations — or
    /// adopting reservations a batch judge already holds for this
    /// transaction.
    ///
    /// The overlay's base is what locked reads resolve against, fixed
    /// for the whole batch
    /// regardless of what the group threads on top.
    ///
    /// The capability table's order is the effect set's canonical order,
    /// so reps are deterministic; the caller passes handles to the guest
    /// in table order.
    ///
    /// The whole [`Declaration`] rather than the three views of it a
    /// table is built from. They are one evaluation and they are read
    /// index for index — the folded set, the clause order a rep is an
    /// index into, and what each of those cells holds — so a caller able
    /// to hand over three that disagreed would be able to hand over a
    /// clause list whose denominations belonged to a different one.
    ///
    /// # Errors
    ///
    /// Any [`MaterializeError`]; all are pre-execution aborts.
    pub fn materialize(
        mut store: OverlayStore,
        declaration: &Declaration,
        tx: TxHash,
        env: EnvInputs,
        hash_fn: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, MaterializeError> {
        let Declaration {
            set: declared,
            ordered,
            ..
        } = declaration;
        store.clear_log();

        // Reservations are judged off the *set*, where `EffectSet::insert`
        // has already summed the amounts two clauses claimed on one cell.
        // Judging the clause list instead would judge each amount
        // separately against the same balance, so a signature reserving
        // `n` twice over a cell holding `n` would pass both. A reservation
        // on a locked cell is refused where its clause's capability is
        // built, like every other mutation of one.
        let mut reservations = Vec::new();
        for effect in declared.iter() {
            if let (EffectTarget::Point(key), Mode::Reserve { amount }) =
                (effect.target, effect.mode)
            {
                match store.held_reservation(key, tx) {
                    Some(held) if held == amount => {}
                    Some(_) => return Err(MaterializeError::HeldMismatch(key)),
                    None => reservations.push((tx, key, amount)),
                }
            }
        }

        // The table is the *clause list*, because a handle's rep is its
        // index here and the guest's parameters are positional. Walking
        // the set instead would order handles by a comparison over
        // hash-derived keys, and would silently shorten the table
        // whenever two clauses evaluated to one target — making a guest's
        // parameter list a function of instance configuration rather than
        // of its own signature.
        //
        // What each cell holds is folded as the table is built, because
        // the two clauses that disagree can be any two: a leaf one
        // denominates and another does not is a leaf handed out as a
        // vault and as a byte cell at once, and a balance written
        // through the byte handle is a balance nothing moved. Keyed by
        // what the target names rather than by the target, so two
        // intervals of one collection are one answer about its entries.
        let mut table = Vec::with_capacity(ordered.len());
        let mut holds: BTreeMap<Holds, bool> = BTreeMap::new();
        for access in ordered {
            let denominated = access.holds.is_some();
            if holds
                .insert(holds_of(access.effect.target), denominated)
                .is_some_and(|held| held != denominated)
            {
                return Err(MaterializeError::MixedContents(access.effect.target));
            }
            table.push(capability_for(&store, access.effect, denominated)?);
        }
        // One transaction may not declare both an exclusive write and a
        // commutative mode on the same cell: the receipt records
        // absolutes for the one and movements for the other, and they
        // cannot compose.
        if let Some(key) = declared.self_conflicting() {
            return Err(MaterializeError::SelfConflicting(key));
        }

        judge_presence(&mut store, declared)?;

        let verdicts = store.judge_and_hold(&reservations)?;
        for ((verdict_tx, key), feasibility) in verdicts {
            if !feasibility.is_feasible() {
                let amount = reservations
                    .iter()
                    .find(|(request_tx, request_key, _)| {
                        *request_tx == verdict_tx && *request_key == key
                    })
                    .map_or(0, |(_, _, amount)| *amount);
                return Err(MaterializeError::Infeasible { key, amount });
            }
        }

        Ok(Self {
            store,
            declared: declared.clone(),
            table,
            tx,
            env,
            hash_fn,
            locality: Locality::All,
            ranges: Ranges::default(),
            invocation: None,
            events: Vec::new(),
            supply: SupplyDelta::default(),
            cell_resources: ordered
                .iter()
                .map(|access| access.holds.map(Address::from))
                .collect(),
            buckets: Buckets::default(),
            issuance: None,
            taken: BTreeSet::new(),
        })
    }
}

/// Judge what every declared write requires of the leaf it lands on.
///
/// Over the committed store and before the body runs, where a
/// reservation's feasibility is already judged — so a create that cannot
/// create aborts rather than trapping inside a guest.
///
/// # Errors
///
/// [`MaterializeError::Occupied`] or [`MaterializeError::Absent`] for a
/// requirement the leaf does not meet, and
/// [`MaterializeError::Unsupported`] for a target that names no leaf for
/// a requirement to be about.
fn judge_presence(store: &mut OverlayStore, declared: &EffectSet) -> Result<(), MaterializeError> {
    // Exhaustive over the target shapes, never skipping one it does not
    // read: a requirement this cannot honour is refused, because a
    // declaration that states a precondition nothing enforces is worse
    // than one that never published.
    for effect in declared.iter() {
        let Mode::Write { requires } = effect.mode else {
            continue;
        };
        if requires == Presence::Either {
            continue;
        }
        let held = match effect.target {
            // The two shapes that name one leaf. An entry's presence
            // is the same question a custody gate's possession read
            // asks, over the same width-one interval.
            EffectTarget::Point(key) => store.read(key)?.is_some(),
            EffectTarget::Entry {
                owner,
                collection,
                order,
            } => !store
                .entries_in_range(owner, collection, order, order, 1)?
                .is_empty(),
            // An interval names no leaf for a requirement to be
            // about — it stays valid whatever enters or leaves it,
            // which is the property that makes it declarable at all.
            // Refused at publish, and again here, because metadata
            // can be authored rather than derived.
            EffectTarget::Range { .. } => {
                return Err(MaterializeError::Unsupported(Box::new(effect)));
            }
        };
        match (requires, held) {
            (Presence::Absent, true) => return Err(MaterializeError::Occupied(effect.target)),
            (Presence::Present, false) => return Err(MaterializeError::Absent(effect.target)),
            _ => {}
        }
    }

    Ok(())
}

/// What a target names as the thing whose contents are one fact: the
/// leaf a point names, or the collection an entry or an interval sits in.
///
/// Not the target itself, because two intervals of one collection are two
/// targets over one set of entries — so an interval saying its entries
/// are instances and an overlapping one saying they are bytes are two
/// answers about the same entries.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Holds {
    /// One leaf.
    Leaf(SubstateKey),
    /// Every entry of one collection.
    Entries(Address, CollectionId),
}

/// Which cell's contents an effect is an answer about.
pub(super) const fn holds_of(target: EffectTarget) -> Holds {
    match target {
        EffectTarget::Point(key) => Holds::Leaf(key),
        EffectTarget::Entry {
            owner, collection, ..
        }
        | EffectTarget::Range {
            owner, collection, ..
        } => Holds::Entries(owner, collection),
    }
}

/// The interval a collection target names; `None` for a point key.
///
/// An entry is the width-one interval at its order — the same
/// normalization the oracle's coverage walk applies — so a declared entry
/// and a declared range reach the store through one shape.
const fn interval_of(target: EffectTarget) -> Option<Interval> {
    match target {
        EffectTarget::Point(_) => None,
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => Some(Interval {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => Some(Interval {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
    }
}

/// The capability form of one declared effect: the world-design mapping.
/// Entry targets are degenerate one-entry intervals, so collection access
/// needs exactly two resource shapes.
fn capability_for(
    store: &OverlayStore,
    effect: Effect,
    denominated: bool,
) -> Result<Capability, MaterializeError> {
    let locked_checked = |key: SubstateKey| {
        if store.is_locked(key) {
            Err(MaterializeError::MutationOfLocked(key))
        } else {
            Ok(key)
        }
    };
    match (effect.target, effect.mode) {
        (EffectTarget::Point(key), Mode::Read) => Ok(if denominated {
            Capability::AmountRead(key)
        } else {
            Capability::Read(key)
        }),
        // The mirror of `locked_checked`, and the reason a locked read needs
        // no proof: an unlocked target could differ between the shard that
        // owns it and one that only reads it, and a locked read makes no
        // participant, so nothing would carry the owner's value to anyone
        // else. Two participants would read one key and derive two
        // receipts. A read of mutable state is `Mode::Read`, which
        // provisions.
        (EffectTarget::Point(key), Mode::Locked) => {
            if store.is_locked(key) {
                Ok(Capability::Locked(key))
            } else {
                Err(MaterializeError::UnlockedTarget(key))
            }
        }
        // What a cell holds chooses the handle. The two share no
        // operation, so a body reaching for the wrong one is holding a
        // type that does not have it rather than meeting a refusal.
        (EffectTarget::Point(key), Mode::Write { .. }) => {
            let key = locked_checked(key)?;
            Ok(if denominated {
                Capability::Amount(key)
            } else {
                Capability::Write(key)
            })
        }
        // The two modes that move value and do nothing else. A cell
        // they name holds value, so the declaration has to say what —
        // judged here rather than at the movement, because a declaration
        // that cannot be materialized is one no body should run against.
        (EffectTarget::Point(key), Mode::Delta) => {
            if denominated {
                Ok(Capability::Delta(locked_checked(key)?))
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        (EffectTarget::Point(key), Mode::Reserve { amount }) => {
            if denominated {
                Ok(Capability::Reserve {
                    key: locked_checked(key)?,
                    amount,
                })
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        // Point targets are spoken for above, so what is left is a
        // collection one — and the two spell the same interval, the mode
        // choosing only which capability carries it.
        (target, mode @ (Mode::Read | Mode::Write { .. })) => interval_of(target)
            .map(|interval| match (mode, denominated) {
                (Mode::Write { .. }, true) => Capability::InstanceRange(interval),
                (Mode::Write { .. }, false) => Capability::RangeWrite(interval),
                _ => Capability::RangeRead(interval),
            })
            .ok_or_else(|| MaterializeError::Unsupported(Box::new(effect))),
        _ => Err(MaterializeError::Unsupported(Box::new(effect))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::{Declaration, DeclaredAccess};
    use hyperscale_vm_types::{
        Address, AddressClass, CollectionId, Denomination, Effect, EffectConflict, EffectSet,
        EffectTarget, Mode, Presence, encode_amount,
    };

    use super::super::fixtures::{RESOURCE, declared, env, hash, held, holding, key, ord, tx};
    use super::{Capability, KernelSession, MaterializeError, capability_for};
    use crate::ledger::AmountLedger;
    use crate::overlay::OverlayStore;
    use crate::store::MemoryStore;

    /// Materialize one write over a store, for the presence tests.
    fn presence_verdict(
        store: MemoryStore,
        target: EffectTarget,
        requires: Presence,
    ) -> Result<(), MaterializeError> {
        let set = declared(&[Effect {
            target,
            mode: Mode::Write { requires },
        }]);
        let ordered = ord(&set);
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: holding(&ordered),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .map(|_| ())
    }

    /// A write says what it requires of the leaf, and the shard holding
    /// the leaf judges it before the body runs — the same seam, and the
    /// same class of verdict, as an infeasible reservation.
    ///
    /// Both shapes that name one leaf answer, because the requirement is
    /// about the leaf rather than about how the target spells it: a cell
    /// and a collection entry are each exactly one.
    #[test]
    fn a_write_requiring_a_presence_the_leaf_does_not_have_refuses() {
        let cell = EffectTarget::Point(key(0xC1));
        let owner = Address::new([0xC1; 31], AddressClass::Component);
        let collection = CollectionId([9; 16]);
        let entry = EffectTarget::Entry {
            owner,
            collection,
            order: 7,
        };
        let empty = |_: EffectTarget| MemoryStore::new();
        let occupied = |target: EffectTarget| {
            let mut store = MemoryStore::new();
            match target {
                EffectTarget::Point(key) => {
                    store.write(key, vec![7]).expect("seed");
                }
                EffectTarget::Entry {
                    owner,
                    collection,
                    order,
                } => {
                    store
                        .entry_write(owner, collection, order, vec![7])
                        .expect("seed");
                }
                EffectTarget::Range { .. } => unreachable!("not a leaf"),
            }
            store
        };

        for target in [cell, entry] {
            // A create lands only where nothing is.
            assert_eq!(
                presence_verdict(empty(target), target, Presence::Absent),
                Ok(()),
                "{target:?}"
            );
            assert_eq!(
                presence_verdict(occupied(target), target, Presence::Absent),
                Err(MaterializeError::Occupied(target)),
                "{target:?}"
            );

            // And its dual.
            assert_eq!(
                presence_verdict(occupied(target), target, Presence::Present),
                Ok(()),
                "{target:?}"
            );
            assert_eq!(
                presence_verdict(empty(target), target, Presence::Present),
                Err(MaterializeError::Absent(target)),
                "{target:?}"
            );

            // An ordinary write is indifferent, which is what every
            // declaration that says nothing means.
            for store in [empty(target), occupied(target)] {
                assert_eq!(
                    presence_verdict(store, target, Presence::Either),
                    Ok(()),
                    "{target:?}"
                );
            }
        }
    }

    /// An interval names no leaf, so a requirement about one is refused
    /// rather than read past — the publish gate says the same, and this
    /// is what holds for metadata that was authored rather than derived.
    #[test]
    fn a_presence_requirement_on_an_interval_refuses() {
        let range = EffectTarget::Range {
            owner: Address::new([0xC3; 31], AddressClass::Component),
            collection: CollectionId([9; 16]),
            lo: 0,
            hi: u128::MAX,
            cap: 4,
        };
        for requires in [Presence::Absent, Presence::Present] {
            assert_eq!(
                presence_verdict(MemoryStore::new(), range, requires),
                Err(MaterializeError::Unsupported(Box::new(Effect {
                    target: range,
                    mode: Mode::Write { requires },
                }))),
                "{requires:?}"
            );
        }
        // The indifferent one is every range write there has ever been.
        assert_eq!(
            presence_verdict(MemoryStore::new(), range, Presence::Either),
            Ok(())
        );
    }

    /// Two clauses on one cell are one access, and what it requires is
    /// what both require — unless they require opposite things, which is
    /// a declaration nothing could satisfy.
    #[test]
    fn presence_requirements_on_one_cell_meet_or_refuse() {
        let key = key(0xC2);
        let write = |requires| Effect {
            target: EffectTarget::Point(key),
            mode: Mode::Write { requires },
        };
        let fold = |a, b| {
            let mut set = EffectSet::new();
            set.insert(write(a))?;
            set.insert(write(b))?;
            Ok::<_, EffectConflict>(set.iter().collect::<Vec<_>>())
        };

        // A named requirement wins over the indifferent one, in either
        // order, and the set holds one access rather than two.
        for named in [Presence::Absent, Presence::Present] {
            for pair in [(Presence::Either, named), (named, Presence::Either)] {
                assert_eq!(fold(pair.0, pair.1), Ok(vec![write(named)]));
            }
            assert_eq!(fold(named, named), Ok(vec![write(named)]));
        }

        // Opposite requirements are refused where the second is written.
        assert_eq!(
            fold(Presence::Absent, Presence::Present),
            Err(EffectConflict::Presence)
        );
        assert_eq!(
            fold(Presence::Present, Presence::Absent),
            Err(EffectConflict::Presence)
        );
    }

    #[test]
    fn the_table_follows_the_clause_order_not_the_set_order() {
        // A handle's rep is its index here and a guest's parameters are
        // positional, so the table must be the order the author wrote —
        // never the set's, which is a comparison over hash-derived keys.
        let (first, second) = (key(0xA1), key(0xA2));
        let write = |k| Effect {
            target: EffectTarget::Point(k),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let set = declared(&[write(first), write(second)]);

        // Whichever way canonical order happens to fall, the reverse of it
        // is a clause order the table has to reproduce exactly.
        let mut reversed: Vec<Effect> = set.iter().collect();
        reversed.reverse();
        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &Declaration {
                set,
                ordered: holding(&reversed),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .expect("two ordinary writes materialize");

        let expected: Vec<Capability> = reversed
            .iter()
            .map(|effect| match effect.target {
                EffectTarget::Point(k) => Capability::Write(k),
                other => panic!("unexpected target {other:?}"),
            })
            .collect();
        assert_eq!(session.capabilities(), expected);
    }

    #[test]
    fn coincident_clauses_each_get_a_handle() {
        // Two clauses that evaluate to one target fold to a single set
        // entry — a degenerate instance configuration does exactly this.
        // The guest's parameter list is a function of its signature, not
        // of that configuration, so the table keeps both slots.
        let cell = key(0xB4);
        let write = Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let set = declared(&[write, write]);
        assert_eq!(set.len(), 1, "the set folds them");

        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &Declaration {
                set,
                ordered: holding(&[write, write]),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .expect("a repeated write is not a self-conflict");
        assert_eq!(
            session.capabilities(),
            [Capability::Write(cell), Capability::Write(cell)],
            "one handle per clause"
        );
    }

    #[test]
    fn repeated_reservations_are_judged_against_their_sum() {
        // The reason materialization keeps both views. Judging the clause
        // list would weigh each amount against the same balance
        // separately, so a signature reserving 60 twice over a cell
        // holding 100 would pass both and hold 120.
        let vault = key(0xC7);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();

        let reserve = Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 60 },
        };
        let set = declared(&[reserve, reserve]);

        let refused = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: holding(&[reserve, reserve]),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .expect_err("120 reserved against 100 is infeasible");
        assert_eq!(
            refused,
            MaterializeError::Infeasible {
                key: vault,
                amount: 120,
            },
            "the folded amount is judged, not each clause's"
        );
    }

    #[test]
    fn repeated_reservations_grant_each_clause_its_own_amount() {
        // The folded hold covers the sum, but each clause's grant is its
        // own declared share — a guest moving exactly what its clause
        // asked for checks against that share, not the fold. Handing
        // every clause the folded total would trap the second withdraw
        // of any fan-out.
        let vault = key(0xC8);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();

        let reserve = |amount| Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount },
        };
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set: declared(&[reserve(5), reserve(6)]),
                ordered: holding(&[reserve(5), reserve(6)]),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .expect("11 reserved against 100 is feasible");

        assert_eq!(session.reserve_amount(0), Ok(5));
        assert_eq!(session.reserve_amount(1), Ok(6));
    }

    /// Publish refuses exactly the pairings materialization cannot build.
    ///
    /// The two answers are written apart and read different things — one
    /// the target expressions a signature carries, one the evaluated
    /// effect — so a pairing the first admitted and the second could not
    /// build would be a package published and unusable, aborting every
    /// call at a clause its author was told nothing about. Held here over
    /// every shape and mode the vocabulary has, because the boundary is
    /// one boundary however many places read it.
    #[test]
    fn the_pairings_publish_refuses_are_the_ones_no_capability_is_built_for() {
        use hyperscale_vm_effects::{
            Clause, Expr, ModeExpr, TargetExpr, Value, materialized_kind, package_slot,
        };

        let store = OverlayStore::new(Arc::new(MemoryStore::new()));
        let owner = Address::new([3; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let resource = || Expr::Literal(Value::Address(RESOURCE));
        let targets = [
            (
                TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: package_slot(0),
                    material: vec![resource()],
                }),
                EffectTarget::Point(key(1)),
            ),
            (
                TargetExpr::Entry {
                    owner: Expr::SelfAddr,
                    collection: package_slot(1),
                    material: vec![resource()],
                    order: Expr::Literal(Value::U128(1)),
                },
                EffectTarget::Entry {
                    owner,
                    collection,
                    order: 1,
                },
            ),
            (
                TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: package_slot(2),
                    material: vec![resource()],
                    lo: Expr::Literal(Value::U128(0)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: 4,
                },
                EffectTarget::Range {
                    owner,
                    collection,
                    lo: 0,
                    hi: u128::MAX,
                    cap: 4,
                },
            ),
        ];
        let modes = [
            (ModeExpr::Read, Mode::Read),
            (ModeExpr::Locked, Mode::Locked),
            (
                ModeExpr::Write {
                    requires: Presence::Either,
                },
                Mode::Write {
                    requires: Presence::Either,
                },
            ),
            (ModeExpr::Delta, Mode::Delta),
            (ModeExpr::Reserve(Expr::Arg(0)), Mode::Reserve { amount: 1 }),
        ];

        // Denominated throughout, so a movement refused for saying
        // nothing cannot stand in for one refused for its shape.
        for (declared, target) in &targets {
            for (spelled, mode) in &modes {
                let clause = Clause::Effect {
                    guard: None,
                    target: declared.clone(),
                    mode: spelled.clone(),
                    denomination: Some(Box::new(resource())),
                };
                let built = capability_for(
                    &store,
                    Effect {
                        target: *target,
                        mode: *mode,
                    },
                    true,
                );
                assert_eq!(
                    materialized_kind(&clause).is_none(),
                    matches!(built, Err(MaterializeError::Unsupported(_))),
                    "{declared:?} {spelled:?} materialised {built:?}"
                );
            }
        }
    }

    /// A declaration whose two ordered views disagree is not one.
    ///
    /// Routing fills both in step, so this is a caller that assembled a
    /// declaration rather than evaluating one. Surfaced rather than
    /// absorbed: reading the shorter of the two would either shorten the
    /// capability table — moving every rep after the gap, and handing the
    /// guest a handle on the wrong cell — or read a cell that says
    /// nothing as one holding no value. Both are quiet.
    /// One cell holds one thing, judged where two expressions that
    /// evaluate onto it can no longer hide behind being different
    /// expressions.
    ///
    /// The publish gate compares target expressions, so a signature that
    /// spells one cell two ways passes it. What lands here is the
    /// evaluated key — and if a body held both handles over it, a balance
    /// written through the byte one and debited through the value one
    /// would be value from nowhere.
    #[test]
    fn one_cell_does_not_materialise_as_a_vault_and_a_byte_cell() {
        let write = Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let materialise = |holds: Vec<Option<Denomination>>| {
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set: declared(&[write]),
                    ordered: vec![
                        DeclaredAccess {
                            effect: write,
                            holds: holds[0],
                        },
                        DeclaredAccess {
                            effect: write,
                            holds: holds[1],
                        },
                    ],
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            )
            .map(|_| ())
        };

        // Two clauses on one leaf, one saying it holds value and one
        // saying nothing: the pair no handle is built for.
        assert_eq!(
            materialise(vec![Some(held()), None]),
            Err(MaterializeError::MixedContents(write.target))
        );
        assert_eq!(
            materialise(vec![None, Some(held())]),
            Err(MaterializeError::MixedContents(write.target))
        );
        // Agreeing clauses are what a body that reads and writes one cell
        // declares, and both directions stand.
        assert!(materialise(vec![Some(held()), Some(held())]).is_ok());
        assert!(materialise(vec![None, None]).is_ok());

        // A collection is the same statement over its entries: two
        // intervals of one collection are two targets, so the
        // disagreement is about the entries rather than about the slices
        // naming them.
        let interval = |hi| Effect {
            target: EffectTarget::Range {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi,
                cap: 4,
            },
            mode: Mode::Write {
                requires: Presence::Either,
            },
        };
        let wide = interval(u128::MAX);
        let narrow = interval(10);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set: declared(&[wide, narrow]),
                    ordered: vec![
                        DeclaredAccess {
                            effect: wide,
                            holds: Some(held()),
                        },
                        DeclaredAccess {
                            effect: narrow,
                            holds: None,
                        },
                    ],
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            )
            .map(|_| ())
            .expect_err("one collection, two answers about its entries"),
            MaterializeError::MixedContents(narrow.target)
        );
    }

    #[test]
    fn one_transaction_cannot_hold_both_absolute_and_commutative_modes() {
        let cell = key(3);
        let set = declared(&[
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Write {
                    requires: Presence::Either,
                },
            },
            Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Delta,
            },
        ]);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set: set.clone(),
                    ordered: holding(&ord(&set)),
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            )
            .expect_err("absolute and movement semantics cannot compose"),
            MaterializeError::SelfConflicting(cell)
        );
    }

    #[test]
    fn a_mismatched_held_reservation_is_surfaced_not_adopted() {
        let vault = key(4);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec()).unwrap();
        // A batch judge already holds a different amount for this
        // transaction than the declaration asks for.
        store.judge_and_hold(&[(tx(1), vault, 40)]).unwrap();
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 50 },
        }]);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(store)),
                &Declaration {
                    set: set.clone(),
                    ordered: holding(&ord(&set)),
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            )
            .expect_err("a bookkeeping mismatch is a defect, not an adoption"),
            MaterializeError::HeldMismatch(vault)
        );
    }

    /// A movement mutates the cell it lands on, so a locked cell admits
    /// none — the same refusal every write meets, judged where the
    /// clause's capability is built.
    #[test]
    fn a_movement_on_a_locked_cell_is_refused() {
        let vault = key(0xCA);
        for mode in [Mode::Reserve { amount: 10 }, Mode::Delta] {
            let mut store = MemoryStore::new();
            store.write(vault, encode_amount(100).to_vec()).unwrap();
            store.lock(vault);
            let set = declared(&[Effect {
                target: EffectTarget::Point(vault),
                mode,
            }]);
            assert_eq!(
                KernelSession::materialize(
                    OverlayStore::new(Arc::new(store)),
                    &Declaration {
                        set: set.clone(),
                        ordered: holding(&ord(&set)),
                        ..Declaration::default()
                    },
                    tx(1),
                    env(),
                    hash,
                )
                .map(|_| ())
                .expect_err("a movement mutates, and a locked cell admits none"),
                MaterializeError::MutationOfLocked(vault),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_mode_the_world_cannot_hand_out_refuses_at_materialization() {
        // A locked read of a collection interval has no capability form.
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 1,
                cap: 1,
            },
            mode: Mode::Locked,
        }]);
        assert!(matches!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set: set.clone(),
                    ordered: holding(&ord(&set)),
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            ),
            Err(MaterializeError::Unsupported(_))
        ));
    }
}
