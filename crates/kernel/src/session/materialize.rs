//! Materialization: the judging that turns a declared effect set into
//! the capability table a session hands out.
//!
//! Every verdict here is a pre-execution abort — an infeasible
//! reservation, a presence the leaf does not meet, a pairing no
//! capability is built for — judged over committed state before any
//! guest runs.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{Condition, Declaration, JudgedLeaf, Rule};
use hyperscale_vm_types::{
    Address, CollectionId, Effect, EffectTarget, Mode, Moves, Presence, ResourceAddr, SubstateKey,
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
    ///
    /// Zero is admissible and means it: a caller handing an empty
    /// collection to a method whose cap counts it declares an interval
    /// that excludes its span and reads none of it. The span is what the
    /// footprint charges for the exclusion, so the declaration is priced
    /// either way — but a coverage probe and a presence seek each want
    /// one entry of headroom, so at zero both answer closed rather than
    /// reaching for an entry nothing bought.
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
    /// An exclusive read-modify-write of one cell holding bytes.
    Write(SubstateKey),
    /// The same exclusive access to a cell holding value.
    ///
    /// A separate variant rather than a flag, because the two share no
    /// operation: bytes are read and replaced, value is credited and
    /// debited, and a handle that offered both would be one the kernel
    /// had to refuse half of at every call.
    Amount {
        /// The cell held.
        key: SubstateKey,
        /// Which directions value may move under it.
        ///
        /// The commutative modes say their direction by being
        /// themselves, so a cell reached through one of those needs no
        /// field. This is the mode that had no way to say it, and what
        /// it says here is what admission judged the access on: an
        /// access that gave up a direction earns only the movement
        /// entry it kept, so keeping the direction out of the
        /// capability would leave the other movement enforced by
        /// nothing.
        moves: Moves,
    },
    /// A read of one cell holding value.
    ///
    /// Its own variant beside [`Capability::Read`] for the reason
    /// [`Capability::Amount`] is one beside [`Capability::Write`]: what a
    /// value cell answers is a quantity, and it has no byte surface for a
    /// body to read one through.
    AmountRead(SubstateKey),
    /// Commutative movement on one amount cell.
    Delta(SubstateKey),
    /// The crediting half of one, and nothing else.
    ///
    /// Its own variant rather than a flag on [`Capability::Delta`],
    /// because what separates them is which operations they answer: a
    /// take through this is refused the way a byte read of a value cell
    /// is, and by the same dispatch.
    Credit(SubstateKey),
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
    ///
    /// The one movement capability a collection has, and it carries its
    /// direction for the reason the exclusive point hold does: the
    /// declaration says which way value moves under it, and a
    /// capability that dropped the answer would leave the direction
    /// declared and unenforced.
    Instances {
        /// The interval it acts over.
        interval: Interval,
        /// Which directions value may move under it.
        moves: Moves,
    },
}

/// When a movement through a capability is judged.
///
/// The whole of what separates the two value modes once permission has
/// been decided: the exclusive hold reads, arithmetises and writes back,
/// so a movement past what the cell holds is refused at the call; the
/// commutative movement queues and leaves the question to the fold,
/// where it is one floor among every other transaction's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// Performed now, against the cell's current contents.
    Immediate(SubstateKey),
    /// Queued for the movement fold.
    Queued(SubstateKey),
}

impl Capability {
    /// The cell this capability holds, where it holds one.
    ///
    /// `None` for the interval forms, which name a span of a collection
    /// rather than a leaf — the one distinction a point operation and an
    /// interval operation still have to make after permission.
    #[must_use]
    pub const fn key(&self) -> Option<SubstateKey> {
        match *self {
            Self::Read(key)
            | Self::Write(key)
            | Self::Amount { key, .. }
            | Self::AmountRead(key)
            | Self::Delta(key)
            | Self::Credit(key)
            | Self::Reserve { key, .. } => Some(key),
            Self::RangeRead(_) | Self::RangeWrite(_) | Self::Instances { .. } => None,
        }
    }

    /// The interval this capability holds, where it holds one.
    #[must_use]
    pub const fn interval(&self) -> Option<Interval> {
        match *self {
            Self::RangeRead(interval)
            | Self::RangeWrite(interval)
            | Self::Instances { interval, .. } => Some(interval),
            Self::Read(_)
            | Self::Write(_)
            | Self::Amount { .. }
            | Self::AmountRead(_)
            | Self::Delta(_)
            | Self::Credit(_)
            | Self::Reserve { .. } => None,
        }
    }

    /// When a movement through this capability is judged, and against
    /// which cell.
    #[must_use]
    pub const fn settlement(&self) -> Option<Settlement> {
        match *self {
            Self::Amount { key, .. } => Some(Settlement::Immediate(key)),
            Self::Delta(key) | Self::Credit(key) => Some(Settlement::Queued(key)),
            Self::Read(_)
            | Self::Write(_)
            | Self::AmountRead(_)
            | Self::Reserve { .. }
            | Self::RangeRead(_)
            | Self::RangeWrite(_)
            | Self::Instances { .. } => None,
        }
    }

    /// Every form, over one cell and one interval — the rows the
    /// permission matrix asks its questions of.
    ///
    /// Beside the enum rather than in the test that consumes it, so that
    /// what the matrix covers is written where a form is added.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn forms(key: SubstateKey, amount: u128, interval: Interval) -> [Self; 14] {
        [
            Self::Read(key),
            Self::Write(key),
            // Every direction, for the reason the interval forms below
            // are enumerated one by one: what giving up a direction
            // buys is exactly what the matrix is there to state.
            Self::Amount {
                key,
                moves: Moves::In,
            },
            Self::Amount {
                key,
                moves: Moves::Out,
            },
            Self::Amount {
                key,
                moves: Moves::Both,
            },
            Self::AmountRead(key),
            Self::Delta(key),
            Self::Credit(key),
            Self::Reserve { key, amount },
            Self::RangeRead(interval),
            Self::RangeWrite(interval),
            Self::Instances {
                interval,
                moves: Moves::In,
            },
            Self::Instances {
                interval,
                moves: Moves::Out,
            },
            Self::Instances {
                interval,
                moves: Moves::Both,
            },
        ]
    }

    /// Where this form sits in [`Capability::forms`].
    ///
    /// Total over the enum, which is what makes that array total: a form
    /// added without a place here does not compile, and one added
    /// without widening the array does not fit its length.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn form(&self) -> usize {
        match self {
            Self::Read(_) => 0,
            Self::Write(_) => 1,
            Self::Amount {
                moves: Moves::In, ..
            } => 2,
            Self::Amount {
                moves: Moves::Out, ..
            } => 3,
            Self::Amount {
                moves: Moves::Both, ..
            } => 4,
            Self::AmountRead(_) => 5,
            Self::Delta(_) => 6,
            Self::Credit(_) => 7,
            Self::Reserve { .. } => 8,
            Self::RangeRead(_) => 9,
            Self::RangeWrite(_) => 10,
            Self::Instances {
                moves: Moves::In, ..
            } => 11,
            Self::Instances {
                moves: Moves::Out, ..
            } => 12,
            Self::Instances {
                moves: Moves::Both, ..
            } => 13,
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
    /// A declared presence condition the committed leaf does not meet.
    ///
    /// The same class of verdict as an infeasible reservation, and at
    /// the same seam: a precondition on committed state, judged by the
    /// shard that holds the leaf, before any body observes anything.
    /// Carries the target rather than a key, because the two shapes that
    /// name one leaf are a cell and a collection entry, and only one of
    /// them is a key.
    #[error("a condition requiring the leaf {required:?} is unmet at {target:?}")]
    ConditionUnmet {
        /// The leaf the condition names.
        target: EffectTarget,
        /// What it required. Never `Either`, which is refused at publish.
        required: Presence,
        /// The manifest node whose frame asked, where the declaration
        /// says. Absent for a declaration assembled without one, which
        /// is every declaration a test builds by hand.
        node: Option<u32>,
    },
    /// A declared condition committed state cannot answer.
    ///
    /// Distinct from [`Self::ConditionUnmet`], which names the leaf that
    /// refused it. This one has no leaf to name: what reached the judge
    /// is a rule nothing about state could satisfy, so what a receipt
    /// carries is the frame that asked and nothing more.
    #[error("a condition on node {node:?} is not one committed state can answer")]
    ConditionUnanswerable {
        /// The manifest node whose frame asked, where the declaration
        /// says.
        node: Option<u32>,
    },
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
    /// Two clauses naming two resources is the same disagreement in the
    /// other direction, and the one nothing downstream can catch. A
    /// movement takes its denomination from the clause that authorised
    /// it, so a body holding both handles debits one resource and has
    /// the debit written down as the other — which conserves, one
    /// resource going out as another comes in, while a cell of the first
    /// empties and value of the second exists that no mint made.
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
        // `n` twice over a cell holding `n` would pass both.
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
        // through the byte handle is a balance nothing moved. Two
        // clauses naming two resources is the same statement about the
        // same leaf, and the one the receipt cannot survive: a movement
        // is denominated off the clause that reached the cell, so a body
        // holding both handles could debit one resource and have the
        // debit recorded in the other. Keyed by what the target names
        // rather than by the target, so two intervals of one collection
        // are one answer about its entries.
        let mut table = Vec::with_capacity(ordered.len());
        let mut contents: BTreeMap<Contents, Option<ResourceAddr>> = BTreeMap::new();
        for access in ordered {
            if contents
                .insert(contents_of(access.effect.target), access.holds)
                .is_some_and(|held| held != access.holds)
            {
                return Err(MaterializeError::MixedContents(access.effect.target));
            }
            table.push(capability_for(access.effect, access.holds.is_some())?);
        }
        // One transaction may not declare both an exclusive write and a
        // commutative mode on the same cell: the receipt records
        // absolutes for the one and movements for the other, and they
        // cannot compose.
        if let Some(key) = declared.self_conflicting() {
            return Err(MaterializeError::SelfConflicting(key));
        }

        judge_conditions(&mut store, &declaration.conditions)?;

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

        let table_len = table.len();
        Ok(Self {
            store,
            declared: declared.clone(),
            table,
            tx,
            env,
            hash_fn,
            locality: Locality::All,
            nullifiers: Vec::new(),
            ranges: Ranges::default(),
            invocation: None,
            events: Vec::new(),
            supply: SupplyDelta::default(),
            cell_resources: ordered.iter().map(|access| access.holds).collect(),
            buckets: Buckets::default(),
            issuance: Vec::new(),
            // One width-one site per capability, in table order, so a
            // capability's rep is also the rep of the site that reaches
            // it. A session is actable the moment it exists; what a walk
            // binds past these is the sites a `for-each` needs.
            entries: (0..u32::try_from(table_len).unwrap_or(u32::MAX))
                .map(Some)
                .collect(),
            sites: (0..u32::try_from(table_len).unwrap_or(u32::MAX))
                .map(|index| (index, 1))
                .collect(),
            taken: BTreeSet::new(),
        })
    }
}

/// Judge the declared presence conditions against the committed store,
/// before any body runs — the same instant a reservation's feasibility
/// is judged, so a create that cannot create aborts rather than trapping
/// inside a guest.
///
/// Every participant judges every condition rather than only the shard
/// owning the leaf. A condition's target is also a declared read, which
/// is what provisions the state wherever the transaction runs, so each
/// participant reaches the verdict the owner reaches.
///
/// # Errors
///
/// [`MaterializeError::ConditionUnmet`] for a target whose state does not
/// hold what the condition requires, or
/// [`MaterializeError::ConditionUnanswerable`] for a condition with no
/// such target to name.
fn judge_conditions(
    store: &mut OverlayStore,
    conditions: &[Condition],
) -> Result<(), MaterializeError> {
    for condition in conditions {
        // The verdict and the reason are one walk. What a receipt names
        // is the first leaf the rule holds that was not met: for the
        // one-leaf rule injection builds that is exact, and for a
        // threshold it is one of the reasons. Beside it, the frame that
        // asked — the rule is a leaf and a presence and says nothing
        // about who wanted either, so a reader without the node has to
        // guess which call it belonged to.
        match judge(store, &condition.rule)? {
            Judgement::Met => {}
            Judgement::Unmet { target, required } => {
                return Err(MaterializeError::ConditionUnmet {
                    target,
                    required,
                    node: condition.node,
                });
            }
            Judgement::Unanswerable => {
                return Err(MaterializeError::ConditionUnanswerable {
                    node: condition.node,
                });
            }
        }
    }
    Ok(())
}

/// What committed state says about a rule.
enum Judgement {
    /// State satisfies it.
    Met,
    /// State does not, and this is the first leaf that says so.
    Unmet {
        /// The leaf whose state did not meet the condition.
        target: EffectTarget,
        /// What it required there.
        required: Presence,
    },
    /// State cannot say, and the rule holds no leaf to point at. A
    /// threshold over no branches is the shape — this algebra's spelling
    /// of the rule nobody satisfies — and it refuses, because the
    /// alternative is a verdict reached by finding nothing to object to.
    Unanswerable,
}

/// Whether `expect` is met by state that does or does not hold
/// something.
const fn met_by(expect: Presence, held: bool) -> bool {
    match expect {
        Presence::Either => true,
        Presence::Absent => !held,
        Presence::Present => held,
    }
}

/// What committed state says about `rule`, and why.
///
/// Every leaf here reads the store: a rule reaching a call's evidence is
/// judged at that call, and admission has already sent it there.
///
/// One walk for both halves of the answer. A second walk to find the
/// reason can disagree with the first about the verdict, and where it
/// finds nothing to object to the refusal it was asked for does not
/// happen.
fn judge(store: &mut OverlayStore, rule: &Rule<JudgedLeaf>) -> Result<Judgement, MaterializeError> {
    match rule {
        Rule::Require(JudgedLeaf::Presence { target, expect }) => {
            Ok(if met_by(*expect, occupied(store, *target)?) {
                Judgement::Met
            } else {
                Judgement::Unmet {
                    target: *target,
                    required: *expect,
                }
            })
        }
        // A leaf reading evidence cannot be answered here, and admission
        // never routes a rule holding one this way.
        Rule::Require(_) => Ok(Judgement::Met),
        Rule::CountOf { count, rules } => {
            let mut got = 0usize;
            let mut first_unmet = None;
            for branch in rules {
                match judge(store, branch)? {
                    Judgement::Met => got += 1,
                    Judgement::Unmet { target, required } => {
                        first_unmet.get_or_insert(Judgement::Unmet { target, required });
                    }
                    Judgement::Unanswerable => {}
                }
            }
            if got >= usize::from(*count) {
                return Ok(Judgement::Met);
            }
            Ok(first_unmet.unwrap_or(Judgement::Unanswerable))
        }
    }
}

/// Whether the state a target names holds anything: the leaf a point
/// names, the entry an entry names, or any entry of an interval.
///
/// One seek whichever shape it is — an interval is asked for a single
/// entry, so the answer costs what a point read costs and the width it
/// spans is charged to the declaration rather than to the read. What an
/// interval pays for asking at all is exclusion: a declared read of it
/// conflicts with every write to the collection, which is what keeps the
/// answer from racing the entry that would change it.
///
/// # Errors
///
/// Whatever the store raises.
pub fn occupied(store: &mut OverlayStore, target: EffectTarget) -> Result<bool, StoreError> {
    let (owner, collection, lo, hi) = match target {
        EffectTarget::Point(key) => return Ok(store.read(key)?.is_some()),
        // An entry is the width-one interval at its order, which is the
        // normalization every other reader of a collection applies.
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => (owner, collection, order, order),
        // An interval that bought no entry answers closed: the seek
        // below would be an access it never declared, and a presence it
        // may not read is one it does not have.
        EffectTarget::Range { cap: 0, .. } => return Ok(false),
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            ..
        } => (owner, collection, lo, hi),
    };
    Ok(!store
        .entries_in_range(owner, collection, lo, hi, 1)?
        .is_empty())
}

/// What a target names as the thing whose contents are one fact: the
/// leaf a point names, or the collection an entry or an interval sits in.
///
/// Not the target itself, because two intervals of one collection are two
/// targets over one set of entries — so an interval saying its entries
/// are instances and an overlapping one saying they are bytes are two
/// answers about the same entries.
///
/// The evaluated half of the pair `publish`'s `ContentsExpr` opens. That
/// one asks whether a *signature* is self-consistent, before anything is
/// evaluated; this asks it of one transaction's evaluated clauses, where
/// two expressions that differ may have reached one cell.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Contents {
    /// One leaf.
    Leaf(SubstateKey),
    /// Every entry of one collection.
    Entries(Address, CollectionId),
}

/// Which cell's contents an effect is an answer about.
pub(super) const fn contents_of(target: EffectTarget) -> Contents {
    match target {
        EffectTarget::Point(key) => Contents::Leaf(key),
        EffectTarget::Entry {
            owner, collection, ..
        }
        | EffectTarget::Range {
            owner, collection, ..
        } => Contents::Entries(owner, collection),
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
pub(super) fn capability_for(
    effect: Effect,
    denominated: bool,
) -> Result<Capability, MaterializeError> {
    match (effect.target, effect.mode) {
        (EffectTarget::Point(key), Mode::Read) => Ok(if denominated {
            Capability::AmountRead(key)
        } else {
            Capability::Read(key)
        }),
        // What a cell holds chooses the handle. The two share no
        // operation, so a body reaching for the wrong one is holding a
        // type that does not have it rather than meeting a refusal.
        (EffectTarget::Point(key), Mode::Write { moves }) => Ok(if denominated {
            Capability::Amount { key, moves }
        } else {
            Capability::Write(key)
        }),
        // The two modes that move value and do nothing else. A cell
        // they name holds value, so the declaration has to say what —
        // judged here rather than at the movement, because a declaration
        // that cannot be materialized is one no body should run against.
        (EffectTarget::Point(key), Mode::Delta) => {
            if denominated {
                Ok(Capability::Delta(key))
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        (EffectTarget::Point(key), Mode::Credit) => {
            if denominated {
                Ok(Capability::Credit(key))
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        (EffectTarget::Point(key), Mode::Reserve { amount }) => {
            if denominated {
                Ok(Capability::Reserve { key, amount })
            } else {
                Err(MaterializeError::UndenominatedMovement(key))
            }
        }
        // Point targets are spoken for above, so what is left is a
        // collection one — and the two spell the same interval, the mode
        // choosing only which capability carries it.
        (target, mode @ (Mode::Read | Mode::Write { .. })) => interval_of(target)
            .map(|interval| match (mode, denominated) {
                (Mode::Write { moves }, true) => Capability::Instances { interval, moves },
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

    use hyperscale_vm_effects::{
        Condition, Declaration, DeclaredAccess, JudgedLeaf, Rule, SlotRef, rule,
    };
    use hyperscale_vm_types::{
        Address, AddressClass, CollectionId, Effect, EffectTarget, Mode, Moves, Presence,
        ResourceAddr, encode_amount,
    };

    use super::super::fixtures::{RESOURCE, declared, env, hash, holding, key, ord, tx};
    use super::{Capability, KernelSession, MaterializeError, capability_for};
    use crate::ledger::AmountLedger;
    use crate::overlay::OverlayStore;
    use crate::store::MemoryStore;

    /// Materialize one write with a presence condition beside it, for
    /// the presence tests.
    fn presence_verdict(
        store: MemoryStore,
        target: EffectTarget,
        requires: Presence,
    ) -> Result<(), MaterializeError> {
        let set = declared(&[Effect {
            target,
            mode: Mode::Write { moves: Moves::Both },
        }]);
        let ordered = ord(&set);
        let conditions = match requires {
            Presence::Either => Vec::new(),
            expect => vec![Condition::declared(Rule::Require(JudgedLeaf::Presence {
                target,
                expect,
            }))],
        };
        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: holding(&ordered),
                conditions,
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .map(|_| ())
    }

    /// The judge does not reach a verdict by failing to find an
    /// objection.
    ///
    /// `never()` is this algebra's spelling of the rule nobody satisfies
    /// — one of no branches — so it holds no leaf, and a walk that
    /// looked for an unmet leaf to blame would find none and let the
    /// transaction run. `Rule::judged` sends a leafless rule to
    /// admission today, so nothing routes one here; the last gate before
    /// a body runs is the wrong place to be relying on that.
    #[test]
    fn a_condition_nobody_satisfies_refuses_with_nothing_to_name() {
        let target = EffectTarget::Point(key(0xC2));
        let set = declared(&[Effect {
            target,
            mode: Mode::Write { moves: Moves::Both },
        }]);
        let ordered = ord(&set);
        assert_eq!(
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set,
                    ordered: holding(&ordered),
                    conditions: vec![Condition::declared(rule::never())],
                    ..Declaration::default()
                },
                tx(1),
                env(),
                hash,
            )
            .map(|_| ())
            .expect_err("a rule nobody satisfies is not satisfied"),
            MaterializeError::ConditionUnanswerable { node: None }
        );
    }

    /// A declaration says what it requires of a leaf, and the shard
    /// holding the leaf judges it before the body runs — the same seam,
    /// and the same class of verdict, as an infeasible reservation.
    ///
    /// All three shapes answer, because the requirement is about whether
    /// the state a target names holds anything rather than about how the
    /// target spells it: a cell is there or is not, an entry is there or
    /// is not, and an interval holds an entry or holds none.
    #[test]
    fn a_write_requiring_a_presence_the_state_does_not_have_refuses() {
        let cell = EffectTarget::Point(key(0xC1));
        let owner = Address::new([0xC1; 31], AddressClass::Component);
        let collection = CollectionId([9; 16]);
        let entry = EffectTarget::Entry {
            owner,
            collection,
            order: 7,
        };
        let interval = EffectTarget::Range {
            owner,
            collection,
            lo: 0,
            hi: u128::MAX,
            cap: 4,
        };
        let empty = |_: EffectTarget| MemoryStore::new();
        let occupied = |target: EffectTarget| {
            let mut store = MemoryStore::new();
            match target {
                EffectTarget::Point(key) => {
                    store.write(key, vec![7]);
                }
                EffectTarget::Entry {
                    owner,
                    collection,
                    order,
                } => {
                    store.entry_write(owner, collection, order, vec![7]);
                }
                EffectTarget::Range {
                    owner, collection, ..
                } => {
                    store.entry_write(owner, collection, 7, vec![7]);
                }
            }
            store
        };

        for target in [cell, entry, interval] {
            // A create lands only where nothing is.
            assert_eq!(
                presence_verdict(empty(target), target, Presence::Absent),
                Ok(()),
                "{target:?}"
            );
            assert_eq!(
                presence_verdict(occupied(target), target, Presence::Absent),
                Err(MaterializeError::ConditionUnmet {
                    target,
                    required: Presence::Absent,
                    node: None,
                }),
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
                Err(MaterializeError::ConditionUnmet {
                    target,
                    required: Presence::Present,
                    node: None,
                }),
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

    /// An interval's presence is about the interval, not about the whole
    /// collection: an entry outside the bounds leaves it empty, and the
    /// cap bounds the walk rather than the answer.
    #[test]
    fn an_intervals_presence_is_what_lies_inside_it() {
        let owner = Address::new([0xC3; 31], AddressClass::Component);
        let collection = CollectionId([9; 16]);
        let interval = EffectTarget::Range {
            owner,
            collection,
            lo: 10,
            hi: 20,
            cap: 1,
        };
        let holding = |order| {
            let mut store = MemoryStore::new();
            store.entry_write(owner, collection, order, vec![7]);
            store
        };

        assert_eq!(
            presence_verdict(holding(15), interval, Presence::Present),
            Ok(())
        );
        assert_eq!(
            presence_verdict(holding(21), interval, Presence::Present),
            Err(MaterializeError::ConditionUnmet {
                target: interval,
                required: Presence::Present,
                node: None,
            }),
            "an entry past the interval is not in it"
        );
        assert_eq!(
            presence_verdict(holding(21), interval, Presence::Absent),
            Ok(())
        );

        // Every entry the cap admits and more: one answer, one seek.
        let mut crowded = MemoryStore::new();
        for order in 10..=20 {
            crowded.entry_write(owner, collection, order, vec![7]);
        }
        assert_eq!(
            presence_verdict(crowded, interval, Presence::Present),
            Ok(())
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
            mode: Mode::Write { moves: Moves::Both },
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
            mode: Mode::Write { moves: Moves::Both },
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
        store.write(vault, encode_amount(100).to_vec());

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
        store.write(vault, encode_amount(100).to_vec());

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

        assert_eq!(session.reserve_amount(0, 0), Ok(5));
        assert_eq!(session.reserve_amount(1, 0), Ok(6));
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
            Clause, Expr, ModeExpr, TargetExpr, Value, package_slot, supports,
        };

        let owner = Address::new([3; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let resource = || Expr::Literal(Value::Address(RESOURCE.address()));
        let targets = [
            (
                TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Fixed(package_slot(0)),
                    material: vec![resource()],
                }),
                EffectTarget::Point(key(1)),
            ),
            (
                TargetExpr::Entry {
                    owner: Expr::SelfAddr,
                    collection: SlotRef::Fixed(package_slot(1)),
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
                    collection: SlotRef::Fixed(package_slot(2)),
                    material: vec![resource()],
                    lo: Expr::Literal(Value::U128(0)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Literal(Value::U64(4)),
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
            (
                ModeExpr::Write { moves: Moves::Both },
                Mode::Write { moves: Moves::Both },
            ),
            (ModeExpr::Delta, Mode::Delta),
            (ModeExpr::Reserve(Expr::Arg(0)), Mode::Reserve { amount: 1 }),
        ];

        // Denominated throughout, so a movement refused for saying
        // nothing cannot stand in for one refused for its shape.
        for (declared, target) in &targets {
            for (spelled, mode) in &modes {
                let clause = Clause::Effect {
                    reach: None,
                    guard: None,
                    target: declared.clone(),
                    mode: spelled.clone(),
                    denomination: Some(Box::new(resource())),
                };
                let built = capability_for(
                    Effect {
                        target: *target,
                        mode: *mode,
                    },
                    true,
                );
                assert_eq!(
                    !supports(&clause),
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
    /// would be value from nowhere, and a debit through one of two
    /// resources would be recorded under the other.
    #[test]
    fn one_cell_does_not_materialise_as_a_vault_and_a_byte_cell() {
        let write = Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Write { moves: Moves::Both },
        };
        let materialise = |holds: Vec<Option<ResourceAddr>>| {
            KernelSession::materialize(
                OverlayStore::new(Arc::new(MemoryStore::new())),
                &Declaration {
                    set: declared(&[write]),
                    ordered: vec![
                        DeclaredAccess {
                            reach: None,
                            effect: write,
                            holds: holds[0],
                        },
                        DeclaredAccess {
                            reach: None,
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
            materialise(vec![Some(RESOURCE), None]),
            Err(MaterializeError::MixedContents(write.target))
        );
        assert_eq!(
            materialise(vec![None, Some(RESOURCE)]),
            Err(MaterializeError::MixedContents(write.target))
        );
        // Two clauses, two resources: the pair a handle *is* built for
        // twice, and the one the receipt cannot describe. A debit through
        // either handle is recorded under whichever resource the first
        // clause named, so the conservation fold reads a transfer of one
        // resource where a cell of the other emptied.
        assert_eq!(
            materialise(vec![Some(RESOURCE), Some(ResourceAddr::new([0xB2; 31]))]),
            Err(MaterializeError::MixedContents(write.target))
        );
        // Agreeing clauses are what a body that reads and writes one cell
        // declares, and both directions stand.
        assert!(materialise(vec![Some(RESOURCE), Some(RESOURCE)]).is_ok());
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
            mode: Mode::Write { moves: Moves::Both },
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
                            reach: None,
                            effect: wide,
                            holds: Some(RESOURCE),
                        },
                        DeclaredAccess {
                            reach: None,
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

    /// Every commutative mode beside the exclusive hold, not just the
    /// one a case happened to name: `Credit` is `Delta` narrowed to one
    /// direction, and a check that knew two of the three would admit the
    /// third on the same cell.
    #[test]
    fn one_transaction_cannot_hold_both_an_exclusive_and_a_commutative_mode() {
        let cell = key(3);
        for commutative in [Mode::Delta, Mode::Credit, Mode::Reserve { amount: 0 }] {
            let set = declared(&[
                Effect {
                    target: EffectTarget::Point(cell),
                    mode: Mode::Write { moves: Moves::Both },
                },
                Effect {
                    target: EffectTarget::Point(cell),
                    mode: commutative,
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
                .expect_err("one cell, two settlement disciplines"),
                MaterializeError::SelfConflicting(cell),
                "{commutative:?}",
            );
        }
    }

    #[test]
    fn a_mismatched_held_reservation_is_surfaced_not_adopted() {
        let vault = key(4);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
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

    #[test]
    fn a_mode_the_world_cannot_hand_out_refuses_at_materialization() {
        // A commutative movement over a collection interval has no
        // capability form: an interval holds entries, not an amount.
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 1,
                cap: 1,
            },
            mode: Mode::Delta,
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
