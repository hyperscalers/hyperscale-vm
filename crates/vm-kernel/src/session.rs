//! The per-transaction kernel session: capability materialization, the
//! mode operations behind the world's handles, and the receipt.
//!
//! A session is built from a declared effect set. Materialization turns
//! each declared effect into one [`Capability`] — the table the runtimes'
//! handle reps index — judging and holding reservations as it goes, so an
//! infeasible reservation aborts before any guest runs. During execution
//! the engines' host adapters delegate every world operation here; each
//! refusal is a deterministic message, identical on every replica because
//! the session itself generates it on both runtimes.
//!
//! [`KernelSession::finish`] is where the trace-subset oracle stands
//! permanently: it folds queued deltas, settles this transaction's
//! reservations, verifies every recorded access against the declared set,
//! and only then produces the receipt — outcome, state delta, fuel.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Mode, ModeKind, RoleId, SubstateKey,
};

use crate::modes::{DeltaOp, ModeError, TxHash, decode_amount, encode_amount};
use crate::oracle::undeclared_accesses;
use crate::overlay::OverlayStore;
use crate::store::{Access, StoreError, SubstateStore};

/// One materialized capability: what a handle rep grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A fresh read of one cell.
    Read(SubstateKey),
    /// A pinned read of one cell.
    Snapshot(SubstateKey),
    /// An exclusive read-modify-write of one cell.
    Write(SubstateKey),
    /// Commutative movement on one amount cell.
    Delta(SubstateKey),
    /// A held reservation on one amount cell.
    Reserve(SubstateKey),
    /// A read interval of an ordered collection.
    RangeRead {
        /// The collection's owner.
        owner: Address,
        /// The collection's role under the owner.
        collection: RoleId,
        /// Inclusive lower order-key bound.
        lo: u128,
        /// Inclusive upper order-key bound.
        hi: u128,
        /// The declared entry cap.
        cap: u32,
    },
    /// A read-modify-write interval of an ordered collection.
    RangeWrite {
        /// The collection's owner.
        owner: Address,
        /// The collection's role under the owner.
        collection: RoleId,
        /// Inclusive lower order-key bound.
        lo: u128,
        /// Inclusive upper order-key bound.
        hi: u128,
        /// The declared entry cap.
        cap: u32,
    },
}

/// Why materialization refused a declared effect set — each an abort
/// before any guest execution.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MaterializeError {
    /// A declared mode/target combination the world cannot yet hand out.
    #[error("no capability form for {0:?}")]
    Unsupported(Effect),
    /// A mutation declared on a permanently locked substate.
    #[error("declared mutation of locked substate {0:?}")]
    LockedTarget(SubstateKey),
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
    /// An already-held reservation whose amount differs from the declared
    /// one — a batch bookkeeping defect, surfaced rather than adopted.
    #[error("held reservation on {0:?} does not match the declaration")]
    HeldMismatch(SubstateKey),
    /// A store failure while judging reservations.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A deterministic host refusal during execution: the trap text on every
/// replica.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionTrap {
    /// A rep with no table entry — unreachable through either runtime's
    /// canonical ABI, kept as an honest error rather than a panic.
    #[error("unknown capability handle {0}")]
    UnknownHandle(u32),
    /// A rep whose capability does not grant the operation — unreachable
    /// through the typed world surface, kept as an honest error.
    #[error("handle {0} does not grant this operation")]
    WrongMode(u32),
    /// An amount that is not a 16-byte cell.
    #[error("amount cell must be 16 bytes, found {0}")]
    BadAmountCell(usize),
    /// An order key that is not a 16-byte cell.
    #[error("order cell must be 16 bytes, found {0}")]
    BadOrderCell(usize),
    /// An entry index past the interval's current entries.
    #[error("entry index {index} out of bounds ({count} entries)")]
    IndexOutOfBounds {
        /// The requested index.
        index: u32,
        /// Entries currently visible in the interval.
        count: usize,
    },
    /// An insert order outside the declared interval.
    #[error("order outside the declared interval")]
    OrderOutsideInterval,
    /// A reservation the table promises but the store no longer holds —
    /// unreachable, kept honest.
    #[error("no reservation held")]
    ReservationMissing,
    /// A store refusal.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The deterministic environment a transaction executes under.
#[derive(Clone, Copy, Debug)]
pub struct EnvInputs {
    /// The transaction clock in milliseconds.
    pub clock_ms: u64,
    /// The transaction's randomness draw.
    pub randomness: [u8; 32],
}

/// How execution ended: the abort taxonomy as the receipt records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The export returned; its scalar result if it had one.
    Completed {
        /// The export's return value, when the signature has one.
        value: Option<u64>,
    },
    /// A guest defect: a trap, a panic, a kernel refusal of bad guest
    /// arguments, a declaration defect. The sender's fault; priced at the
    /// sender.
    UserError {
        /// The deterministic reason class.
        reason: String,
    },
    /// A lost deterministic race: a declared reservation the committed
    /// balance could not cover — aborted before any execution — or an
    /// unconditional debit past the floor of committed minus outstanding
    /// reservations, aborted at commit with its fuel charged.
    Infeasible {
        /// The cell that could not cover it.
        key: SubstateKey,
        /// The uncovered amount.
        amount: u128,
    },
    /// A kernel or store invariant failure — never the sender's fault, and
    /// never expected to occur.
    ProtocolError {
        /// The deterministic reason class.
        reason: String,
    },
}

/// This transaction's commutative movement on one amount cell: checked
/// credit and debit totals.
///
/// Recording movements rather than absolute cell values is what makes
/// receipts schedule-invariant — another transaction's compatible deltas
/// on the same cell cannot leak into this receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Movement {
    /// Total credited.
    pub credit: u128,
    /// Total debited.
    pub debit: u128,
}

/// The committed state change, keyed canonically: `None` is a removal.
/// Exclusive accesses report absolute outcomes; commutative accesses
/// report movements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDelta {
    /// Cells changed under exclusive write capabilities.
    pub cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    /// Changed ordered-collection entries.
    pub entries: BTreeMap<(Address, RoleId, u128), Option<Vec<u8>>>,
    /// Delta movements per amount cell.
    pub movements: BTreeMap<SubstateKey, Movement>,
    /// Settled reservation amounts per cell.
    pub settles: BTreeMap<SubstateKey, u128>,
}

impl StateDelta {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
            && self.entries.is_empty()
            && self.movements.is_empty()
            && self.settles.is_empty()
    }
}

/// The transaction's receipt: a pure function of committed content and the
/// signed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// How execution ended.
    pub outcome: Outcome,
    /// What committed.
    pub delta: StateDelta,
    /// Total fuel consumed: engine schedule plus boundary supplement.
    pub fuel: u64,
}

/// Why the session refused to produce a receipt.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinishError {
    /// The oracle's verdict: accesses outside the declared set. With
    /// capability materialization in front, this indicates a kernel defect,
    /// and it is checked after every execution regardless.
    #[error("{} accesses outside the declared set", .0.len())]
    Undeclared(Vec<Access>),
    /// A store failure while folding deltas or settling reservations.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The per-transaction kernel session.
#[derive(Debug)]
pub struct KernelSession {
    store: OverlayStore,
    declared: EffectSet,
    table: Vec<Capability>,
    tx: TxHash,
    env: EnvInputs,
    hash_fn: fn(&[u8]) -> [u8; 32],
}

impl KernelSession {
    /// Materialize capabilities for a declared effect set over the
    /// overlay's state, judging and holding the declared reservations — or
    /// adopting reservations a batch judge already holds for this
    /// transaction.
    ///
    /// The overlay's base is the snapshot source: the attested version
    /// snapshot reads resolve against, fixed for the whole batch
    /// regardless of what the group threads on top.
    ///
    /// The capability table's order is the effect set's canonical order,
    /// so reps are deterministic; the caller passes handles to the guest
    /// in table order.
    ///
    /// # Errors
    ///
    /// Any [`MaterializeError`]; all are pre-execution aborts.
    pub fn materialize(
        mut store: OverlayStore,
        declared: &EffectSet,
        tx: TxHash,
        env: EnvInputs,
        hash_fn: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, MaterializeError> {
        store.clear_log();
        let mut table = Vec::with_capacity(declared.len());
        let mut reservations = Vec::new();
        for effect in declared.iter() {
            if let (EffectTarget::Point(key), Mode::Reserve { amount }) =
                (effect.target, effect.mode)
            {
                if store.is_locked(key) {
                    return Err(MaterializeError::LockedTarget(key));
                }
                match store.held_reservation(key, tx) {
                    Some(held) if held == amount => {}
                    Some(_) => return Err(MaterializeError::HeldMismatch(key)),
                    None => reservations.push((tx, key, amount)),
                }
            }
            table.push(capability_for(&store, effect)?);
        }
        reject_self_conflicts(declared)?;

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
        })
    }

    /// The capability table; a handle's rep is its index here.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.table
    }

    fn capability(&self, rep: u32) -> Result<Capability, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.table.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// A fresh read through a read capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Read(key) => Ok(self.store.read(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// A pinned read through a snapshot capability: the value comes from
    /// the overlay's base — the attested version — never from state
    /// concurrent transactions are changing.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn snap_cell(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Snapshot(key) => Ok(self.store.snapshot(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The read half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Write(key) => Ok(self.store.read(key)?.unwrap_or_default()),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The write half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), SessionTrap> {
        match self.capability(rep)? {
            Capability::Write(key) => Ok(self.store.write(key, value)?),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Credit through a delta capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_add(&mut self, rep: u32, amount: &[u8]) -> Result<(), SessionTrap> {
        self.delta(rep, amount, DeltaOp::Add)
    }

    /// Debit through a delta capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn delta_sub(&mut self, rep: u32, amount: &[u8]) -> Result<(), SessionTrap> {
        self.delta(rep, amount, DeltaOp::Sub)
    }

    fn delta(
        &mut self,
        rep: u32,
        amount: &[u8],
        op: fn(u128) -> DeltaOp,
    ) -> Result<(), SessionTrap> {
        match self.capability(rep)? {
            Capability::Delta(key) => {
                let amount =
                    decode_amount(amount).map_err(|_| SessionTrap::BadAmountCell(amount.len()))?;
                Ok(self.store.queue_delta(key, op(amount))?)
            }
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The reserved amount behind a reserve capability, as a 16-byte cell.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_amount(&mut self, rep: u32) -> Result<Vec<u8>, SessionTrap> {
        match self.capability(rep)? {
            Capability::Reserve(key) => self
                .store
                .held_reservation(key, self.tx)
                .map(|amount| encode_amount(amount).to_vec())
                .ok_or(SessionTrap::ReservationMissing),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    fn range_of(&self, rep: u32) -> Result<(Address, RoleId, u128, u128, u32, bool), SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeRead {
                owner,
                collection,
                lo,
                hi,
                cap,
            } => Ok((owner, collection, lo, hi, cap, false)),
            Capability::RangeWrite {
                owner,
                collection,
                lo,
                hi,
                cap,
            } => Ok((owner, collection, lo, hi, cap, true)),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    fn scan(&mut self, rep: u32) -> Result<Vec<(u128, Vec<u8>)>, SessionTrap> {
        let (owner, collection, lo, hi, cap, _) = self.range_of(rep)?;
        Ok(self.store.scan(owner, collection, lo, hi, cap)?)
    }

    /// Entries currently visible in the interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_count(&mut self, rep: u32) -> Result<u32, SessionTrap> {
        let entries = self.scan(rep)?;
        Ok(u32::try_from(entries.len()).unwrap_or(u32::MAX))
    }

    /// The order key at `index`, ascending, as a 16-byte cell.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_order(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, SessionTrap> {
        let entries = self.scan(rep)?;
        indexed(&entries, index).map(|(order, _)| encode_amount(*order).to_vec())
    }

    /// The entry value at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, SessionTrap> {
        let entries = self.scan(rep)?;
        indexed(&entries, index).map(|(_, value)| value.clone())
    }

    /// Replace the entry value at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), SessionTrap> {
        let (owner, collection, _, _, _, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        let entries = self.scan(rep)?;
        let (order, _) = indexed(&entries, index)?;
        Ok(self.store.entry_write(owner, collection, *order, value)?)
    }

    /// Insert or replace the entry at `order`, which must lie inside the
    /// declared interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_insert(
        &mut self,
        rep: u32,
        order: &[u8],
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let (owner, collection, lo, hi, _, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        let order = decode_amount(order).map_err(|_| SessionTrap::BadOrderCell(order.len()))?;
        if !(lo..=hi).contains(&order) {
            return Err(SessionTrap::OrderOutsideInterval);
        }
        Ok(self.store.entry_write(owner, collection, order, value)?)
    }

    /// Remove the entry at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), SessionTrap> {
        let (owner, collection, _, _, _, writable) = self.range_of(rep)?;
        if !writable {
            return Err(SessionTrap::WrongMode(rep));
        }
        let entries = self.scan(rep)?;
        let (order, _) = indexed(&entries, index)?;
        self.store.entry_remove(owner, collection, *order)?;
        Ok(())
    }

    /// The transaction clock in milliseconds.
    #[must_use]
    pub const fn clock_ms(&self) -> u64 {
        self.env.clock_ms
    }

    /// The transaction's randomness draw.
    #[must_use]
    pub const fn randomness(&self) -> [u8; 32] {
        self.env.randomness
    }

    /// The protocol hash function.
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        (self.hash_fn)(data)
    }

    /// Close the session: fold queued deltas, settle this transaction's
    /// reservations, run the trace-subset oracle, and produce the receipt
    /// together with the threaded store (the input for the next
    /// transaction in a conflict group).
    ///
    /// A debit past the movement floor — committed plus this
    /// transaction's credit, minus every outstanding reservation — is the
    /// transaction's own deterministic loss: it comes back as an
    /// [`Outcome::Infeasible`] receipt over the untouched store, never as
    /// an error.
    ///
    /// # Errors
    ///
    /// [`FinishError::Undeclared`] if any recorded access escaped the
    /// declared set; a store failure otherwise. All are kernel defects.
    pub fn finish(
        mut self,
        outcome: Outcome,
        fuel: u64,
    ) -> Result<(Receipt, OverlayStore), FinishError> {
        // Movements first: the pending deltas, as checked totals.
        let mut movements: BTreeMap<SubstateKey, Movement> = BTreeMap::new();
        for (key, ops) in self.store.pending_deltas() {
            let mut movement = Movement::default();
            for op in ops {
                match op {
                    DeltaOp::Add(amount) => {
                        movement.credit = movement
                            .credit
                            .checked_add(amount)
                            .ok_or(StoreError::Mode(ModeError::DeltaOverflow))?;
                    }
                    DeltaOp::Sub(amount) => {
                        movement.debit = movement
                            .debit
                            .checked_add(amount)
                            .ok_or(StoreError::Mode(ModeError::DeltaOverflow))?;
                    }
                }
            }
            movements.insert(key, movement);
        }
        for (key, movement) in &movements {
            match self
                .store
                .judge_movement(*key, movement.credit, movement.debit)
            {
                Ok(_) => {}
                Err(StoreError::Mode(ModeError::CellUnderflow | ModeError::CellOverflow)) => {
                    let refusal = Outcome::Infeasible {
                        key: *key,
                        amount: movement.debit,
                    };
                    self.store.discard_active();
                    return Ok((
                        Receipt {
                            outcome: refusal,
                            delta: StateDelta::default(),
                            fuel,
                        },
                        self.store,
                    ));
                }
                Err(defect) => return Err(defect.into()),
            }
        }
        self.store.commit_deltas()?;
        let mut settles = BTreeMap::new();
        for capability in &self.table {
            if let Capability::Reserve(key) = capability {
                let amount = self.store.settle(*key, self.tx)?;
                settles.insert(*key, amount);
            }
        }
        let escaped = undeclared_accesses(self.store.access_log(), &self.declared);
        if !escaped.is_empty() {
            return Err(FinishError::Undeclared(escaped));
        }
        let mut delta = diff(&self.store);
        // Commutative changes report as movements, never as absolutes.
        delta
            .cells
            .retain(|key, _| !movements.contains_key(key) && !settles.contains_key(key));
        delta.movements = movements;
        delta.settles = settles;
        self.store.merge_active();
        Ok((
            Receipt {
                outcome,
                delta,
                fuel,
            },
            self.store,
        ))
    }

    /// Abandon the session: the transaction's layer is dropped and the
    /// store returns as the session found it.
    #[must_use]
    pub fn discard(mut self) -> OverlayStore {
        self.store.discard_active();
        self.store
    }

    /// The session's store, for test inspection.
    #[must_use]
    pub const fn store(&self) -> &OverlayStore {
        &self.store
    }
}

/// One transaction may not declare both an exclusive write and a
/// commutative mode on the same cell: the receipt records absolutes for
/// the one and movements for the other, and they cannot compose.
fn reject_self_conflicts(declared: &EffectSet) -> Result<(), MaterializeError> {
    let effects: Vec<Effect> = declared.iter().collect();
    for (index, a) in effects.iter().enumerate() {
        for b in &effects[index + 1..] {
            if let (EffectTarget::Point(key), EffectTarget::Point(other)) = (a.target, b.target)
                && key == other
            {
                let kinds = (a.mode.kind(), b.mode.kind());
                let exclusive_and_commutative = matches!(
                    kinds,
                    (ModeKind::Write, ModeKind::Delta | ModeKind::Reserve)
                        | (ModeKind::Delta | ModeKind::Reserve, ModeKind::Write)
                );
                if exclusive_and_commutative {
                    return Err(MaterializeError::SelfConflicting(key));
                }
            }
        }
    }
    Ok(())
}

/// The capability form of one declared effect: the world-design mapping.
/// Entry targets are degenerate one-entry intervals, so collection access
/// needs exactly two resource shapes.
fn capability_for(store: &OverlayStore, effect: Effect) -> Result<Capability, MaterializeError> {
    let locked_checked = |key: SubstateKey| {
        if store.is_locked(key) {
            Err(MaterializeError::LockedTarget(key))
        } else {
            Ok(key)
        }
    };
    match (effect.target, effect.mode) {
        (EffectTarget::Point(key), Mode::Read) => Ok(Capability::Read(key)),
        (EffectTarget::Point(key), Mode::Snapshot { .. }) => Ok(Capability::Snapshot(key)),
        (EffectTarget::Point(key), Mode::Write) => Ok(Capability::Write(locked_checked(key)?)),
        (EffectTarget::Point(key), Mode::Delta) => Ok(Capability::Delta(locked_checked(key)?)),
        (EffectTarget::Point(key), Mode::Reserve { .. }) => {
            Ok(Capability::Reserve(locked_checked(key)?))
        }
        (
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            Mode::Read,
        ) => Ok(Capability::RangeRead {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        (
            EffectTarget::Entry {
                owner,
                collection,
                order,
            },
            Mode::Write,
        ) => Ok(Capability::RangeWrite {
            owner,
            collection,
            lo: order,
            hi: order,
            cap: 1,
        }),
        (
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            },
            Mode::Read,
        ) => Ok(Capability::RangeRead {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
        (
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            },
            Mode::Write,
        ) => Ok(Capability::RangeWrite {
            owner,
            collection,
            lo,
            hi,
            cap,
        }),
        _ => Err(MaterializeError::Unsupported(effect)),
    }
}

fn indexed<T>(entries: &[T], index: u32) -> Result<&T, SessionTrap> {
    usize::try_from(index)
        .ok()
        .and_then(|index| entries.get(index))
        .ok_or(SessionTrap::IndexOutOfBounds {
            index,
            count: entries.len(),
        })
}

/// The committed state change: the active layer against what the store
/// held before this transaction — a write of the value already in place
/// is no change at all.
fn diff(store: &OverlayStore) -> StateDelta {
    let mut delta = StateDelta::default();
    for (key, after) in store.active_cells() {
        if store.pre_active_cell(key).as_deref() != after {
            delta.cells.insert(key, after.map(<[u8]>::to_vec));
        }
    }
    for ((owner, collection, order), after) in store.active_entries() {
        if store.pre_active_entry(owner, collection, order).as_deref() != after {
            delta
                .entries
                .insert((owner, collection, order), after.map(<[u8]>::to_vec));
        }
    }
    delta
}
