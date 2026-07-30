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

use hyperscale_vm_effects::{Address, Effect, EffectSet, EffectTarget, Mode, RoleId, SubstateKey};

use crate::modes::{DeltaOp, TxHash, decode_amount, encode_amount};
use crate::oracle::undeclared_accesses;
use crate::store::{Access, MemoryStore, StoreError, SubstateStore};

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

/// How execution ended, as the receipt records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The export returned; its scalar result if it had one.
    Completed {
        /// The export's return value, when the signature has one.
        value: Option<u64>,
    },
    /// Execution trapped; the deterministic reason class.
    Trapped {
        /// The trap's classification text.
        reason: String,
    },
}

/// The committed state change, keyed canonically: `None` is a removal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDelta {
    /// Changed point cells.
    pub cells: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    /// Changed ordered-collection entries.
    pub entries: BTreeMap<(Address, RoleId, u128), Option<Vec<u8>>>,
}

impl StateDelta {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.entries.is_empty()
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
    store: MemoryStore,
    baseline: MemoryStore,
    declared: EffectSet,
    table: Vec<Capability>,
    tx: TxHash,
    env: EnvInputs,
    hash_fn: fn(&[u8]) -> [u8; 32],
}

impl KernelSession {
    /// Materialize capabilities for a declared effect set over committed
    /// state, judging and holding the declared reservations.
    ///
    /// The capability table's order is the effect set's canonical order,
    /// so reps are deterministic; the caller passes handles to the guest
    /// in table order.
    ///
    /// # Errors
    ///
    /// Any [`MaterializeError`]; all are pre-execution aborts.
    pub fn materialize(
        mut store: MemoryStore,
        declared: &EffectSet,
        tx: TxHash,
        env: EnvInputs,
        hash_fn: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, MaterializeError> {
        let baseline = store.clone();
        let mut table = Vec::with_capacity(declared.len());
        let mut reservations = Vec::new();
        for effect in declared.iter() {
            if let (EffectTarget::Point(key), Mode::Reserve { amount }) =
                (effect.target, effect.mode)
            {
                if store.is_locked(key) {
                    return Err(MaterializeError::LockedTarget(key));
                }
                reservations.push((tx, key, amount));
            }
            table.push(capability_for(&store, effect)?);
        }

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
            baseline,
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

    /// A pinned read through a snapshot capability.
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
    /// reservations, run the trace-subset oracle, and produce the receipt.
    ///
    /// # Errors
    ///
    /// [`FinishError::Undeclared`] if any recorded access escaped the
    /// declared set; a store failure otherwise.
    pub fn finish(mut self, outcome: Outcome, fuel: u64) -> Result<Receipt, FinishError> {
        self.store.commit_deltas()?;
        for capability in &self.table {
            if let Capability::Reserve(key) = capability {
                self.store.settle(*key, self.tx)?;
            }
        }
        let escaped = undeclared_accesses(self.store.access_log(), &self.declared);
        if !escaped.is_empty() {
            return Err(FinishError::Undeclared(escaped));
        }
        Ok(Receipt {
            outcome,
            delta: diff(&self.baseline, &self.store),
            fuel,
        })
    }

    /// The session's store, for test inspection.
    #[must_use]
    pub const fn store(&self) -> &MemoryStore {
        &self.store
    }
}

/// The capability form of one declared effect: the world-design mapping.
/// Entry targets are degenerate one-entry intervals, so collection access
/// needs exactly two resource shapes.
fn capability_for(store: &MemoryStore, effect: Effect) -> Result<Capability, MaterializeError> {
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

fn diff(before: &MemoryStore, after: &MemoryStore) -> StateDelta {
    let mut delta = StateDelta::default();
    let before_cells: BTreeMap<_, _> = before.cells().collect();
    let after_cells: BTreeMap<_, _> = after.cells().collect();
    for (key, value) in &after_cells {
        if before_cells.get(key) != Some(value) {
            delta.cells.insert(*key, Some(value.to_vec()));
        }
    }
    for key in before_cells.keys() {
        if !after_cells.contains_key(key) {
            delta.cells.insert(*key, None);
        }
    }
    let before_entries: BTreeMap<_, _> = before.collection_entries().collect();
    let after_entries: BTreeMap<_, _> = after.collection_entries().collect();
    for (key, value) in &after_entries {
        if before_entries.get(key) != Some(value) {
            delta.entries.insert(*key, Some(value.to_vec()));
        }
    }
    for key in before_entries.keys() {
        if !after_entries.contains_key(key) {
            delta.entries.insert(*key, None);
        }
    }
    delta
}
