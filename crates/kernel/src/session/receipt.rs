//! The receipt: what a transaction committed, judged and folded at
//! [`KernelSession::finish`].
//!
//! This is where the trace-subset oracle stands permanently: finishing
//! folds queued deltas, settles this transaction's reservations, verifies
//! every recorded access against the declared set, and only then produces
//! the receipt — outcome, state delta, fuel.

use std::collections::BTreeMap;

use hyperscale_vm_types::{AbortReason, EntryKey, Event, Movement, Outcome, SubstateKey};

use super::{Capability, KernelSession};
use crate::ledger::AmountLedger;
use crate::modes::{DeltaOp, total_movement};
use crate::oracle::undeclared_accesses;
use crate::overlay::OverlayStore;
use crate::store::{Access, Fault, StoreError};
use crate::supply::SupplyDelta;

/// The committed state change, keyed canonically: `None` is a removal.
/// Exclusive accesses report absolute outcomes; commutative accesses
/// report movements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDelta {
    /// Cells changed under exclusive write capabilities.
    pub cells: DeltaMap<SubstateKey, Option<Vec<u8>>>,
    /// Changed ordered-collection entries.
    pub entries: DeltaMap<EntryKey, Option<Vec<u8>>>,
    /// Delta movements per amount cell.
    pub movements: DeltaMap<SubstateKey, Movement>,
    /// Settled reservation amounts per cell.
    pub settles: DeltaMap<SubstateKey, u128>,
}

/// One kind of change a receipt carries, keyed by what it changes.
///
/// Lookup is open: asking whether a receipt changed a named key is a
/// question about that key, and the answer does not depend on who is
/// asking. Walking is not open, because every walk of a receipt exists to
/// apply it somewhere, and the shard applying it owns only part of what the
/// receipt carries — the rest is the outbound record for the shard that
/// does. So iteration is reachable only through [`StateDelta::owned`], and
/// a walk that skips the locality check stops being a review question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaMap<K: Ord, V> {
    entries: BTreeMap<K, V>,
}

// Derived `Default` would demand it of the key and the value; an empty map
// needs neither.
impl<K: Ord, V> Default for DeltaMap<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V> DeltaMap<K, V> {
    /// The change recorded at `key`, if any.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get(key)
    }

    /// Whether a change is recorded at `key`.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.contains_key(key)
    }

    /// Whether nothing of this kind changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many keys changed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Record a change, replacing any at the same key.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.entries.insert(key, value)
    }

    /// Drop the changes `keep` refuses.
    pub fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain(keep);
    }

    /// The whole map, for the crate that owns the locality rule. Consumers
    /// reach it through [`StateDelta::owned`].
    #[allow(clippy::iter_without_into_iter)] // an IntoIterator restores the unfiltered walk
    pub(crate) fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.entries.iter()
    }
}

impl<K: Ord, V> From<BTreeMap<K, V>> for DeltaMap<K, V> {
    fn from(entries: BTreeMap<K, V>) -> Self {
        Self { entries }
    }
}

impl<K: Ord + std::borrow::Borrow<Q>, Q: Ord + ?Sized, V> std::ops::Index<&Q> for DeltaMap<K, V> {
    type Output = V;

    fn index(&self, key: &Q) -> &V {
        &self.entries[key]
    }
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
    /// What the transaction said happened, in emission order.
    ///
    /// Carried on every participant of a cross-shard transaction, never
    /// locality-scoped: locality decides what a receipt *applies*, and two
    /// committees check each other's copy byte for byte. Which shard
    /// stores an event is the consumer's rule, read off each event's
    /// emitter.
    pub events: Vec<Event>,
    /// What this transaction brought into and out of existence.
    ///
    /// Empty for almost every transaction: a transfer is a debit and a
    /// credit that sum to zero, so only one carrying resource authority
    /// moves supply at all. What a shard does with this is add it to its
    /// own accumulator, which is the whole of how the accumulator moves
    /// on this path.
    pub supply: SupplyDelta,
    /// Total fuel consumed: engine schedule plus boundary supplement.
    ///
    /// Exact on a completed execution and engine-defined at a core trap,
    /// where wasmtime's in-register counter never flushes and `vm-ref`
    /// charges every executed operator. Reported as the engine saw it
    /// either way; what a consumer needs agreement on is
    /// [`Work`](crate::Work), which is derived beside the receipt rather
    /// than on it.
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

/// How a session's reservations settled: the per-cell amounts, or the
/// outcome the transaction aborts with instead.
enum Settlement {
    Settled(BTreeMap<SubstateKey, u128>),
    Aborted(Outcome),
}

impl KernelSession {
    /// Settle every reservation the table holds: an owned cell's settle
    /// releases the hold and folds the debit, a remote one releases with
    /// the amount kept as the outbound record. The store's hold is the
    /// per-transaction fold, so a cell reserved by several clauses
    /// settles once, whole — a second settle of the same hold would find
    /// it already gone.
    ///
    /// The error is a kernel defect; a refusal the caller aborts the
    /// transaction with comes back as [`Settlement::Aborted`].
    fn settle_reservations(&mut self) -> Result<Settlement, FinishError> {
        let mut settles = BTreeMap::new();
        for index in 0..self.table.len() {
            if let Capability::Reserve { key, .. } = self.table[index] {
                if settles.contains_key(&key) {
                    continue;
                }
                // A remote reservation settles at its owning shard; here
                // the hold releases and the receipt keeps the amount as
                // the outbound record.
                let settled = if self.locality.is_local(key.owner) {
                    self.store.settle(key, self.tx)
                } else {
                    self.store.release(key, self.tx)
                };
                match settled {
                    Ok(amount) => {
                        settles.insert(key, amount);
                    }
                    // An exclusive write earlier in this group drained the
                    // cell below the reservation it still covers. The
                    // reserver lost that race, and the refusal left its
                    // hold standing, so the amount is still readable.
                    Err(defect) => match defect.fault() {
                        Fault::Floor => {
                            let amount = self
                                .store
                                .held_reservation(key, self.tx)
                                .unwrap_or_default();
                            return Ok(Settlement::Aborted(Outcome::Infeasible { key, amount }));
                        }
                        Fault::Declaration(error) => {
                            return Ok(Settlement::Aborted(Outcome::UserError {
                                reason: error.into(),
                            }));
                        }
                        Fault::Defect => return Err(defect.into()),
                    },
                }
            }
        }
        Ok(Settlement::Settled(settles))
    }

    /// Close the session for a guest that completed: fold queued deltas,
    /// settle this transaction's reservations, run the trace-subset
    /// oracle, and produce the receipt together with the threaded store
    /// (the input for the next transaction in a conflict group).
    ///
    /// The outcome is this function's to produce, never its caller's to
    /// assert: [`Outcome::Completed`] with `value` when the account
    /// balances, or the flip the judgement forces — value dropped, a
    /// movement past its floor, a reservation lost — as an abort receipt
    /// over the untouched store. An abort that happened *before*
    /// completion never reaches here; it goes to [`Self::discard`].
    ///
    /// Supply accumulators do not move here, and cannot: a movement lands
    /// on a hashed key, so the resource it moved is unknowable at this
    /// layer — see [`SupplyLedger`](crate::SupplyLedger) for where the
    /// accumulator does move.
    ///
    /// # Errors
    ///
    /// [`FinishError::Undeclared`] if any recorded access escaped the
    /// declared set; a store failure otherwise. All are kernel defects.
    ///
    /// # Panics
    ///
    /// On an undrained scan debt, which is a host adapter that reached a
    /// scan without charging for it.
    pub fn finish(
        mut self,
        value: Option<u64>,
        fuel: u64,
    ) -> Result<(Receipt, OverlayStore), FinishError> {
        assert_eq!(
            self.ranges.owing(),
            0,
            "a host call reached a scan without charging what it lifted"
        );
        // Value first, because a transaction that lost some has nothing
        // else worth judging. A bucket still carrying anything here was
        // debited from a cell and never put into one, and the drop the
        // canonical ABI delivers is only reached by a body that lets a
        // handle go — a body that simply keeps one reaches nothing at
        // all. So the table is the account, and it has to balance for the
        // transaction to commit.
        if self.buckets.carries_value() {
            return Ok(abort_with(
                self.store,
                Outcome::UserError {
                    reason: AbortReason::ValueDropped,
                },
                fuel,
            ));
        }
        // Movements next: the pending deltas, as checked totals.
        let mut movements: BTreeMap<SubstateKey, Movement> = BTreeMap::new();
        let queued: Vec<(SubstateKey, Vec<DeltaOp>)> = self.store.pending_deltas().collect();
        for (key, ops) in queued {
            match total_movement(&ops) {
                Ok(movement) => {
                    movements.insert(key, movement);
                }
                // Totals past `u128` are the guest's own arithmetic — it
                // queued the operations — so the loss is its own.
                Err(error) => {
                    return Ok(abort_with(
                        self.store,
                        Outcome::UserError {
                            reason: error.into(),
                        },
                        fuel,
                    ));
                }
            }
        }
        for (key, movement) in &movements {
            if !self.locality.is_local(key.owner) {
                // The owning shard judges its own cells; here the
                // movement is the outbound record.
                continue;
            }
            let refusal = match self
                .store
                .judge_movement(*key, movement.credit, movement.debit)
            {
                Ok(_) => continue,
                // An uncovered debit, and a cell an exclusive write left
                // below the reservations still outstanding on it, are the
                // same deterministic loss: the floor this movement needed
                // is not there, and the transaction that declared the
                // movement is the one that loses.
                Err(defect) => match defect.fault() {
                    Fault::Floor => Outcome::Infeasible {
                        key: *key,
                        amount: movement.debit,
                    },
                    Fault::Declaration(error) => Outcome::UserError {
                        reason: error.into(),
                    },
                    Fault::Defect => return Err(defect.into()),
                },
            };
            return Ok(abort_with(self.store, refusal, fuel));
        }
        // A movement on a key this shard does not own folds at the owning
        // shard, never here: the receipt already carries it as the
        // outbound record, and folding it locally would fabricate a
        // balance for a cell this shard holds none of.
        let locality = self.locality.clone();
        self.store
            .retain_pending_deltas(&|key: SubstateKey| locality.is_local(key.owner));
        if let Err(defect) = self.store.commit_deltas() {
            // Every remaining fold is on an owned cell the movement judge
            // just cleared, so a floor here — like anything else that is
            // not a declaration defect — is the kernel disagreeing with
            // itself.
            return match defect.fault() {
                Fault::Declaration(error) => Ok(abort_with(
                    self.store,
                    Outcome::UserError {
                        reason: error.into(),
                    },
                    fuel,
                )),
                Fault::Floor | Fault::Defect => Err(defect.into()),
            };
        }
        let settles = match self.settle_reservations()? {
            Settlement::Settled(settles) => settles,
            Settlement::Aborted(refusal) => return Ok(abort_with(self.store, refusal, fuel)),
        };
        let escaped = undeclared_accesses(self.store.access_log(), &self.declared);
        if !escaped.is_empty() {
            return Err(FinishError::Undeclared(escaped));
        }
        let mut delta = diff(&self.store);
        // Commutative changes report as movements, never as absolutes.
        delta
            .cells
            .retain(|key, _| !movements.contains_key(key) && !settles.contains_key(key));
        delta.movements = movements.into();
        delta.settles = settles.into();
        self.store.merge_active();
        Ok((
            Receipt {
                outcome: Outcome::Completed { value },
                delta,
                events: self.events,
                // Value exists because the transaction committed it;
                // every flip above discarded its claims — supply and
                // events alike — with its effects.
                supply: self.supply,
                fuel,
            },
            self.store,
        ))
    }
}

/// Abandon everything this transaction did and report the failure as its
/// own rather than the batch's.
fn abort_with(mut store: OverlayStore, outcome: Outcome, fuel: u64) -> (Receipt, OverlayStore) {
    store.discard_active();
    (
        Receipt {
            outcome,
            delta: StateDelta::default(),
            // An abort discards its effects, and what it claimed happened
            // is one of them — including value it said it brought into or
            // out of existence, which never happened either.
            events: Vec::new(),
            supply: SupplyDelta::default(),
            fuel,
        },
        store,
    )
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
    for (key, after) in store.active_entries() {
        if store
            .pre_active_entry(key.owner, key.collection, key.order)
            .as_deref()
            != after
        {
            delta.entries.insert(key, after.map(<[u8]>::to_vec));
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{
        AbortReason, Address, AddressClass, CollectionId, Effect, EffectTarget, Event, Mode,
        Outcome, encode_amount,
    };

    use super::super::fixtures::{declared, key, session_holding, session_over};
    use crate::modes::decode_amount;
    use crate::store::{MemoryStore, WorkingStore};

    #[test]
    fn an_emission_is_stamped_with_the_entered_invocation() {
        // Attribution decides which shard stores an event, so the address
        // comes from the runner entering a node — never from the guest,
        // which would make it a claim.
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        let (first, second) = (
            Address::new([0x11; 31], AddressClass::Component),
            Address::new([0x22; 31], AddressClass::Component),
        );

        session.enter_invocation(first);
        session.emit(3, b"one".to_vec()).unwrap();
        session.enter_invocation(second);
        session.emit(4, b"two".to_vec()).unwrap();

        let (receipt, _) = session.finish(None, 0).unwrap();
        assert_eq!(
            receipt.events,
            vec![
                Event {
                    emitter: first,
                    event_type: 3,
                    payload: b"one".to_vec(),
                },
                Event {
                    emitter: second,
                    event_type: 4,
                    payload: b"two".to_vec(),
                },
            ],
        );
    }

    #[test]
    fn an_abort_discards_what_the_transaction_claimed() {
        // An abort discards its effects, and a claim about what happened
        // is one of them.
        let cell = key(0xE1);
        let set = declared(&[Effect {
            target: EffectTarget::Point(cell),
            mode: Mode::Delta,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        session.enter_invocation(Address::new([9; 31], AddressClass::Component));
        session.emit(1, b"paid".to_vec()).unwrap();
        session.delta_sub(0, 1).unwrap();

        let (receipt, _) = session.finish(None, 7).unwrap();
        assert!(
            matches!(receipt.outcome, Outcome::Infeasible { .. }),
            "a debit past the floor is the transaction's own loss",
        );
        assert!(receipt.events.is_empty());
    }

    /// Value a body neither credits nor hands back does not commit.
    ///
    /// The drop refusal only reaches a body that lets a handle go. One
    /// that keeps it says nothing to the ABI at all, so the debit would
    /// otherwise land and the value it produced reach nowhere.
    #[test]
    fn a_transaction_still_holding_value_does_not_commit() {
        let vault = key(0xB2);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write,
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.write_take(0, 40).expect("the cell covers it");
        let (receipt, mut threaded) = session.finish(None, 7).expect("finishes");
        assert_eq!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::ValueDropped,
            },
        );
        // The debit is discarded with everything else the transaction
        // claimed, so the cell stands where it was.
        assert_eq!(
            decode_amount(&threaded.read(vault).unwrap().unwrap()),
            Ok(100)
        );
        assert!(receipt.delta.cells.is_empty());
        let _ = funds;
    }

    /// An emptied bucket is not value, so keeping one commits.
    ///
    /// What a split leaves behind is a live handle carrying nothing, and
    /// a body has no reason to put it anywhere. Refusing on liveness
    /// rather than on quantity would make every split need a drop.
    #[test]
    fn an_empty_bucket_left_standing_is_not_a_loss() {
        let vault = key(0xB3);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write,
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.write_take(0, 40).expect("the cell covers it");
        let split = session.bucket_take(funds, 40).expect("the whole of it");
        session.write_put(0, split).expect("the credit lands");

        let (receipt, _) = session.finish(None, 7).expect("finishes");
        assert_eq!(receipt.outcome, Outcome::Completed { value: None });
    }

    #[test]
    #[should_panic(expected = "without charging what it lifted")]
    fn finishing_still_owing_for_a_scan_is_a_defect() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        session.range_count(0).unwrap();
        let _ = session.finish(None, 0);
    }
}
