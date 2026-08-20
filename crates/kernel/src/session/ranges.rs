//! The interval machinery: materialized scans, the scan-debt accounting
//! behind boundary pricing, and the write-cap budget.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{SCAN_SEEK_ENTRIES, distinct_ids};
use hyperscale_vm_types::{AMOUNT_CELL_BYTES, Address, CollectionId};

use super::{Capability, Held, Interval, KernelSession, SessionTrap};
use crate::store::WorkingStore;

/// What one interval scan costs before any entry is counted, in the
/// boundary-byte terms the fuel schedule prices.
///
/// The declared seek floor at the per-entry byte floor, so the fuel
/// schedule and the declared footprint price the same seek from one
/// figure. Structural for the reason [`SCAN_SEEK_ENTRIES`] states: the
/// seek walks both overlay layers and the base whether or not the
/// interval holds anything, so a page's cost is not proportional to what
/// it returns and an empty one is not free.
pub const SCAN_SEEK_BYTES: usize = SCAN_SEEK_ENTRIES * AMOUNT_CELL_BYTES;

/// The session's interval state: what scans have materialized, what they
/// still owe, and what each write interval has spent of its cap.
#[derive(Debug, Default)]
pub(super) struct Ranges {
    /// Materialized interval contents per handle, dropped when a write
    /// touches the collection. A guest walking an interval asks for its
    /// length and then each entry in turn; re-scanning per question makes
    /// that walk quadratic in the interval and floods the access log with
    /// one record per step.
    scans: BTreeMap<u32, Vec<(u128, Vec<u8>)>>,
    /// What the scans above lifted out of the store, in boundary-byte
    /// terms, since whoever holds the fuel budget last drained it.
    ///
    /// A scan crosses no ABI boundary — a page stays host-side until an
    /// accessor asks it for one entry — so the copy metering that prices
    /// every other host call is blind to it. Left unpriced, the page a
    /// write invalidates would be free to re-materialize, and a body
    /// alternating a write with a count would buy an unbounded number of
    /// them at the cost of the loop alone.
    scanned: usize,
    /// The distinct entries each write interval has changed, against the
    /// cap that interval declared.
    ///
    /// A scan truncates at the cap, so reads are bounded by construction;
    /// nothing truncates a write, so the budget is counted here or not at
    /// all. Kept per handle rather than per collection because the cap is
    /// a property of the declared interval, and cumulative across the
    /// transaction rather than per scan — a write budget the invalidation
    /// of a materialized interval must not refund.
    written: BTreeMap<u32, BTreeSet<u128>>,
}

impl Ranges {
    /// What the scans still owe the fuel budget, in boundary bytes.
    pub(super) const fn owing(&self) -> usize {
        self.scanned
    }
}

impl KernelSession {
    /// The interval a range handle names, whichever mode it carries.
    ///
    /// For the questions both modes answer — how many entries, what is at
    /// an index, which collection a scan belongs to.
    fn interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeRead(interval)
            | Capability::RangeWrite(interval)
            | Capability::InstanceRange(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The interval a byte-writing handle names.
    ///
    /// Every entry rewrite asks through here, so the refusal a read
    /// interval meets is stated once rather than repeated at each of
    /// them — and a mutation added later cannot forget to ask, because
    /// there is no other way to reach the interval it would change.
    fn write_interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::RangeWrite(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// The interval an instance-moving handle names — the same
    /// statement as [`Self::write_interval`], for the entries that are
    /// value rather than bytes.
    fn instance_interval(&self, rep: u32) -> Result<Interval, SessionTrap> {
        match self.capability(rep)? {
            Capability::InstanceRange(interval) => Ok(interval),
            _ => Err(SessionTrap::WrongMode(rep)),
        }
    }

    /// Read a run of entries, charging what it lifted to
    /// [`Self::take_scan_debt`].
    ///
    /// The seek is charged whatever the run holds, because walking the
    /// layers and the base is what an empty one costs too.
    fn lift(
        &mut self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        cap: u32,
    ) -> Result<Vec<(u128, Vec<u8>)>, SessionTrap> {
        let entries = self
            .store
            .entries_in_range(owner, collection, lo, hi, cap)?;
        let lifted = entries.iter().fold(SCAN_SEEK_BYTES, |total, (_, value)| {
            total
                .saturating_add(AMOUNT_CELL_BYTES)
                .saturating_add(value.len())
        });
        self.ranges.scanned = self.ranges.scanned.saturating_add(lifted);
        Ok(entries)
    }

    /// Whether one entry is there, on the same terms a page is read.
    fn probe(
        &mut self,
        owner: Address,
        collection: CollectionId,
        order: u128,
    ) -> Result<bool, SessionTrap> {
        Ok(!self.lift(owner, collection, order, order, 1)?.is_empty())
    }

    /// Materialize the interval behind `rep` if it is not already.
    fn scan(&mut self, rep: u32) -> Result<(), SessionTrap> {
        if self.ranges.scans.contains_key(&rep) {
            return Ok(());
        }
        let interval = self.interval(rep)?;
        let entries = self.lift(
            interval.owner,
            interval.collection,
            interval.lo,
            interval.hi,
            interval.cap,
        )?;
        self.ranges.scans.insert(rep, entries);
        Ok(())
    }

    /// What interval scans have lifted out of the store since this was
    /// last asked, in the boundary-byte terms the fuel schedule prices.
    ///
    /// Called by whoever holds the fuel budget, after every host call
    /// that can reach a scan. [`Self::finish`] refuses a session that
    /// still owes, so an accessor added later cannot quietly scan for
    /// free — it fails every test that runs it.
    pub const fn take_scan_debt(&mut self) -> usize {
        std::mem::replace(&mut self.ranges.scanned, 0)
    }

    /// Charge one entry against `rep`'s declared write cap.
    ///
    /// The budget counts distinct orders rather than operations: writing
    /// an entry this interval already changed is the same entry touched
    /// again, and the cap bounds how much of the collection a declaration
    /// reaches, not how many times a guest reaches it.
    fn charge_write(&mut self, rep: u32, order: u128, cap: u32) -> Result<(), SessionTrap> {
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let written = self.ranges.written.entry(rep).or_default();
        if !written.contains(&order) && written.len() >= cap {
            return Err(SessionTrap::WriteCapExceeded {
                cap: u32::try_from(cap).unwrap_or(u32::MAX),
                order,
            });
        }
        written.insert(order);
        Ok(())
    }

    /// Drop every materialized interval over a collection a write touched.
    fn invalidate(&mut self, owner: Address, collection: CollectionId) {
        let stale: Vec<u32> = self
            .ranges
            .scans
            .keys()
            .copied()
            .filter(|rep| {
                self.interval(*rep)
                    .is_ok_and(|scanned| scanned.owner == owner && scanned.collection == collection)
            })
            .collect();
        for rep in stale {
            self.ranges.scans.remove(&rep);
        }
    }

    /// Entries currently visible in the interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_count(&mut self, rep: u32) -> Result<u32, SessionTrap> {
        self.scan(rep)?;
        Ok(u32::try_from(self.ranges.scans[&rep].len()).unwrap_or(u32::MAX))
    }

    /// The order key at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, SessionTrap> {
        self.scan(rep)?;
        indexed(&self.ranges.scans[&rep], index).map(|(order, _)| *order)
    }

    /// The entry value at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, SessionTrap> {
        self.scan(rep)?;
        indexed(&self.ranges.scans[&rep], index).map(|(_, value)| value.clone())
    }

    /// Replace the entry value at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), SessionTrap> {
        let interval = self.write_interval(rep)?;
        self.scan(rep)?;
        let order = *indexed(&self.ranges.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_write(interval.owner, interval.collection, order, value)?;
        self.invalidate(interval.owner, interval.collection);
        Ok(())
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
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let interval = self.write_interval(rep)?;
        if !interval.holds(order) {
            return Err(SessionTrap::OrderOutsideInterval);
        }
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_write(interval.owner, interval.collection, order, value)?;
        self.invalidate(interval.owner, interval.collection);
        Ok(())
    }

    /// Remove the entry at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), SessionTrap> {
        let interval = self.write_interval(rep)?;
        self.scan(rep)?;
        let order = *indexed(&self.ranges.scans[&rep], index).map(|(order, _)| order)?;
        self.charge_write(rep, order, interval.cap)?;
        self.store
            .entry_remove(interval.owner, interval.collection, order)?;
        self.invalidate(interval.owner, interval.collection);
        Ok(())
    }

    /// Take the named entries of a write interval, as the instances they
    /// were.
    ///
    /// The removal and the edge are one operation, which is what a
    /// movement is for an amount cell and what this is for a collection:
    /// a body cannot hand on instances it left where they were. Naming
    /// none yields an empty bucket, so a method that moves nothing needs
    /// no way to name one.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: a malformed id cell, an id outside the
    /// declared interval, one the collection does not hold, or more
    /// entries than the interval's cap admits.
    pub fn range_take(&mut self, rep: u32, ids: &[u64]) -> Result<u32, SessionTrap> {
        let interval = self.instance_interval(rep)?;
        let resource = self.value_of(rep)?;
        // The decoder refuses a repeated id, so the set below loses
        // nothing to dedup and a count is an instance count.
        let ids = distinct_ids(ids).ok_or(SessionTrap::MalformedIdSet)?;
        // Every entry is charged and removed, or none is: the budget is
        // what the declaration bought, and a take that overran it must
        // leave the collection alone.
        let mut taken = BTreeSet::new();
        for id in ids {
            let order = u128::from(id);
            if !interval.holds(order) {
                return Err(SessionTrap::OrderOutsideInterval);
            }
            // Asked at the instance's own key rather than of the
            // interval's page. The cap bounds how many entries execution
            // may touch, and a take names at most an edge's worth — so
            // answering from a page would make reachability a function of
            // how many lower-ordered instances sit in front of this one,
            // and a holder past the cap could never move its later ids.
            let held = self.probe(interval.owner, interval.collection, order)?;
            if !held {
                return Err(SessionTrap::InstanceNotHeld(order));
            }
            self.charge_write(rep, order, interval.cap)?;
            taken.insert(order);
        }
        for order in &taken {
            self.store
                .entry_remove(interval.owner, interval.collection, *order)?;
        }
        self.invalidate(interval.owner, interval.collection);
        Ok(self.open_bucket(Held::Instances(taken), resource))
    }

    /// File every instance the bucket at `funds` carries as an entry of a
    /// write interval, at the order it was taken under.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: an instance outside the declared interval, a
    /// bucket carrying an amount, or a cap the filing would overrun.
    pub fn range_put(&mut self, rep: u32, funds: u32, value: &[u8]) -> Result<(), SessionTrap> {
        let interval = self.instance_interval(rep)?;
        self.judge_credit(rep, funds)?;
        let Held::Instances(ids) = self.bucket(funds)? else {
            return Err(SessionTrap::WrongEdgeKind);
        };
        for order in &ids {
            if !interval.holds(*order) {
                return Err(SessionTrap::OrderOutsideInterval);
            }
        }
        for order in &ids {
            self.charge_write(rep, *order, interval.cap)?;
        }
        for order in &ids {
            self.store
                .entry_write(interval.owner, interval.collection, *order, value.to_vec())?;
        }
        self.invalidate(interval.owner, interval.collection);
        self.take_bucket(funds).map(|_| ())
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_effects::Declaration;
    use hyperscale_vm_types::{
        AMOUNT_CELL_BYTES, Address, AddressClass, CollectionId, Effect, EffectTarget, Mode,
    };

    use super::super::fixtures::{declared, env, hash, holding, session_holding, session_over, tx};
    use super::{Held, KernelSession, SCAN_SEEK_BYTES, SessionTrap};
    use crate::overlay::OverlayStore;
    use crate::store::MemoryStore;

    #[test]
    fn interval_operations_bound_their_index_and_order() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        store.entry_write(owner, collection, 10, vec![1]).unwrap();
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 5,
                hi: 15,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(1));
        assert_eq!(session.range_entry(0, 0), Ok(vec![1]));
        assert_eq!(
            session.range_entry(0, 1),
            Err(SessionTrap::IndexOutOfBounds { index: 1, count: 1 })
        );
        assert_eq!(
            session.range_remove(0, 9),
            Err(SessionTrap::IndexOutOfBounds { index: 9, count: 1 })
        );
        // An insert must land inside the declared interval, and its order
        // key is an amount cell like any other.
        assert_eq!(
            session.range_insert(0, 99, vec![2]),
            Err(SessionTrap::OrderOutsideInterval)
        );
        assert_eq!(session.range_insert(0, 12, vec![2]), Ok(()));
        assert_eq!(session.range_count(0), Ok(2));
    }

    #[test]
    fn a_write_interval_bounds_the_entries_it_adds_by_its_cap() {
        // Nothing truncates a write the way a scan truncates a read, so
        // the cap has to refuse: a declaration claiming two entries must
        // not be able to grow the collection without bound.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 2,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        assert_eq!(session.range_insert(0, 10, vec![1]), Ok(()));
        assert_eq!(session.range_insert(0, 20, vec![2]), Ok(()));
        assert_eq!(
            session.range_insert(0, 30, vec![3]),
            Err(SessionTrap::WriteCapExceeded { cap: 2, order: 30 }),
            "a third distinct entry is past the declared cap"
        );

        // Rewriting an entry the interval already changed is the same
        // entry touched again, not a new one.
        assert_eq!(session.range_insert(0, 10, vec![9]), Ok(()));
    }

    #[test]
    fn the_write_budget_survives_a_scan_invalidation() {
        // A write drops the materialized interval, and the budget must not
        // come back with it — otherwise re-scanning between writes buys an
        // unbounded number of them.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 1,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);

        assert_eq!(session.range_insert(0, 10, vec![1]), Ok(()));
        assert_eq!(
            session.range_count(0),
            Ok(1),
            "re-materializes the interval"
        );
        assert_eq!(
            session.range_insert(0, 20, vec![2]),
            Err(SessionTrap::WriteCapExceeded { cap: 1, order: 20 }),
        );
    }

    #[test]
    fn a_full_page_of_read_modify_writes_fits_its_cap() {
        // The order book's fill: scan the cap and rewrite or remove every
        // entry it returned. The write budget is the cap, and reads are
        // truncated at it separately, so the pattern sits exactly inside
        // the declaration rather than being refused by it.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store
                .entry_write(owner, collection, order, vec![u8::try_from(order).unwrap()])
                .unwrap();
        }
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(4));
        for index in 0..4 {
            assert_eq!(session.range_set(0, index, vec![0xFF]), Ok(()));
        }
        // And removing what it just rewrote reaches no new entry.
        assert_eq!(session.range_remove(0, 0), Ok(()));
    }

    #[test]
    fn a_re_materialized_page_is_charged_again() {
        // The write budget survives an invalidation, so the loop that
        // re-scans between writes is reachable; what stops it being free
        // is that each page costs what it lifts.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store
                .entry_write(owner, collection, order, vec![7; 10])
                .unwrap();
        }
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_over(store, &set);

        assert_eq!(session.range_count(0), Ok(4));
        let page = SCAN_SEEK_BYTES + 4 * (AMOUNT_CELL_BYTES + 10);
        assert_eq!(session.take_scan_debt(), page);
        // Drained, and a memoized page is not scanned twice.
        assert_eq!(session.range_count(0), Ok(4));
        assert_eq!(session.take_scan_debt(), 0);
        // A write drops the page, and asking for it again buys another.
        assert_eq!(session.range_set(0, 0, vec![8; 10]), Ok(()));
        assert_eq!(session.range_count(0), Ok(4));
        assert_eq!(session.take_scan_debt(), page);
    }

    /// Scan debt is priced fuel, so which pages a write drops is
    /// consensus-visible: a write into one collection must not buy the
    /// re-materialization of another's page.
    #[test]
    fn a_write_invalidates_only_its_own_collection() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let (held, other) = (CollectionId([1; 16]), CollectionId([2; 16]));
        let mut store = MemoryStore::new();
        store.entry_write(owner, held, 1, vec![7]).unwrap();
        let interval = |collection| Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        };
        // The clause order pins the reps: 0 reads the held collection,
        // 1 writes the other.
        let set = declared(&[interval(held), interval(other)]);
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: holding(&[interval(held), interval(other)]),
                ..Declaration::default()
            },
            tx(1),
            env(),
            hash,
        )
        .expect("two write intervals materialize");

        assert_eq!(session.range_count(0), Ok(1));
        assert!(session.take_scan_debt() > 0, "the page was lifted");
        assert_eq!(session.range_insert(1, 5, vec![1]), Ok(()));
        assert_eq!(session.range_count(0), Ok(1));
        assert_eq!(session.take_scan_debt(), 0, "the cached page survives");
    }

    #[test]
    fn a_take_reaches_every_instance_the_interval_declares() {
        // A holder past the cap keeps its later ids: the cap bounds the
        // entries a take may touch, never which of them it can name.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..100u128 {
            store
                .entry_write(owner, collection, order, vec![1])
                .unwrap();
        }
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 4,
            },
            mode: Mode::Write,
        }]);
        let mut session = session_holding(store, &set);

        // An id well past the first page of four.
        assert_eq!(session.range_take(0, &[90]), Ok(0));
        assert_eq!(session.bucket(0), Ok(Held::Instances([90].into())));
        // And one the collection does not hold still refuses.
        assert_eq!(
            session.range_take(0, &[500]),
            Err(SessionTrap::InstanceNotHeld(500))
        );
        // The cap is the budget it always was: three more distinct
        // entries fit, a fourth does not.
        assert!(session.range_take(0, &[91, 92, 93]).is_ok());
        assert_eq!(
            session.range_take(0, &[94]),
            Err(SessionTrap::WriteCapExceeded { cap: 4, order: 94 })
        );
    }

    #[test]
    fn a_read_interval_refuses_every_mutation() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 10,
                cap: 4,
            },
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(
            session.range_set(0, 0, vec![1]),
            Err(SessionTrap::WrongMode(0))
        );
        assert_eq!(
            session.range_insert(0, 1, vec![1]),
            Err(SessionTrap::WrongMode(0))
        );
        assert_eq!(session.range_remove(0, 0), Err(SessionTrap::WrongMode(0)));
    }
}
