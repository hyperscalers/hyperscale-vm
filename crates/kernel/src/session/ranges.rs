//! The interval machinery: materialized scans, the scan-debt accounting
//! behind boundary pricing, and the write-cap budget.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::{SCAN_SEEK_ENTRIES, distinct_ids};
use hyperscale_vm_types::{AMOUNT_CELL_BYTES, Address, CollectionId};

use super::{Capability, Held, Interval, KernelSession, Op, SessionTrap};
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

/// One materialized page, and what has been learned about it.
#[derive(Debug)]
struct Scan {
    /// The entries the page holds, ascending.
    entries: Vec<(u128, Vec<u8>)>,
    /// Whether the page covers its interval, once asked. Memoized here
    /// rather than beside the page so the answer cannot outlive the
    /// entries it describes: whatever drops the page drops it.
    covered: Option<bool>,
}

/// The session's interval state: what scans have materialized, what they
/// still owe, and what each write interval has spent of its cap.
#[derive(Debug, Default)]
pub(super) struct Ranges {
    /// Materialized interval contents per handle, dropped when a write
    /// touches the collection. A guest walking an interval asks for its
    /// length and then each entry in turn; re-scanning per question makes
    /// that walk quadratic in the interval and floods the access log with
    /// one record per step.
    scans: BTreeMap<(u32, u32), Scan>,
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
    written: BTreeMap<(u32, u32), BTreeSet<u128>>,
}

impl Ranges {
    /// What the scans still owe the fuel budget, in boundary bytes.
    pub(super) const fn owing(&self) -> usize {
        self.scanned
    }
}

impl KernelSession {
    /// The interval an operation acts over, once its capability has been
    /// held to it.
    ///
    /// Every interval operation asks through here, so which modes admit
    /// a walk and which admit a rewrite is the permission table's answer
    /// rather than a check restated at each of them — and an operation
    /// added later cannot forget to ask, because there is no other way to
    /// reach the interval it would act on.
    ///
    /// The point arms are unreachable — no operation admitting an
    /// interval is granted by a point capability — and answer as the
    /// refusal they would be rather than as a panic.
    fn acting_interval(
        &self,
        site: u32,
        element: u32,
        attempted: Op,
    ) -> Result<Interval, SessionTrap> {
        match self.acting(site, element, attempted)? {
            Capability::RangeRead(interval)
            | Capability::RangeWrite(interval)
            | Capability::InstanceRange(interval) => Ok(interval),
            held => Err(SessionTrap::WrongMode {
                site,
                element,
                held,
                attempted,
            }),
        }
    }

    /// The interval a walk reads over, whichever mode carries it.
    fn interval(&self, site: u32, element: u32) -> Result<Interval, SessionTrap> {
        self.acting_interval(site, element, Op::ReadEntries)
    }

    /// The interval a byte-writing handle names.
    fn write_interval(&self, site: u32, element: u32) -> Result<Interval, SessionTrap> {
        self.acting_interval(site, element, Op::WriteEntries)
    }

    /// The interval an instance-moving handle names — the same
    /// statement as [`Self::write_interval`], for the entries that are
    /// value rather than bytes.
    fn instance_interval(&self, site: u32, element: u32) -> Result<Interval, SessionTrap> {
        self.acting_interval(site, element, Op::MoveInstances)
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
    fn scan(&mut self, site: u32, element: u32) -> Result<(), SessionTrap> {
        if self.ranges.scans.contains_key(&(site, element)) {
            return Ok(());
        }
        let interval = self.interval(site, element)?;
        let entries = self.lift(
            interval.owner,
            interval.collection,
            interval.lo,
            interval.hi,
            interval.cap,
        )?;
        self.ranges.scans.insert(
            (site, element),
            Scan {
                entries,
                covered: None,
            },
        );
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
    fn charge_write(
        &mut self,
        site: u32,
        element: u32,
        order: u128,
        cap: u32,
    ) -> Result<(), SessionTrap> {
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let written = self.ranges.written.entry((site, element)).or_default();
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
        let stale: Vec<(u32, u32)> = self
            .ranges
            .scans
            .keys()
            .copied()
            .filter(|(site, element)| {
                self.interval(*site, *element)
                    .is_ok_and(|scanned| scanned.owner == owner && scanned.collection == collection)
            })
            .collect();
        for key in stale {
            self.ranges.scans.remove(&key);
        }
    }

    /// Entries currently visible in the interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_count(&mut self, site: u32, element: u32) -> Result<u32, SessionTrap> {
        self.scan(site, element)?;
        Ok(u32::try_from(self.ranges.scans[&(site, element)].entries.len()).unwrap_or(u32::MAX))
    }

    /// Whether the materialized page holds every entry the interval
    /// does.
    ///
    /// A page shorter than its cap exhausted the interval, and answers
    /// by itself. A full page proves nothing about what lies past it,
    /// so the last entry's successor is probed — one more seek inside
    /// the declared key space, charged to scan debt like the page was —
    /// and the page covered the interval exactly when nothing is there.
    /// Under a cap of zero the page is empty and the probe runs from
    /// the interval's own floor, so coverage is the interval's
    /// emptiness. Memoized with the page, so a repeated ask answers
    /// like a repeated count: from what was already paid for.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_covered(&mut self, site: u32, element: u32) -> Result<bool, SessionTrap> {
        self.scan(site, element)?;
        let interval = self.interval(site, element)?;
        let page = &self.ranges.scans[&(site, element)];
        if let Some(covered) = page.covered {
            return Ok(covered);
        }
        let short = page.entries.len() < usize::try_from(interval.cap).unwrap_or(usize::MAX);
        let resume = match page.entries.last() {
            _ if short => None,
            Some((last, _)) if *last == interval.hi => None,
            Some((last, _)) => Some(last + 1),
            None => Some(interval.lo),
        };
        let covered = match resume {
            None => true,
            Some(resume) => self
                .lift(interval.owner, interval.collection, resume, interval.hi, 1)?
                .is_empty(),
        };
        if let Some(page) = self.ranges.scans.get_mut(&(site, element)) {
            page.covered = Some(covered);
        }
        Ok(covered)
    }

    /// The order key at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_order(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
    ) -> Result<u128, SessionTrap> {
        self.scan(site, element)?;
        indexed(&self.ranges.scans[&(site, element)].entries, index).map(|(order, _)| *order)
    }

    /// The entry value at `index`, ascending.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_entry(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
    ) -> Result<Vec<u8>, SessionTrap> {
        self.scan(site, element)?;
        indexed(&self.ranges.scans[&(site, element)].entries, index).map(|(_, value)| value.clone())
    }

    /// Replace the entry value at `index` through a write interval.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn range_set(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let interval = self.write_interval(site, element)?;
        self.scan(site, element)?;
        let order = *indexed(&self.ranges.scans[&(site, element)].entries, index)
            .map(|(order, _)| order)?;
        self.charge_write(site, element, order, interval.cap)?;
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
        site: u32,
        element: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let interval = self.write_interval(site, element)?;
        if !interval.holds(order) {
            return Err(SessionTrap::OrderOutsideInterval);
        }
        self.charge_write(site, element, order, interval.cap)?;
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
    pub fn range_remove(&mut self, site: u32, element: u32, index: u32) -> Result<(), SessionTrap> {
        let interval = self.write_interval(site, element)?;
        self.scan(site, element)?;
        let order = *indexed(&self.ranges.scans[&(site, element)].entries, index)
            .map(|(order, _)| order)?;
        self.charge_write(site, element, order, interval.cap)?;
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
    pub fn range_take(&mut self, site: u32, element: u32, ids: &[u64]) -> Result<u32, SessionTrap> {
        let interval = self.instance_interval(site, element)?;
        let resource = self.value_of(site, element)?;
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
            self.charge_write(site, element, order, interval.cap)?;
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
    /// bucket carrying an amount, a cap the filing would overrun, or an
    /// order the collection already holds.
    pub fn range_put(
        &mut self,
        site: u32,
        element: u32,
        funds: u32,
        value: &[u8],
    ) -> Result<(), SessionTrap> {
        let interval = self.instance_interval(site, element)?;
        self.judge_credit(site, element, funds)?;
        let Held::Instances(ids) = self.bucket(funds)? else {
            return Err(SessionTrap::WrongEdgeKind);
        };
        for order in &ids {
            if !interval.holds(*order) {
                return Err(SessionTrap::OrderOutsideInterval);
            }
        }
        // Charged before probing, so a filing that overruns its cap is
        // refused without paying for the seeks it would have taken.
        for order in &ids {
            self.charge_write(site, element, *order, interval.cap)?;
        }
        // An instance arrives or it does not. Filing over an order the
        // collection already holds leaves one instance in two places and
        // the entry count unmoved — so what a receipt reports as an
        // arrival would be a rewrite, and the id would exist twice.
        //
        // Asked at each instance's own key, for the reason a take asks
        // there: a page answers only for the orders ahead of the cap, so
        // a collection deep enough could be filed with an id it already
        // had.
        for order in &ids {
            if self.probe(interval.owner, interval.collection, *order)? {
                return Err(SessionTrap::InstanceHeldTwice(*order));
            }
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

    use super::super::fixtures::{
        RESOURCE, declared, env, hash, holding, session_holding, session_over, tx,
    };
    use super::{Held, KernelSession, Op, SCAN_SEEK_BYTES, SessionTrap};
    use crate::overlay::OverlayStore;
    use crate::store::MemoryStore;

    #[test]
    fn interval_operations_bound_their_index_and_order() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        store.entry_write(owner, collection, 10, vec![1]);
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

        assert_eq!(session.range_count(0, 0), Ok(1));
        assert_eq!(session.range_entry(0, 0, 0), Ok(vec![1]));
        assert_eq!(
            session.range_entry(0, 0, 1),
            Err(SessionTrap::IndexOutOfBounds { index: 1, count: 1 })
        );
        assert_eq!(
            session.range_remove(0, 0, 9),
            Err(SessionTrap::IndexOutOfBounds { index: 9, count: 1 })
        );
        // An insert must land inside the declared interval, and its order
        // key is an amount cell like any other.
        assert_eq!(
            session.range_insert(0, 0, 99, vec![2]),
            Err(SessionTrap::OrderOutsideInterval)
        );
        assert_eq!(session.range_insert(0, 0, 12, vec![2]), Ok(()));
        assert_eq!(session.range_count(0, 0), Ok(2));
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

        assert_eq!(session.range_insert(0, 0, 10, vec![1]), Ok(()));
        assert_eq!(session.range_insert(0, 0, 20, vec![2]), Ok(()));
        assert_eq!(
            session.range_insert(0, 0, 30, vec![3]),
            Err(SessionTrap::WriteCapExceeded { cap: 2, order: 30 }),
            "a third distinct entry is past the declared cap"
        );

        // Rewriting an entry the interval already changed is the same
        // entry touched again, not a new one.
        assert_eq!(session.range_insert(0, 0, 10, vec![9]), Ok(()));
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

        assert_eq!(session.range_insert(0, 0, 10, vec![1]), Ok(()));
        assert_eq!(
            session.range_count(0, 0),
            Ok(1),
            "re-materializes the interval"
        );
        assert_eq!(
            session.range_insert(0, 0, 20, vec![2]),
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
            store.entry_write(owner, collection, order, vec![u8::try_from(order).unwrap()]);
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

        assert_eq!(session.range_count(0, 0), Ok(4));
        for index in 0..4 {
            assert_eq!(session.range_set(0, 0, index, vec![0xFF]), Ok(()));
        }
        // And removing what it just rewrote reaches no new entry.
        assert_eq!(session.range_remove(0, 0, 0), Ok(()));
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
            store.entry_write(owner, collection, order, vec![7; 10]);
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

        assert_eq!(session.range_count(0, 0), Ok(4));
        let page = SCAN_SEEK_BYTES + 4 * (AMOUNT_CELL_BYTES + 10);
        assert_eq!(session.take_scan_debt(), page);
        // Drained, and a memoized page is not scanned twice.
        assert_eq!(session.range_count(0, 0), Ok(4));
        assert_eq!(session.take_scan_debt(), 0);
        // A write drops the page, and asking for it again buys another.
        assert_eq!(session.range_set(0, 0, 0, vec![8; 10]), Ok(()));
        assert_eq!(session.range_count(0, 0), Ok(4));
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
        store.entry_write(owner, held, 1, vec![7]);
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

        assert_eq!(session.range_count(0, 0), Ok(1));
        assert!(session.take_scan_debt() > 0, "the page was lifted");
        assert_eq!(session.range_insert(1, 0, 5, vec![1]), Ok(()));
        assert_eq!(session.range_count(0, 0), Ok(1));
        assert_eq!(session.take_scan_debt(), 0, "the cached page survives");
    }

    /// An instance arrives or it does not.
    ///
    /// A collection already holding an order refuses the filing rather
    /// than writing over it. An overwrite would leave the id in two
    /// places while the entries — which is what says how many arrived —
    /// stayed as they were, so the one thing a receipt reports about an
    /// instance would stop being true of it.
    #[test]
    fn filing_over_an_order_the_collection_holds_is_refused() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        // Deep enough that the contested id sits well past the cap,
        // which is where answering from a page would have missed it.
        for order in 0..100u128 {
            store.entry_write(owner, collection, order, vec![1]);
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

        let carried = session.open_bucket(Held::Instances([90].into()), RESOURCE);
        assert_eq!(
            session.range_put(0, 0, carried, &[1]),
            Err(SessionTrap::InstanceHeldTwice(90))
        );

        // An order it does not hold still files, so what the probe
        // refuses is the collision and not the filing.
        let fresh = session.open_bucket(Held::Instances([500].into()), RESOURCE);
        assert_eq!(session.range_put(0, 0, fresh, &[1]), Ok(()));
    }

    #[test]
    fn a_take_reaches_every_instance_the_interval_declares() {
        // A holder past the cap keeps its later ids: the cap bounds the
        // entries a take may touch, never which of them it can name.
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..100u128 {
            store.entry_write(owner, collection, order, vec![1]);
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
        assert_eq!(session.range_take(0, 0, &[90]), Ok(0));
        assert_eq!(session.bucket(0), Ok(Held::Instances([90].into())));
        // And one the collection does not hold still refuses.
        assert_eq!(
            session.range_take(0, 0, &[500]),
            Err(SessionTrap::InstanceNotHeld(500))
        );
        // The cap is the budget it always was: three more distinct
        // entries fit, a fourth does not.
        assert!(session.range_take(0, 0, &[91, 92, 93]).is_ok());
        assert_eq!(
            session.range_take(0, 0, &[94]),
            Err(SessionTrap::WriteCapExceeded { cap: 4, order: 94 })
        );
    }

    /// Coverage is exact, not conservative: a page with headroom proves
    /// the interval exhausted, and a full page is answered by probing
    /// the last entry's successor rather than declined outright.
    #[test]
    fn coverage_is_proved_by_headroom_or_by_the_probe() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store.entry_write(owner, collection, order, vec![1]);
        }
        let at_cap = |cap| {
            declared(&[Effect {
                target: EffectTarget::Range {
                    owner,
                    collection,
                    lo: 0,
                    hi: u128::MAX,
                    cap,
                },
                mode: Mode::Read,
            }])
        };
        let covered = |cap| {
            session_over(store.clone(), &at_cap(cap))
                .range_covered(0, 0)
                .unwrap()
        };
        // Headroom is the cheap proof: five saw four and stopped short.
        assert!(covered(5));
        // A full page of four still covers, by the probe: nothing sits
        // past the fourth entry.
        assert!(covered(4));
        // A full page of three does not: the probe finds the fourth.
        assert!(!covered(3));
        // A cap of zero materializes nothing, so coverage is the
        // interval's emptiness — and this one holds entries.
        assert!(!covered(0));
    }

    /// A repeated coverage ask answers from the memo — the probe is
    /// paid once per page — and a write drops the memo with the page
    /// it describes, so the next ask sees the new truth.
    #[test]
    fn coverage_is_memoized_with_its_page() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store.entry_write(owner, collection, order, vec![1]);
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

        // A full page: the answer costs a page and a probe.
        assert!(session.range_covered(0, 0).unwrap());
        assert!(session.take_scan_debt() > 0);
        // Asked again, it answers from the memo and lifts nothing.
        assert!(session.range_covered(0, 0).unwrap());
        assert_eq!(session.take_scan_debt(), 0);
        // A write drops the page and the memo with it: a fifth entry
        // past the cap turns the same question false.
        assert_eq!(session.range_insert(0, 0, 10, vec![2]), Ok(()));
        assert!(!session.range_covered(0, 0).unwrap());
        assert!(session.take_scan_debt() > 0, "the new page was paid for");
    }

    /// A full page whose last entry sits on the interval's own upper
    /// bound needs no probe: nothing inside the claim can lie past it.
    #[test]
    fn a_page_ending_on_the_bound_is_covered_without_a_probe() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let mut store = MemoryStore::new();
        for order in 0..4u128 {
            store.entry_write(owner, collection, order, vec![1]);
        }
        let set = declared(&[Effect {
            target: EffectTarget::Range {
                owner,
                collection,
                lo: 0,
                hi: 3,
                cap: 4,
            },
            mode: Mode::Read,
        }]);
        let mut session = session_over(store, &set);
        assert!(session.range_covered(0, 0).unwrap());
    }

    /// An empty interval is covered at any cap — including zero, where
    /// the question degenerates to "is anything there".
    #[test]
    fn an_empty_interval_is_covered_at_any_cap() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let at_cap = |cap| {
            declared(&[Effect {
                target: EffectTarget::Range {
                    owner,
                    collection: CollectionId([4; 16]),
                    lo: 0,
                    hi: u128::MAX,
                    cap,
                },
                mode: Mode::Read,
            }])
        };
        for cap in [0, 4] {
            let mut session = session_over(MemoryStore::new(), &at_cap(cap));
            assert!(session.range_covered(0, 0).unwrap());
        }
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
        for outcome in [
            session.range_set(0, 0, 0, vec![1]),
            session.range_insert(0, 0, 1, vec![1]),
            session.range_remove(0, 0, 0),
        ] {
            assert!(matches!(
                outcome,
                Err(SessionTrap::WrongMode {
                    attempted: Op::WriteEntries,
                    ..
                })
            ));
        }
    }
}
