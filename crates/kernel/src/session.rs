//! The per-transaction kernel session: capability materialization, the
//! mode operations behind the world's handles, and the receipt.
//!
//! A session is built from a declared effect set. Materialization turns
//! each declared effect into one [`Capability`], judging and holding
//! reservations as it goes, so an infeasible reservation aborts before
//! any guest runs. What the runtimes' handle reps index is the *site*
//! table beside it: one site per handle parameter, each covering the
//! elements the declaration resolved, and each element naming a position
//! in the capability table. During execution
//! the engines' host adapters delegate every world operation here; each
//! refusal is a deterministic message, identical on every replica because
//! the session itself generates it on both runtimes.
//!
//! [`KernelSession::finish`] is where the trace-subset oracle stands
//! permanently: it folds queued deltas, settles this transaction's
//! reservations, verifies every recorded access against the declared set,
//! and only then produces the receipt — outcome, state delta, fuel.
//!
//! The five machines a session interleaves each live beside it:
//! [`materialize`] judges the declaration into the capability table,
//! [`grants`] decides what each capability grants, [`buckets`] is the
//! linearity ledger for value in flight, [`ranges`] holds the interval
//! scan cache and its budgets, and [`receipt`] folds what committed.
//! Beside them sit two subjects that are not machines: [`trap`], the
//! refusal vocabulary and its abort classes, and [`seal`], the
//! commitment a cell can carry.

mod buckets;
#[cfg(test)]
mod fixtures;
mod grants;
mod materialize;
mod ranges;
mod receipt;
mod seal;
mod trap;

use std::collections::BTreeSet;

use buckets::Buckets;
pub use buckets::Held;
pub use grants::{Op, grants};
use hyperscale_vm_effects::{IssuanceGrant, ResourceKind, distinct_ids};
use hyperscale_vm_types::{
    ABSENT_REP, Address, EffectSet, EffectTarget, ResourceAddr, SeedWindow, SubstateKey, TxHash,
};
// The emission caps and the event record are the shared vocabulary: the
// same constants bound the kernel's emission here and the wire's decode in
// the consensus workspace, so the two cannot drift.
use hyperscale_vm_types::{Event, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX};
pub use materialize::{Capability, Interval, MaterializeError, Settlement};
use ranges::Ranges;
pub use ranges::SCAN_SEEK_BYTES;
pub use receipt::{DeltaMap, FinishError, Receipt, StateDelta};
pub use seal::DOMAIN_SEALED_DRAW;
pub use trap::SessionTrap;

use crate::ledger::AmountLedger;
use crate::locality::Locality;
use crate::modes::{DeltaOp, decode_amount};
use crate::overlay::OverlayStore;
use crate::store::WorkingStore;
use crate::supply::SupplyDelta;

/// The deterministic environment a transaction executes under.
#[derive(Clone, Debug)]
pub struct EnvInputs {
    /// The transaction clock in milliseconds.
    pub clock_ms: u64,
    /// The epoch this transaction executes in — what a seal records.
    pub epoch: u64,
    /// The epochs a sealed draw can resolve against, and the frontier
    /// separating one that has not happened from one that happened
    /// unusably.
    pub seeds: SeedWindow,
}

impl EnvInputs {
    /// An environment no seal can open: a clock, over a window nothing
    /// has folded into.
    ///
    /// For callers with no seal in sight. A consensus path states its
    /// window, on the same terms it states its clock — what a seal
    /// resolves to is an execution input, and one that defaulted would
    /// be a wrong answer nothing would catch.
    #[must_use]
    pub const fn unsealed(clock_ms: u64) -> Self {
        Self {
            clock_ms,
            epoch: 0,
            seeds: SeedWindow::unfolded(),
        }
    }
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
    locality: Locality,
    /// The subintent cells committing spends, from the batch entry.
    ///
    /// Held here rather than written by the caller because spending is
    /// part of committing: the write belongs in the layer the rest of
    /// the transaction wrote into, so it merges or discards with it.
    nullifiers: Vec<SubstateKey>,
    /// The interval machinery: materialized scans, scan debt, write caps.
    ranges: Ranges,
    /// The instance whose method is executing, set by the runner as it
    /// enters each manifest node. The capability table is per transaction
    /// and positional, so the session has no other way to know whose
    /// invocation an emission belongs to.
    invocation: Option<Address>,
    /// Events emitted so far, kept until the outcome is known: an abort
    /// discards them, so nothing an aborted transaction said survives.
    events: Vec<Event>,
    /// What each capability's cell holds, by the same rep the capability
    /// table uses; `None` where the cell holds no value.
    ///
    /// The declaration's answer, carried here because the kernel's own is
    /// a hashed key it cannot invert. What it buys is that a movement can
    /// be judged against the resource its cell is denominated in without
    /// trusting anything the transaction said about which parameter went
    /// where — so a package whose metadata was authored rather than
    /// derived is held to the same rule as one the tracer wrote.
    cell_resources: Vec<Option<ResourceAddr>>,
    /// The linearity ledger for value in flight; see [`buckets`].
    buckets: Buckets,
    /// What this transaction brought into and out of existence, by
    /// resource.
    ///
    /// Accumulated as the operations happen rather than derived at the
    /// end, because the grant that authorised each one is gone by then:
    /// entering the next node takes it away, and the resource with it.
    supply: SupplyDelta,
    /// Whether the executing invocation may create value.
    ///
    /// One entry per issuance the running method declares, in the order
    /// its signature declares them — which is the index a body names.
    ///
    /// A list rather than one grant because a component founds every
    /// resource it declares in the one call that makes it actual, and a
    /// single ambient grant would let it found exactly one. Each carries
    /// which way it goes: a body may bring a bucket into existence with
    /// no cell debited behind it, take one out of existence, or both,
    /// and which of those its declaration claimed is what holds it.
    issuance: Vec<IssuanceGrant>,
    /// Every site this invocation can act through, flattened: one entry
    /// per element of each site, in the order they were bound.
    ///
    /// An entry names a position in [`KernelSession::table`], or nothing
    /// where the site's guard did not fire for that element.
    entries: Vec<Option<u32>>,
    /// Where each site's entries start, and how many it has; a site
    /// handle's rep is its index here.
    ///
    /// Materialization seeds one width-one site per capability, in table
    /// order, so **site `n` element 0 is capability `n`** — which is what
    /// lets a session be acted through the moment it exists, rather than
    /// only after a walk has bound something. Sites a `for-each` needs
    /// are appended past the seeded ones.
    sites: Vec<(u32, u32)>,
    /// Reservations already taken, by capability rep.
    ///
    /// A grant answers once. The read this replaces answered every time
    /// it was asked, so a body asking twice held two edges against one
    /// hold; taking is a question with one answer and this is what makes
    /// it so.
    taken: BTreeSet<u32>,
}

impl KernelSession {
    /// Scope the session to the executing shard's keys; see [`Locality`].
    #[must_use]
    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.locality = locality;
        self
    }

    /// The subintent cells a commit spends.
    #[must_use]
    pub fn with_nullifiers(mut self, nullifiers: Vec<SubstateKey>) -> Self {
        self.nullifiers = nullifiers;
        self
    }

    /// The capability table; a handle's rep is its index here.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.table
    }

    /// What the cell behind a capability holds, where it holds value.
    fn cell_resource(&self, site: u32, element: u32) -> Option<ResourceAddr> {
        self.resource_at(self.entry(site, element).ok()??)
    }

    /// What the cell behind one capability holds, by its position in the
    /// table — for the kernel's own walks, which have no site in hand.
    fn resource_at(&self, rep: u32) -> Option<ResourceAddr> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.cell_resources.get(index))
            .copied()
            .flatten()
    }

    /// What the cell behind a capability holds, for a movement through
    /// it.
    ///
    /// The check and the answer are one lookup: a movement needs the
    /// resource, and a cell that does not name one is a cell no value
    /// moves through.
    fn value_of(&self, site: u32, element: u32) -> Result<ResourceAddr, SessionTrap> {
        self.cell_resource(site, element)
            .ok_or(SessionTrap::BytesAsValue { site, element })
    }

    /// Judge a credit: the value going into a cell is the resource that
    /// cell holds, or it does not go in.
    ///
    /// One comparison with nothing to skip. Both sides are known by
    /// construction — a cell a movement reaches was denominated by the
    /// declaration, and a bucket carries what it was made from — so the
    /// question is only whether they agree.
    fn judge_credit(&self, site: u32, element: u32, funds: u32) -> Result<(), SessionTrap> {
        let cell = self.value_of(site, element)?;
        let carried = self.buckets.resource_of(funds)?;
        if cell == carried {
            Ok(())
        } else {
            Err(SessionTrap::WrongResource { cell, carried })
        }
    }

    /// The capability one element of a site names.
    ///
    /// An element the site's guard did not fire for names none, which is
    /// a body whose control flow disagrees with the verdict it was
    /// handed — named rather than folded into an unknown handle because
    /// the diagnostic is the whole value: nothing was materialized here
    /// on purpose.
    fn at(&self, site: u32, element: u32) -> Result<Capability, SessionTrap> {
        let rep = self.rep_at(site, element)?;
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.table.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Where in the table the capability one element names sits.
    ///
    /// The identity a per-capability budget is kept under: two handle
    /// parameters may name one clause, so the site that reached it is
    /// not what a rule about the declaration may key on.
    fn rep_at(&self, site: u32, element: u32) -> Result<u32, SessionTrap> {
        self.entry(site, element)?
            .ok_or(SessionTrap::UndeclaredBranch)
    }

    /// The capability at `rep`, held to the operation it is about to
    /// perform.
    ///
    /// The one place permission is decided. Every operation reaches its
    /// capability through here, so an operation added later cannot act
    /// through a mode that never granted it — there is no other way to
    /// resolve a rep into something to act on.
    fn acting(&self, site: u32, element: u32, attempted: Op) -> Result<Capability, SessionTrap> {
        let held = self.at(site, element)?;
        if grants(&held, attempted) {
            Ok(held)
        } else {
            Err(SessionTrap::Ungranted {
                site,
                element,
                held,
                attempted,
            })
        }
    }

    /// The cell a point operation acts on, once its capability has been
    /// held to it.
    ///
    /// An interval capability has no cell, and no operation admitting one
    /// resolves through here — so the arm answers as the refusal it would
    /// be rather than as a panic, on the terms every other handle refusal
    /// does.
    fn acting_key(
        &self,
        site: u32,
        element: u32,
        attempted: Op,
    ) -> Result<SubstateKey, SessionTrap> {
        let held = self.acting(site, element, attempted)?;
        held.key().ok_or(SessionTrap::Ungranted {
            site,
            element,
            held,
            attempted,
        })
    }

    /// Lend one declared site, answering the rep it is reached at.
    ///
    /// One entry per element, in the order the walk resolved them: a
    /// plain access is a site of one, and a `for-each` site is as wide
    /// as the collection its loop mapped over.
    ///
    /// Always appended, never matched against the seeded sites: a site
    /// the walk binds carries what the *declaration* resolved, which for
    /// a guarded-out clause is an absence no capability stands behind.
    pub fn bind_site(&mut self, entries: Vec<Option<u32>>) -> u32 {
        let rep = u32::try_from(self.sites.len()).unwrap_or(u32::MAX);
        let start = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let len = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        self.entries.extend(entries);
        self.sites.push((start, len));
        rep
    }

    /// The entries the site at `rep` covers.
    fn site(&self, rep: u32) -> Result<&[Option<u32>], SessionTrap> {
        let (start, len) = usize::try_from(rep)
            .ok()
            .and_then(|index| self.sites.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))?;
        let start = start as usize;
        self.entries
            .get(start..start + len as usize)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// How many elements the site covers.
    ///
    /// The element count rather than the count of expansions that fired,
    /// so two sites in one body agree on what an index means and a
    /// guarded one reads absent rather than shortening the walk. A plain
    /// access answers one, declared or not.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] on a rep no site occupies.
    pub fn site_len(&self, rep: u32) -> Result<u32, SessionTrap> {
        Ok(u32::try_from(self.site(rep)?.len()).unwrap_or(u32::MAX))
    }

    /// Whether the site declared anything for the element at `index`.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn site_declared(&self, rep: u32, index: u32) -> Result<bool, SessionTrap> {
        Ok(self.entry(rep, index)?.is_some())
    }

    /// One entry of a site, refusing an index past its elements.
    fn entry(&self, rep: u32, index: u32) -> Result<Option<u32>, SessionTrap> {
        if rep == ABSENT_REP {
            return Err(SessionTrap::UndeclaredBranch);
        }
        let entries = self.site(rep)?;
        usize::try_from(index)
            .ok()
            .and_then(|index| entries.get(index))
            .copied()
            .ok_or(SessionTrap::IndexOutOfBounds {
                index,
                count: entries.len(),
            })
    }

    /// The current value of a declared cell, for the kernel's own gate
    /// reads — the same view a read capability serves, empty meaning
    /// absent. The key comes from the gate admission lowered, which is
    /// the same evaluation that materialized the cell's capability, so
    /// it is declared by construction.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_cell(&mut self, key: SubstateKey) -> Result<Vec<u8>, SessionTrap> {
        Ok(self.store.read(key)?.unwrap_or_default())
    }

    /// Whether the target a declared read names holds anything.
    ///
    /// Presence rather than contents, because that is the whole of what
    /// a credential asks — and for a value cell the two agree, since a
    /// balance reaching zero deletes its leaf. The same read
    /// materialization performs, so a rule mixing presence with evidence
    /// gets the same answer wherever the mix sends it.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`] the store raises.
    pub fn declared_present(&mut self, target: EffectTarget) -> Result<bool, SessionTrap> {
        Ok(materialize::occupied(&mut self.store, target)?)
    }

    /// The bytes this cell holds; empty if absent.
    ///
    /// One read for both byte modes. What the exclusive mode adds is the
    /// writes, so the question a fresh read asks and the question a hold
    /// asks are the same question with the same answer.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, SessionTrap> {
        let key = self.acting_key(site, element, Op::Read)?;
        Ok(self.store.read(key)?.unwrap_or_default())
    }

    /// What an amount cell holds.
    ///
    /// The one question about a balance that moves none of it, and the
    /// reason a value cell needs a read at all: a curve is a function of
    /// its reserves. An absent cell is nothing, and a stored cell that is
    /// not an amount is the state's own defect.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn amount_cell_balance(&mut self, site: u32, element: u32) -> Result<u128, SessionTrap> {
        let key = self.acting_key(site, element, Op::Balance)?;
        self.amount_cell(key)
    }

    /// The write half of a write capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_set(
        &mut self,
        site: u32,
        element: u32,
        value: Vec<u8>,
    ) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Write)?;
        Ok(self.store.write(key, value)?)
    }

    /// The other end of a write capability: the leaf ends rather than
    /// changing.
    ///
    /// What makes a cell's lifetime an ordinary one — created where the
    /// declaration required it absent, ended where the declaration
    /// required it present — so state a package stops needing stops
    /// being state.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn write_cell_clear(&mut self, site: u32, element: u32) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Clear)?;
        self.store.remove(key)?;
        Ok(())
    }

    /// Credit a delta capability with no bucket behind the credit.
    ///
    /// Fixtures only, and gated so it stays that way: value a
    /// transaction hands a cell comes out of the bucket table, and a
    /// credit that skipped it is value from nowhere. Production reaches
    /// the same queue through [`Self::cell_put`], which consumes an
    /// edge to make the credit.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    #[cfg(any(test, feature = "testing"))]
    pub fn delta_add(&mut self, site: u32, element: u32, amount: u128) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Put)?;
        Ok(self.store.queue_delta(key, DeltaOp::Add(amount))?)
    }

    /// Debit a delta capability without producing the edge for it.
    ///
    /// Fixtures only, on the terms [`Self::delta_add`] states.
    /// Production reaches the same queue through [`Self::cell_take`],
    /// which hands the debit out as a bucket.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    #[cfg(any(test, feature = "testing"))]
    pub fn delta_sub(&mut self, site: u32, element: u32, amount: u128) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Take)?;
        Ok(self.store.queue_delta(key, DeltaOp::Sub(amount))?)
    }

    /// The reserved amount behind a reserve capability.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_amount(&mut self, site: u32, element: u32) -> Result<u128, SessionTrap> {
        self.reserved(site, element, Op::ReservedAmount)
    }

    /// The grant a reservation carries, held to the operation asking.
    ///
    /// The clause's own declared amount, not the folded hold: two
    /// reservations on one cell share a single held total, and a guest
    /// asking about its grant means its own share of it. The hold is
    /// still consulted — a capability whose hold never materialized is a
    /// defect whatever amount it declared.
    fn reserved(&self, site: u32, element: u32, attempted: Op) -> Result<u128, SessionTrap> {
        let Capability::Reserve { key, amount } = self.acting(site, element, attempted)? else {
            return Err(SessionTrap::ReservationMissing);
        };
        self.store
            .held_reservation(key, self.tx)
            .map(|_| amount)
            .ok_or(SessionTrap::ReservationMissing)
    }

    /// Debit `amount` from this cell and hand the value out as a bucket.
    ///
    /// What the pairing buys, in either mode, is that the amount debited
    /// and the amount now in flight are one number the body never got to
    /// write twice. When the debit is refused differs: the exclusive hold
    /// performs the read-modify-write and refuses an over-take here,
    /// where the commutative movement queues and leaves the question to
    /// the fold.
    ///
    /// Either way it is what the cell holds, not what it has free. A
    /// reservation standing on the cell is another transaction's doing
    /// and nothing this body can see, so crossing one is judged at the
    /// fold with every other movement's floor — where it is priced as
    /// the lost race it is, rather than as this body's arithmetic.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, SessionTrap> {
        // A credit gave up this direction, which is why the table admits
        // it to the credit and not to the debit.
        let held = self.acting(site, element, Op::Take)?;
        let resource = self.value_of(site, element)?;
        let key = match Self::settling(site, element, held, Op::Take)? {
            // The exclusive hold performs the read-modify-write, so a
            // debit past what the cell holds is refused at the call.
            Settlement::Immediate(key) => {
                self.amount_cell(key)?
                    .checked_sub(amount)
                    .ok_or(SessionTrap::CellUnderflow)?;
                key
            }
            // The commutative movement queues, so whether the cell
            // covered it is the fold's question and an over-take is
            // infeasible at settle rather than a refusal here.
            Settlement::Queued(key) => key,
        };
        self.store.queue_delta(key, DeltaOp::Sub(amount))?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Credit this cell with what the bucket at `funds` carries.
    ///
    /// The bucket is consumed, so the credit and the value that crossed
    /// are one number and there is no second one to disagree with.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn cell_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), SessionTrap> {
        // Nothing is consumed until everything is judged. A refusal
        // aborts the whole transaction, so no state would escape either
        // way; what the ordering keeps true is that the kernel is never
        // holding a credit it did not make, which is the property the
        // bucket table exists to state.
        let held = self.acting(site, element, Op::Put)?;
        self.judge_credit(site, element, funds)?;
        let amount = self.bucket_amount(funds)?;
        let key = match Self::settling(site, element, held, Op::Put)? {
            // The exclusive hold performs the read-modify-write, so a
            // credit past the width an amount has is refused at the call.
            Settlement::Immediate(key) => {
                self.amount_cell(key)?
                    .checked_add(amount)
                    .ok_or(SessionTrap::CellOverflow)?;
                key
            }
            // A credit answers this and a delta answers it too: what the
            // narrower mode gave up is the other direction, not this one.
            Settlement::Queued(key) => key,
        };
        self.store.queue_delta(key, DeltaOp::Add(amount))?;
        self.take_bucket(funds).map(|_| ())
    }

    /// When a movement through the capability just held moves, and
    /// against which cell.
    ///
    /// Only the value modes settle, and only those admit a movement — so
    /// the refusal is unreachable and answers as one rather than as a
    /// panic, on the terms [`Self::acting_key`] states.
    const fn settling(
        site: u32,
        element: u32,
        held: Capability,
        attempted: Op,
    ) -> Result<Settlement, SessionTrap> {
        match held.settlement() {
            Some(settlement) => Ok(settlement),
            None => Err(SessionTrap::Ungranted {
                site,
                element,
                held,
                attempted,
            }),
        }
    }

    /// A declared cell's contents as an amount, as this transaction has
    /// left it; an absent cell is zero.
    fn amount_cell(&mut self, key: SubstateKey) -> Result<u128, SessionTrap> {
        let cell = self.store.read(key)?.unwrap_or_default();
        let committed = if cell.is_empty() {
            0
        } else {
            decode_amount(&cell).map_err(|_| SessionTrap::BadAmountCell(key))?
        };
        Ok(self.store.with_queued(key, committed)?)
    }

    /// Create `amount` of what this invocation issues, as a bucket.
    ///
    /// The one bucket with no cell behind it. What an invocation may
    /// issue is its own grant, read off the issuance its signature
    /// declares, so there is nothing for a body to hold and nothing for
    /// it to name.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint(&mut self, grant: u32, amount: u128) -> Result<u32, SessionTrap> {
        let resource = self.issued(grant, ResourceKind::Fungible)?;
        self.supply.mint(resource, amount)?;
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// Create the named instances of what this invocation issues.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a mint against a grant this
    /// invocation was never given.
    pub fn mint_instances(&mut self, grant: u32, ids: &[u64]) -> Result<u32, SessionTrap> {
        let resource = self.issued(grant, ResourceKind::NonFungible)?;
        let named = distinct_ids(ids).ok_or(SessionTrap::MalformedIdSet)?;
        let instances: BTreeSet<u128> = named.into_iter().map(u128::from).collect();
        // An instance's supply is its existence: what a non-fungible
        // mints is a count, which is what its holdings are measured in.
        self.supply.mint(resource, instances.len() as u128)?;
        Ok(self.open_bucket(Held::Instances(instances), resource))
    }

    /// Destroy what this invocation issues, consuming the bucket.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a burn by an invocation granted
    /// nothing.
    pub fn burn(&mut self, funds: u32) -> Result<(), SessionTrap> {
        // A burn names no grant, and needs none: a mark names one grant,
        // so at most one of this invocation's can be the bucket's. What
        // is refused is value no grant of this invocation covers, which
        // is the same refusal a mint through an index nobody granted
        // meets.
        let carried = self.buckets.resource_of(funds)?;
        let resource = self
            .issuance
            .iter()
            .find(|grant| grant.resource == carried && grant.direction.burns())
            .ok_or(SessionTrap::IssuanceUngranted)?
            .resource;
        let destroyed = self.bucket(funds)?.quantity();
        self.supply.burn(resource, destroyed)?;
        self.take_bucket(funds).map(|_| ())
    }

    /// Grant the executing invocation the issuances its declaration
    /// claimed, in the order it declares them.
    ///
    /// Read off the method's own declaration by whoever entered the node;
    /// entering the next one takes them away again. Whether the caller
    /// was entitled to them is already settled — each resource's own
    /// entry was judged before the body ran — so what this holds a body
    /// to is the narrower question of whether its code does what its
    /// signature said.
    pub fn grant_issuance(&mut self, grants: Vec<IssuanceGrant>) {
        self.issuance = grants;
    }

    /// The resource the grant at `grant` names, held to the kind the
    /// operation creates and to the direction the declaration claimed.
    ///
    /// The grant's address commits its kind, so a mint of the other kind
    /// is not a variant of the resource — it is an operation on a
    /// resource this invocation was never granted. The direction is the
    /// same refusal read the other way: a burn-only declaration was
    /// judged against the burn entry alone, so minting through it is a
    /// right nobody granted. An index past the list is the third form of
    /// the same refusal, since it names no grant at all.
    fn issued(&self, grant: u32, kind: ResourceKind) -> Result<ResourceAddr, SessionTrap> {
        let held = usize::try_from(grant)
            .ok()
            .and_then(|at| self.issuance.get(at))
            .filter(|held| held.direction.mints())
            .ok_or(SessionTrap::IssuanceUngranted)?;
        if held.kind != kind {
            return Err(SessionTrap::WrongIssuanceKind);
        }
        Ok(held.resource)
    }

    /// Take the reservation this capability holds, as a bucket.
    ///
    /// Once per capability: the grant is a quantity the kernel judged and
    /// held before the body ran, and a second answer to the same question
    /// would be a second edge against one hold.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn reserve_take(&mut self, site: u32, element: u32) -> Result<u32, SessionTrap> {
        let amount = self.reserved(site, element, Op::TakeReserved)?;
        let resource = self.value_of(site, element)?;
        // Once per capability rather than once per site: two handle
        // parameters may name one clause, and the grant leaves the
        // kernel once whichever of them asks.
        let rep = self.rep_at(site, element)?;
        if !self.taken.insert(rep) {
            return Err(SessionTrap::ReservationTaken);
        }
        Ok(self.open_bucket(Held::Amount(amount), resource))
    }

    /// The transaction clock in milliseconds.
    #[must_use]
    pub const fn clock_ms(&self) -> u64 {
        self.env.clock_ms
    }

    /// The epoch this transaction executes in.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.env.epoch
    }

    /// The protocol hash function.
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        (self.hash_fn)(data)
    }

    /// Enter an invocation: subsequent emissions are stamped with
    /// `emitter`, the address of the instance whose method runs next.
    ///
    /// The runner calls this as it walks each manifest node, since the
    /// node names its target and the session does not.
    pub fn enter_invocation(&mut self, emitter: Address) {
        self.invocation = Some(emitter);
        // Issuance is one node's, granted from that node's own
        // declaration, so entering the next one starts from nothing.
        self.issuance.clear();
    }

    /// Leave the current invocation. An emission outside one is a runner
    /// defect and traps rather than guessing an emitter.
    pub fn leave_invocation(&mut self) {
        self.invocation = None;
        self.issuance.clear();
    }

    /// Emit an event from the executing instance.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`]: no invocation to attribute it to, a type past
    /// [`MAX_EVENT_TYPES`], or a count or payload past its cap. The caps
    /// trap rather than truncate, so what a transaction emitted is either
    /// entirely in its receipt or the transaction did not complete.
    pub fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), SessionTrap> {
        let emitter = self.invocation.ok_or(SessionTrap::NoInvocation)?;
        if event_type >= MAX_EVENT_TYPES {
            return Err(SessionTrap::EventTypeOutOfRange(event_type));
        }
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(SessionTrap::EventPayloadTooLarge(payload.len()));
        }
        if self.events.len() >= MAX_EVENTS_PER_TX {
            return Err(SessionTrap::TooManyEvents);
        }
        self.events.push(Event {
            emitter,
            event_type,
            payload,
        });
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_vm_types::{
        ABSENT_REP, AbortReason, Address, AddressClass, CollectionId, Effect, EffectTarget,
        MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Mode, Moves, encode_amount,
    };

    use super::fixtures::{declared, env, key, session_holding, session_over, tx};
    use super::materialize::capability_for;
    use super::{Capability, Interval, KernelSession, Op, SessionTrap, grants};
    use crate::ledger::AmountLedger;
    use crate::overlay::OverlayStore;
    use crate::store::{MemoryStore, StoreError};

    #[test]
    fn a_rep_outside_the_table_is_an_unknown_handle() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(session.cell_get(7, 0), Err(SessionTrap::UnknownHandle(7)));
        assert_eq!(
            session.range_count(7, 0),
            Err(SessionTrap::UnknownHandle(7))
        );
    }

    #[test]
    fn the_reserved_rep_names_a_branch_that_was_not_declared() {
        // A guest is handed a handle for every clause its signature
        // declares, guarded-out ones included — an export's parameter
        // list is a function of its signature and cannot lose a
        // parameter to a branch. Touching that one is a body whose
        // control flow disagrees with the verdict it was given, and the
        // diagnostic is the whole value of naming it: nothing was
        // materialized here on purpose.
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_over(MemoryStore::new(), &set);
        assert_eq!(
            session.cell_get(ABSENT_REP, 0),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            session.range_count(ABSENT_REP, 0),
            Err(SessionTrap::UndeclaredBranch)
        );
        assert_eq!(
            AbortReason::from(SessionTrap::UndeclaredBranch),
            AbortReason::UndeclaredBranch
        );
    }

    /// Every mode the kernel materializes, one of each.
    ///
    /// Built rather than materialized from a declaration: what is under
    /// test is what a capability grants, and reaching each of them
    /// through a signature that produces it would test the materializer
    /// instead. Built by [`Capability::forms`], so a mode added to the
    /// enum has to take a place in what the matrix asks.
    fn every_capability() -> [Capability; 15] {
        Capability::forms(
            key(1),
            5,
            Interval {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 100,
                cap: 8,
            },
        )
    }

    /// A session holding exactly `held`, reachable at rep zero.
    ///
    /// The capability and the site that reaches it are installed
    /// together, which is the invariant materialization keeps: a
    /// capability nothing can be acted through is not a session state
    /// any declaration produces.
    fn holding(held: Capability) -> KernelSession {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        session.table = vec![held];
        session.entries = vec![Some(0)];
        session.sites = vec![(0, 1)];
        session
    }

    /// Perform `op` through the entry point that carries it, at rep 0.
    ///
    /// The arguments are whatever reaches the permission check; an
    /// operation the capability grants may still fail for a reason of
    /// its own, which is why the matrix asks only whether the refusal
    /// was a refusal for want of the grant.
    fn attempt(session: &mut KernelSession, op: Op) -> Result<(), SessionTrap> {
        match op {
            Op::Read => session.cell_get(0, 0).map(|_| ()),
            Op::Write => session.write_cell_set(0, 0, vec![1]),
            Op::Clear => session.write_cell_clear(0, 0),
            Op::Seal => session.seal(0, 0),
            Op::OpenSeal => session.open_seal(0, 0).map(|_| ()),
            Op::Balance => session.amount_cell_balance(0, 0).map(|_| ()),
            Op::Take => session.cell_take(0, 0, 1).map(|_| ()),
            Op::Put => session.cell_put(0, 0, 0),
            Op::ReservedAmount => session.reserve_amount(0, 0).map(|_| ()),
            Op::TakeReserved => session.reserve_take(0, 0).map(|_| ()),
            Op::ReadEntries => session.range_count(0, 0).map(|_| ()),
            Op::WriteEntries => session.range_set(0, 0, 0, vec![1]),
            Op::FileInstances => session.range_put(0, 0, 0, &[1]),
            Op::TakeInstances => session.range_take(0, 0, &[1]).map(|_| ()),
        }
    }

    /// The whole of what the kernel grants, asked through the entry
    /// points a guest reaches rather than of the table alone: a row the
    /// table admits and the operation refuses anyway would pass a test
    /// of `grants` by itself.
    #[test]
    fn every_capability_grants_exactly_what_the_table_says() {
        for (position, held) in every_capability().into_iter().enumerate() {
            assert_eq!(held.form(), position, "the matrix covers each form once");
        }
        for held in every_capability() {
            for op in Op::ALL {
                let mut session = holding(held);
                let refused = matches!(
                    attempt(&mut session, op),
                    Err(SessionTrap::Ungranted { .. })
                );
                assert_eq!(
                    refused,
                    !grants(&held, op),
                    "{held:?} against {op:?}: refused_as_ungranted={refused}"
                );
            }
        }
    }

    /// And a refusal says which mode was held and what was asked of it,
    /// because it is the only signal a body reaching past its own
    /// declaration gets.
    #[test]
    fn an_ungranted_refusal_names_both_halves() {
        let mut session = holding(Capability::Read(key(1)));
        assert_eq!(
            session.write_cell_set(0, 0, vec![1]),
            Err(SessionTrap::Ungranted {
                site: 0,
                element: 0,
                held: Capability::Read(key(1)),
                attempted: Op::Write,
            })
        );
        assert_eq!(
            session
                .write_cell_set(0, 0, vec![1])
                .unwrap_err()
                .to_string(),
            "the handle at site 0 element 0 holds a fresh read, which does not grant replace the \
             cell's bytes"
        );
    }

    /// A direction the declaration gave up is one the capability
    /// refuses, whichever shape of cell holds the value.
    ///
    /// Materialization is what the case is about rather than the table
    /// alone: admission judges a directional access on the one movement
    /// entry it earns, so a capability built without the direction
    /// would leave the other movement enforced by nothing at all.
    #[test]
    fn a_hold_that_gave_up_a_direction_refuses_the_movement_it_gave_up() {
        let cell = |moves| {
            capability_for(
                Effect {
                    target: EffectTarget::Point(key(1)),
                    mode: Mode::Write { moves },
                },
                true,
            )
            .expect("a denominated exclusive point materializes")
        };
        let interval = |moves| Capability::Instances {
            interval: Interval {
                owner: Address::new([9; 31], AddressClass::Component),
                collection: CollectionId([4; 16]),
                lo: 0,
                hi: 100,
                cap: 8,
            },
            moves,
        };
        for held in [cell, interval] {
            for (moves, debits, credits) in [
                (Moves::In, false, true),
                (Moves::Out, true, false),
                (Moves::Both, true, true),
            ] {
                let held = held(moves);
                let (take, put) = match held {
                    Capability::Instances { .. } => (Op::TakeInstances, Op::FileInstances),
                    _ => (Op::Take, Op::Put),
                };
                assert_eq!(grants(&held, take), debits, "{held:?} debits");
                assert_eq!(grants(&held, put), credits, "{held:?} credits");
            }
        }
    }

    #[test]
    fn the_environment_reaches_the_guest_unchanged() {
        let session = session_over(MemoryStore::new(), &declared(&[]));
        assert_eq!(session.clock_ms(), env().clock_ms);
        assert_eq!(session.hash(&[1, 2, 3])[0], 3);
        assert!(session.capabilities().is_empty());
    }

    #[test]
    fn emission_refuses_outside_an_invocation_and_past_its_caps() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::NoInvocation));

        session.enter_invocation(Address::new([7; 31], AddressClass::Component));
        assert_eq!(
            session.emit(MAX_EVENT_TYPES, Vec::new()),
            Err(SessionTrap::EventTypeOutOfRange(MAX_EVENT_TYPES)),
        );
        let oversized = vec![0u8; MAX_EVENT_PAYLOAD_BYTES + 1];
        assert_eq!(
            session.emit(0, oversized),
            Err(SessionTrap::EventPayloadTooLarge(
                MAX_EVENT_PAYLOAD_BYTES + 1
            )),
        );
        for _ in 0..MAX_EVENTS_PER_TX {
            session.emit(0, Vec::new()).unwrap();
        }
        // The cap traps rather than truncating: what a transaction emitted
        // is entirely in its receipt, or the transaction did not complete.
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::TooManyEvents));

        session.leave_invocation();
        assert_eq!(session.emit(0, Vec::new()), Err(SessionTrap::NoInvocation));
    }

    /// The grant is a quantity and it leaves the kernel once: a second
    /// take of one reservation would be a second edge against one hold.
    #[test]
    fn a_reservation_is_taken_once() {
        let vault = key(6);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
        let set = declared(&[Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Reserve { amount: 40 },
        }]);
        let mut session = session_holding(store, &set);

        let funds = session.reserve_take(0, 0).expect("the grant is held");
        assert_eq!(
            session.reserve_take(0, 0),
            Err(SessionTrap::ReservationTaken)
        );
        // The refusal minted nothing: the one edge stands as it was.
        assert_eq!(session.bucket_amount(funds), Ok(40));
    }

    #[test]
    fn judging_refuses_the_same_pair_twice() {
        let vault = key(5);
        let mut store = MemoryStore::new();
        store.write(vault, encode_amount(100).to_vec());
        assert_eq!(
            store.judge_and_hold(&[(tx(1), vault, 10), (tx(1), vault, 20)]),
            Err(StoreError::DuplicateRequest {
                tx: tx(1),
                key: vault,
            })
        );
        let mut overlay = OverlayStore::new(Arc::new(store));
        assert_eq!(
            overlay.judge_and_hold(&[(tx(1), vault, 10), (tx(1), vault, 20)]),
            Err(StoreError::DuplicateRequest {
                tx: tx(1),
                key: vault,
            })
        );
    }
}
