//! The value seam: the operations that move value between cells and
//! buckets.
//!
//! Each movement is one number the body never writes twice: a debit
//! opens the bucket it debited, a credit consumes the bucket it
//! credited, a mint and a burn act on the issuance grants the executing
//! invocation's declaration claimed, and a reservation leaves as the
//! edge the kernel already judged and held. The ledger these feed is
//! [`buckets`](super::buckets), and
//! [`finish`](super::KernelSession::finish) balances what they fed.

use std::collections::BTreeSet;

use hyperscale_vm_effects::{IssuanceGrant, ResourceKind, distinct_ids};
use hyperscale_vm_types::{ResourceAddr, SubstateKey};

use super::buckets::Held;
use super::{Capability, KernelSession, Op, SessionTrap, Settlement};
use crate::ledger::AmountLedger;
use crate::modes::{DeltaOp, decode_amount};
use crate::store::WorkingStore;

impl KernelSession {
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
    pub(super) fn amount_cell(&mut self, key: SubstateKey) -> Result<u128, SessionTrap> {
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
}
