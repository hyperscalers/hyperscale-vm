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

use hyperscale_vm_effects::{
    CrossingCell, CrossingSite, IssuanceGrant, Recourse, ResourceKind, distinct_ids,
};
use hyperscale_vm_types::{ResourceAddr, SubstateKey};

use super::buckets::Held;
use super::{Capability, KernelSession, Op, SessionTrap, Settlement};
use crate::escrow::{Crossed, Departure, Disposal, Disposition};
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
        Ok(self.open_bucket(Held::Amount(amount), resource, Some(key)))
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
            // credit past the width an amount has is refused at the
            // call — as the floor the fold refuses a queued one at, which
            // is what the recorded key and amount let the walk say.
            Settlement::Immediate(key) => {
                if self.amount_cell(key)?.checked_add(amount).is_none() {
                    self.lost_floor = Some((key, amount));
                    return Err(SessionTrap::CellOverflow { key, amount });
                }
                key
            }
            // A credit answers this and a delta answers it too: what the
            // narrower mode gave up is the other direction, not this one.
            Settlement::Queued(key) => key,
        };
        self.store.queue_delta(key, DeltaOp::Add(amount))?;
        self.take_bucket(funds).map(|_| ())
    }

    /// The cell and amount the last call-time refusal found no floor
    /// for, taken once.
    pub const fn take_lost_floor(&mut self) -> Option<(SubstateKey, u128)> {
        self.lost_floor.take()
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
        Ok(self.open_bucket(Held::Amount(amount), resource, None))
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
        Ok(self.open_bucket(Held::Instances(instances), resource, None))
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

    /// Send what a bucket carries out of this execution as escrow.
    ///
    /// Not a destruction and not a mint: the value exists after this and
    /// exists somewhere else, so it moves the escrow term rather than the
    /// supply one. Folding a crossing into supply would record a mint
    /// that never happened.
    ///
    /// The bucket is consumed, which is what makes this the shape a
    /// producing node's output takes on the way out. A non-fungible
    /// bucket is refused: the attestation is linear over amounts and
    /// blind to identity, so what an id-bearing crossing would arrive
    /// with is a delta its producer's history supports.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], and [`SessionTrap::WrongEdgeKind`] for an
    /// instance-bearing bucket — the sender's own defect.
    pub(crate) fn escrow_out(
        &mut self,
        node: u32,
        output: u32,
        funds: u32,
        departure: Departure,
    ) -> Result<Crossed, SessionTrap> {
        let resource = self.buckets.resource_of(funds)?;
        // Both refusals below read the bucket rather than consume it, so
        // a crossing the kernel declines leaves the value where it was:
        // an instance-bearing edge is the sender's own defect, and a
        // crossing with nothing to go back to is refused with the bucket
        // still whole.
        let amount = self.bucket_amount(funds)?;
        let origin = self.bucket_origin(funds);
        // A crossing an outbound leg consumes is that consumer's from
        // the moment the core commits it. No cell is the crossing's to
        // return to, whatever produced it, so the record names nobody
        // and stands until the consumer claims it.
        //
        // Every other crossing goes back where its value came from: the
        // cell the bucket was debited from, which the table carried
        // here. Where there is no such cell there is no crossing: a
        // consumer that refuses leaves a record nobody may claim and
        // nobody may take back, and the value stands in a cell no sweep
        // reaches and no action moves. So the kernel refuses to issue
        // one rather than issue value into a dead end.
        //
        // One shape reaches it: value with no single cell behind it — a
        // mint, a crossing claimed in, or a bucket merged from two. A
        // cell this execution could not credit does not, because value
        // only leaves a cell through a capability, and a capability on a
        // cell another member judges is refused where it is exercised.
        // So the origin is this member's to credit wherever there is
        // one, which is what a reclaim needs of it.
        let recourse = if departure.delivers {
            Recourse::Nobody
        } else {
            let Some(cell) = origin else {
                return Err(SessionTrap::CrossingWithoutRecourse(departure.site.key()));
            };
            Recourse::Producer(cell)
        };
        self.take_bucket(funds)?;
        let crossed = Crossed { resource, amount };
        self.escrow.issue(node, output, crossed)?;
        self.record_crossing(
            departure.site.key(),
            departure
                .site
                .crossing(
                    self.tx,
                    resource,
                    amount,
                    departure.consumer_claim,
                    recourse,
                )
                .to_bytes(),
        )?;
        Ok(crossed)
    }

    /// The cell the capability at `rep` moves value through, if it
    /// moves value at all.
    fn cell_at(&self, rep: u32) -> Option<SubstateKey> {
        match self.table.get(usize::try_from(rep).ok()?)? {
            Capability::Amount { key, .. }
            | Capability::Delta { key, .. }
            | Capability::Reserve { key, .. } => Some(*key),
            Capability::Read(_)
            | Capability::Write(_)
            | Capability::AmountRead(_)
            | Capability::RangeRead(_)
            | Capability::RangeWrite(_)
            | Capability::Instances { .. } => None,
        }
    }

    /// Settle one record this execution issued: take the crossing back,
    /// or retire the record once its claim committed.
    ///
    /// Taking it back is the producing node claiming its own record
    /// through the path a consumer claims it: the claim is a loss and
    /// the credit a gain, so the fold balances with no term of its own,
    /// and the claim cell under the producer's own target is what
    /// refuses a second reclaim, on the machinery that refuses a second
    /// claim. The resource, the amount and the cell credited are all
    /// the record's. Retiring moves nothing and enters no fold term: the
    /// consumer's claim moved the value where it ran, and what is left
    /// is a cell saying so.
    ///
    /// Either way the record goes: it is a balance held for a claim, and
    /// the claim has happened or never will.
    ///
    /// The record has to be there and name the edge — one that is not
    /// was settled already, and a second settlement is the batch's
    /// defect rather than a lost race.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::EscrowRecordUnreadable`] for a record that is
    /// absent, does not decode, names another edge, or — for a reclaim
    /// — leaves the crossing nobody's to take back;
    /// [`SessionTrap::EscrowCreditUndeclared`] where the declaration
    /// carries no movement handle on the cell the record says to credit;
    /// and any [`SessionTrap`] the claim, the credit or the store
    /// raises.
    pub(crate) fn escrow_settle(&mut self, disposal: &Disposal) -> Result<(), SessionTrap> {
        let record: CrossingCell = self
            .store
            .read(disposal.record)?
            .and_then(|bytes| CrossingCell::from_bytes(&bytes))
            .filter(|record| disposal.claim.names(record))
            .ok_or(SessionTrap::EscrowRecordUnreadable(disposal.record))?;
        if disposal.disposition == Disposition::Reclaim {
            let Recourse::Producer(credit) = record.recourse else {
                return Err(SessionTrap::EscrowRecordUnreadable(disposal.record));
            };
            let site = self
                .table
                .iter()
                .position(|held| matches!(held, Capability::Delta { key, .. } if *key == credit))
                .and_then(|index| u32::try_from(index).ok())
                .ok_or(SessionTrap::EscrowCreditUndeclared(credit))?;
            let crossed = Crossed {
                resource: record.resource,
                amount: record.amount,
            };
            let funds = self.escrow_in(crossed, disposal.claim)?;
            self.cell_put(site, 0, funds)?;
        }
        self.store.remove(disposal.record)?;
        Ok(())
    }

    /// Write the crossing `value` at `key`, where nothing has written
    /// one already.
    ///
    /// The key names the edge, so a second crossing at one key is two
    /// edges the chain cannot tell apart: the record cell holds one of
    /// them, the receipt attests both by manifest index, and the
    /// consumer is credited twice against a single claim. Refusing the
    /// write is the defence in depth beneath admission's rule that no
    /// two intents of one tree may derive one key.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::CrossingKeyRepeated`] where `key` already holds a
    /// crossing.
    fn record_crossing(&mut self, key: SubstateKey, value: Vec<u8>) -> Result<(), SessionTrap> {
        if self.crossings.insert(key, value).is_some() {
            return Err(SessionTrap::CrossingKeyRepeated(key));
        }
        Ok(())
    }

    /// Take an attested arrival in as a bucket.
    ///
    /// What stands in for a producer another shard ran. No grant is
    /// consulted, and none could be: the authority that let the value
    /// exist was exercised where it was produced, and what reaches here
    /// is a certificate saying so.
    ///
    /// # Errors
    ///
    /// [`SessionTrap`] on an overflowing escrow total.
    pub(crate) fn escrow_in(
        &mut self,
        crossed: Crossed,
        site: CrossingSite,
    ) -> Result<u32, SessionTrap> {
        self.escrow.claim(crossed)?;
        self.record_crossing(site.key(), site.claimed_by(self.tx).to_bytes())?;
        Ok(self.open_bucket(Held::Amount(crossed.amount), crossed.resource, None))
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
        let origin = self.cell_at(rep);
        Ok(self.open_bucket(Held::Amount(amount), resource, origin))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_effects::{CrossingSite, Hash32, IntentHash, TestHasher};
    use hyperscale_vm_types::{Address, AddressClass, LocalKey, ResourceAddr, SubstateKey};

    use super::super::fixtures::{declared, session_over};
    use super::Held;
    use crate::escrow::{Crossed, Departure};
    use crate::session::SessionTrap;
    use crate::store::MemoryStore;

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

    fn site() -> CrossingSite {
        CrossingSite::record(
            &TestHasher,
            Address::new([0xA1; 31], AddressClass::Component),
            IntentHash(Hash32([0x5A; 32])),
            0,
            0,
            1_000,
        )
    }

    /// A cell the session applies, so a crossing funded from it names a
    /// producer that could take it back.
    fn origin_cell() -> SubstateKey {
        SubstateKey {
            owner: Address::new([0xA1; 31], AddressClass::Component),
            local: LocalKey([0x11; 16]),
        }
    }

    fn departure() -> Departure {
        Departure {
            delivers: false,
            site: site(),
            consumer_claim: CrossingSite::claim(
                &TestHasher,
                Address::new([0xB2; 31], AddressClass::Component),
                IntentHash(Hash32([0x5A; 32])),
                0,
                0,
                1_000,
            )
            .key(),
        }
    }

    /// The escrow attestation is linear over amounts and blind to
    /// identity, so a named-instance crossing would arrive carrying a
    /// delta its producer's history supports. Refused at the issue, which
    /// is where the sender's own defect belongs.
    #[test]
    fn an_instance_bucket_is_refused_at_the_issue() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        let instances = session.open_bucket(Held::Instances(BTreeSet::from([7])), RESOURCE, None);
        assert_eq!(
            session.escrow_out(0, 0, instances, departure()),
            Err(SessionTrap::WrongEdgeKind),
        );
    }

    /// A fungible bucket crosses as exactly what it carried, and the
    /// bucket is consumed on the way out.
    #[test]
    fn a_fungible_bucket_crosses_as_what_it_carried() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        let funds = session.open_bucket(Held::Amount(40), RESOURCE, Some(origin_cell()));
        assert_eq!(
            session.escrow_out(0, 0, funds, departure()),
            Ok(Crossed {
                resource: RESOURCE,
                amount: 40,
            }),
        );
        assert!(session.bucket(funds).is_err(), "consumed on the way out");
        assert_eq!(session.escrow.issued(RESOURCE), 40);
    }

    /// A crossing no outbound leg consumes has to be able to come home.
    ///
    /// Value with no one cell behind it — a mint, a crossing claimed in,
    /// a bucket merged from two — would leave a record naming nobody: a
    /// consumer that refuses can never claim it and nothing may take it
    /// back, so it would stand in a cell no sweep reaches and no action
    /// moves. Refused at the issue, with the bucket still whole.
    #[test]
    fn a_crossing_with_nothing_to_go_back_to_is_refused_at_the_issue() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        let merged = session.open_bucket(Held::Amount(40), RESOURCE, None);
        assert_eq!(
            session.escrow_out(0, 0, merged, departure()),
            Err(SessionTrap::CrossingWithoutRecourse(site().key())),
        );
        assert!(
            session.bucket(merged).is_ok(),
            "the value stays where it was",
        );
        assert_eq!(session.escrow.issued(RESOURCE), 0, "and nothing crossed");
    }

    /// A crossing an outbound leg consumes is the exception the shape is
    /// built on: it is that consumer's from the moment the core commits
    /// it and nothing is meant to take it back, so it issues whatever
    /// produced the value.
    #[test]
    fn a_delivering_crossing_needs_nothing_to_go_back_to() {
        let mut session = session_over(MemoryStore::new(), &declared(&[]));
        let minted = session.open_bucket(Held::Amount(40), RESOURCE, None);
        let delivering = Departure {
            delivers: true,
            ..departure()
        };
        assert_eq!(
            session.escrow_out(0, 0, minted, delivering),
            Ok(Crossed {
                resource: RESOURCE,
                amount: 40,
            }),
        );
    }
}
