//! The bucket table: the linearity state machine for value in flight.
//!
//! A bucket is opened only by the kernel's own producers, changes shape
//! only through splits and merges the kernel performs, and leaves the
//! table only by being taken back or by carrying nothing. The whole
//! surface of these operations is one promise: value is never duplicated
//! and never silently lost.
//!
//! Nothing here judges a loss. Whether one happened is a question about
//! the whole transaction, answered once at the close over the table as a
//! whole — so a body that lets a full bucket go and a body that holds one
//! to the end meet the same verdict rather than two.

use std::collections::BTreeSet;

use hyperscale_vm_types::ResourceAddr;
use hyperscale_vm_types::math::{MathError, Rounding, U256, mul_div};

use super::{KernelSession, SessionTrap};

/// What a bucket carries.
///
/// The two are one object because they are one thing to a manifest — value
/// in flight between a producer and a consumer — and they differ in what
/// quantity means: a fungible edge has an amount nothing declares, and a
/// non-fungible one names the instances it moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Held {
    /// A quantity of a fungible resource.
    Amount(u128),
    /// The instances a non-fungible edge moves, by the order key each was
    /// filed at in its collection.
    Instances(BTreeSet<u128>),
}

impl Held {
    /// What a signed bound is judged over: an amount, or how many
    /// instances.
    #[must_use]
    pub fn quantity(&self) -> u128 {
        match self {
            Self::Amount(amount) => *amount,
            Self::Instances(ids) => ids.len() as u128,
        }
    }

    /// Whether it carries nothing, which is what lets its slot go when a
    /// guest lets the handle go.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quantity() == 0
    }
}

/// Value held on the executing body's behalf, indexed by the rep a
/// guest's `own<bucket>` handle names.
///
/// Its own rep space, beside the capability table rather than inside it:
/// a bucket carries value and confers no state access, and a capability
/// is materialized once from the declaration where a bucket appears and
/// leaves during execution. A slot empties when the bucket leaves —
/// dropped by the guest or taken back by the kernel — and is never
/// reused, so one rep names one bucket for the transaction's life.
///
/// The table therefore measures the takes and splits a body performed
/// rather than what it is holding, and what bounds it is the signed fuel
/// budget: every rep is minted by a metered call, so the slots a
/// transaction can leave standing are priced before they are allocated.
#[derive(Debug, Default)]
pub(super) struct Buckets {
    slots: Vec<Option<Held>>,
    /// The resource each live bucket carries, by the same rep the slots
    /// use.
    ///
    /// Stamped where value comes into being — debited from a cell, taken
    /// against a grant, or handed in as a routed edge — and read where it
    /// lands, which is the pair that makes value crossing between two
    /// resources inexpressible rather than merely undeclared.
    ///
    /// Not an `Option`. Every producer names what it made: a cell a
    /// movement reached is one the declaration denominated, a grant is
    /// authority over one resource, and a split inherits from what it
    /// came off. A bucket that could carry nothing in particular would
    /// be one every destination had to admit.
    resources: Vec<ResourceAddr>,
}

impl Buckets {
    /// Open a bucket carrying `held`, returning its rep.
    ///
    /// # Panics
    ///
    /// Only past `u32` buckets in one transaction. Reps are minted per
    /// take and split, so the bound is the fuel budget — four billion
    /// host calls — not any declared count.
    pub(super) fn open(&mut self, held: Held, resource: ResourceAddr) -> u32 {
        let rep = u32::try_from(self.slots.len()).expect("bounded");
        self.slots.push(Some(held));
        self.resources.push(resource);
        rep
    }

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub(super) fn get(&self, rep: u32) -> Result<Held, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.slots.get(index))
            .cloned()
            .flatten()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// The amount the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for a bucket carrying instances:
    /// what a movement moves is an amount, and a named thing is not one.
    pub(super) fn amount(&self, rep: u32) -> Result<u128, SessionTrap> {
        match self.get(rep)? {
            Held::Amount(amount) => Ok(amount),
            Held::Instances(_) => Err(SessionTrap::WrongEdgeKind),
        }
    }

    /// What the bucket at `rep` carries, answered for any rep the table
    /// has ever held — the resource outlives the value, which is what
    /// lets a merge refuse on denomination before consuming anything.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep past the table.
    pub(super) fn resource_of(&self, rep: u32) -> Result<ResourceAddr, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.resources.get(index))
            .copied()
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Take the bucket at `rep` out of the table: the kernel holds the
    /// value again and the rep names nothing afterwards.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub(super) fn take(&mut self, rep: u32) -> Result<Held, SessionTrap> {
        usize::try_from(rep)
            .ok()
            .and_then(|index| self.slots.get_mut(index))
            .and_then(Option::take)
            .ok_or(SessionTrap::UnknownHandle(rep))
    }

    /// Replace what a live bucket carries. The rep is one `get` has
    /// already resolved, so there is no slot to miss.
    fn set(&mut self, rep: u32, held: Held) {
        if let Some(slot) = usize::try_from(rep)
            .ok()
            .and_then(|index| self.slots.get_mut(index))
        {
            *slot = Some(held);
        }
    }

    /// Split `amount` off the bucket at `rep`, as a new bucket.
    ///
    /// The subtraction is performed here, so the half that comes off and
    /// the half left behind are one operation and a body writes down
    /// neither.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a split past what the bucket holds.
    pub(super) fn split(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        // A quantity divides what a quantity is. Splitting an instance
        // set by a number has no answer — which instances? — so the
        // vocabulary refuses rather than picking.
        let held = self.amount(rep)?;
        let resource = self.resource_of(rep)?;
        let left = held
            .checked_sub(amount)
            .ok_or(SessionTrap::BucketUnderflow { amount, held })?;
        self.set(rep, Held::Amount(left));
        Ok(self.open(Held::Amount(amount), resource))
    }

    /// Split `num/den` of the bucket at `rep` off, as a new bucket.
    ///
    /// The share is computed and the remainder is *derived*: what stays
    /// behind is the subtraction, never a second multiplication. That is
    /// what makes conservation arithmetic rather than checked — the two
    /// outputs sum to the input because one of them is defined as the
    /// difference, so there is no rounding argument to get wrong and no
    /// way to write the bug where distributed parts do not sum to the
    /// whole. The supply accumulators downstream assume exactly that.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for an instance edge, which a
    /// proportion cannot divide; [`SessionTrap::Math`] on a zero
    /// denominator; [`SessionTrap::ShareAboveOne`] past one.
    pub(super) fn split_share(
        &mut self,
        rep: u32,
        num: U256,
        den: U256,
    ) -> Result<u32, SessionTrap> {
        let held = self.amount(rep)?;
        if den.is_zero() {
            return Err(SessionTrap::Math(MathError::DivideByZero));
        }
        if num > den {
            return Err(SessionTrap::ShareAboveOne);
        }
        // The share is at most what is held, because the ratio is at most
        // one — so the narrowing and the subtraction below are both
        // total, and neither needs a check the type system would then
        // have to explain.
        let share = mul_div(U256::from_u128(held), num, den, Rounding::Down)?
            .to_u128()
            .ok_or(SessionTrap::Math(MathError::Overflow))?;
        let resource = self.resource_of(rep)?;
        let left = held
            .checked_sub(share)
            .ok_or(SessionTrap::BucketUnderflow {
                amount: share,
                held,
            })?;
        self.set(rep, Held::Amount(left));
        Ok(self.open(Held::Amount(share), resource))
    }

    /// Merge the bucket at `other` into the one at `rep`, consuming it.
    ///
    /// The consumed bucket leaves the table before the merge, which is
    /// what an owned argument means and what makes a merge of a bucket
    /// into itself say so: the one bucket is gone by the time the other
    /// is looked up, so the second lookup is the unknown handle the
    /// guest's own table already agrees it is. Reading both first would
    /// instead add a quantity to itself and put the total back in the
    /// slot the take had just emptied, which is value from nowhere.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a total past an amount's width.
    pub(super) fn merge(&mut self, rep: u32, other: u32) -> Result<(), SessionTrap> {
        // A merge makes two edges one, so it is the same question a cell
        // credit asks — with the receiving edge's resource in place of a
        // cell's. Both lookups answer for a rep the table has ever held,
        // so a merge into itself still reaches the take below and fails
        // there, which is where the guest's own table agrees it should.
        let into = self.resource_of(rep)?;
        let carried = self.resource_of(other)?;
        if into != carried {
            return Err(SessionTrap::WrongResource {
                cell: into,
                carried,
            });
        }
        let added = self.take(other)?;
        let merged = match (self.get(rep)?, added) {
            (Held::Amount(held), Held::Amount(added)) => {
                Held::Amount(held.checked_add(added).ok_or(SessionTrap::BucketOverflow)?)
            }
            // Instances are named, so a merge is a union and a name
            // appearing twice is one instance in two places.
            (Held::Instances(mut held), Held::Instances(added)) => {
                for id in added {
                    if !held.insert(id) {
                        return Err(SessionTrap::InstanceHeldTwice(id));
                    }
                }
                Held::Instances(held)
            }
            _ => return Err(SessionTrap::WrongEdgeKind),
        };
        self.set(rep, merged);
        Ok(())
    }

    /// Let go of the bucket at `rep`.
    ///
    /// An empty one leaves the table, because there is nothing left to
    /// account for. One still carrying value stays in it, and stays the
    /// table's to answer for at
    /// [`carries_value`](Self::carries_value) — so letting a handle go
    /// and never letting it go are the same fact about the transaction,
    /// judged once where the whole of it is visible.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub(super) fn drop(&mut self, rep: u32) -> Result<(), SessionTrap> {
        if self.get(rep)?.is_empty() {
            self.take(rep)?;
        }
        Ok(())
    }

    /// Whether any live bucket still carries value — the account
    /// [`KernelSession::finish`](super::KernelSession::finish) balances
    /// before anything commits.
    pub(super) fn carries_value(&self) -> bool {
        self.slots.iter().flatten().any(|held| !held.is_empty())
    }
}

impl KernelSession {
    /// Takes a quantity into the kernel's keeping, returning the rep a
    /// guest's handle names.
    ///
    /// Every producer is the kernel's own — an edge routed to this
    /// invocation, a debit against a cell the method declared — because
    /// the world exports no constructor for one.
    ///
    /// # Panics
    ///
    /// Only past `u32` buckets in one transaction. Reps are minted per
    /// take and split, so the bound is the fuel budget — four billion
    /// host calls — not any declared count.
    pub(crate) fn open_bucket(&mut self, held: Held, resource: ResourceAddr) -> u32 {
        self.buckets.open(held, resource)
    }

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn bucket(&self, rep: u32) -> Result<Held, SessionTrap> {
        self.buckets.get(rep)
    }

    /// The amount the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for a bucket carrying instances:
    /// what a movement moves is an amount, and a named thing is not one.
    pub fn bucket_amount(&self, rep: u32) -> Result<u128, SessionTrap> {
        self.buckets.amount(rep)
    }

    /// Takes the bucket at `rep` back out of the table: the kernel holds
    /// the value again and the rep names nothing afterwards.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn take_bucket(&mut self, rep: u32) -> Result<Held, SessionTrap> {
        self.buckets.take(rep)
    }

    /// Split `amount` off the bucket at `rep`, as a new bucket.
    ///
    /// The kernel performs the subtraction, so the half that comes off
    /// and the half left behind are one operation and a body writes down
    /// neither.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a split past what the bucket holds.
    pub fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, SessionTrap> {
        self.buckets.split(rep, amount)
    }

    /// Split `num/den` of the bucket at `rep` off, as a bucket.
    ///
    /// See [`Buckets::split_share`] for why conservation here is
    /// arithmetic rather than checked.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::WrongEdgeKind`] for an instance edge, which a
    /// proportion cannot divide; [`SessionTrap::Math`] on a zero
    /// denominator; [`SessionTrap::ShareAboveOne`] past one.
    pub fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, SessionTrap> {
        self.buckets.split_share(rep, num, den)
    }

    /// Merge the bucket at `other` into the one at `rep`, consuming it.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including a total past an amount's width.
    pub fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), SessionTrap> {
        self.buckets.merge(rep, other)
    }

    /// A bucket handle the guest let go of.
    ///
    /// The canonical ABI delivers the drop, and what the kernel does with
    /// it is release the slot. It judges nothing: whether value was
    /// forgotten is a question about the whole transaction, and a body
    /// that keeps a full bucket to the end delivers no drop at all — so
    /// deciding it here would answer for one of the two ways of losing
    /// value and be silent about the other. [`KernelSession::finish`]
    /// answers for both, once, where the table is whole.
    ///
    /// # Errors
    ///
    /// [`SessionTrap::UnknownHandle`] for a rep naming no live bucket.
    pub fn drop_bucket(&mut self, rep: u32) -> Result<(), SessionTrap> {
        self.buckets.drop(rep)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::ResourceAddr;

    use super::{Buckets, Held, MathError, SessionTrap, U256};

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

    /// A deterministic generator: the property is exact, so the corpus
    /// only has to be wide and reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A `u128` with a uniformly chosen bit width, so small values
        /// are as common as wide ones.
        fn amount(&mut self) -> u128 {
            let bits = self.next() % 129;
            if bits == 0 {
                return 0;
            }
            let value = u128::from(self.next()) | (u128::from(self.next()) << 64);
            value >> (128 - bits)
        }
    }

    /// The property the primitive exists for: the two outputs sum to the
    /// input, for every quantity and every share at or under one, with no
    /// rounding argument anywhere in the statement.
    #[test]
    fn a_split_conserves_what_it_divides() {
        let mut buckets = Buckets::default();
        let mut rng = Rng(0x5eed_0f0f_1234_0001);
        for _ in 0..2_000 {
            let held = rng.amount();
            let den = rng.amount().max(1);
            let num = rng.amount() % (den + 1);
            let rep = buckets.open(Held::Amount(held), RESOURCE);
            let part = buckets
                .split_share(rep, U256::from_u128(num), U256::from_u128(den))
                .expect("a share at or under one");
            let share = buckets.amount(part).expect("a fungible edge");
            let rest = buckets.amount(rep).expect("a fungible edge");
            assert_eq!(
                share.checked_add(rest),
                Some(held),
                "split({num}/{den}) of {held} lost or made value"
            );
            assert!(share <= held);
        }
    }

    /// The dust falls to the bucket that was split, always: the share is
    /// the floor, so the remainder is what absorbs the truncation. That
    /// is the whole of the rounding policy, and it is a consequence of
    /// deriving one output rather than a direction anyone supplies.
    #[test]
    fn a_split_leaves_its_dust_with_the_remainder() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(Held::Amount(10), RESOURCE);
        let part = buckets
            .split_share(rep, U256::from_u128(1), U256::from_u128(3))
            .expect("a third");
        assert_eq!(buckets.amount(part), Ok(3));
        assert_eq!(buckets.amount(rep), Ok(7));
    }

    /// The widest quantity there is, split by the finest share that is
    /// not zero: the product leaves the amount width entirely, which is
    /// what makes the operation the kernel's rather than a guest's.
    #[test]
    fn a_split_holds_a_product_the_amount_width_cannot() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(Held::Amount(u128::MAX), RESOURCE);
        let part = buckets
            .split_share(
                rep,
                U256::from_u128(u128::MAX - 1),
                U256::from_u128(u128::MAX),
            )
            .expect("a share under one");
        let share = buckets.amount(part).expect("a fungible edge");
        let rest = buckets.amount(rep).expect("a fungible edge");
        assert_eq!(share.checked_add(rest), Some(u128::MAX));
        assert_eq!(rest, 1);
    }

    /// A share above one leaves a negative remainder, which denominates
    /// nothing — so it is refused rather than saturated. Saturating would
    /// answer `(everything, nothing)`, which is the kind of answer a
    /// caller builds on.
    #[test]
    fn a_share_above_one_is_refused_rather_than_saturated() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(Held::Amount(100), RESOURCE);
        assert_eq!(
            buckets.split_share(rep, U256::from_u128(3), U256::from_u128(2)),
            Err(SessionTrap::ShareAboveOne)
        );
        assert_eq!(
            buckets.amount(rep),
            Ok(100),
            "a refused split moves nothing"
        );
    }

    /// A zero denominator is the empty pool's share, and it is a refusal
    /// rather than a trap in the arithmetic below it.
    #[test]
    fn a_split_by_nothing_is_refused() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(Held::Amount(100), RESOURCE);
        assert_eq!(
            buckets.split_share(rep, U256::from_u128(1), U256::ZERO),
            Err(SessionTrap::Math(MathError::DivideByZero))
        );
    }

    /// A proportion cannot divide named instances: which ones would it
    /// take? The vocabulary refuses rather than picking.
    #[test]
    fn a_proportion_does_not_divide_an_instance_edge() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(
            Held::Instances([1u128, 2, 3].into_iter().collect()),
            RESOURCE,
        );
        assert_eq!(
            buckets.split_share(rep, U256::from_u128(1), U256::from_u128(2)),
            Err(SessionTrap::WrongEdgeKind)
        );
    }

    /// A merge of a bucket into itself is one bucket, and the table says
    /// so rather than adding a quantity to itself.
    ///
    /// Both engines' canonical ABIs refuse the call before it reaches
    /// here — an owned argument cannot be lifted out of a handle the same
    /// call is borrowing — so this is the kernel holding the invariant on
    /// its own account, where it does not depend on either of them.
    #[test]
    fn a_merge_of_a_bucket_into_itself_is_not_two_buckets() {
        let mut buckets = Buckets::default();
        let funds = buckets.open(Held::Amount(40), RESOURCE);
        assert_eq!(
            buckets.merge(funds, funds),
            Err(SessionTrap::UnknownHandle(funds)),
        );
        // And the take consumed it exactly once: the bucket is gone, not
        // doubled and not left standing.
        assert_eq!(buckets.get(funds), Err(SessionTrap::UnknownHandle(funds)));
    }

    /// A taken bucket is gone: the rep answers nothing afterwards, and
    /// the value exists only where the kernel put it.
    #[test]
    fn a_take_leaves_the_rep_naming_nothing() {
        let mut buckets = Buckets::default();
        let rep = buckets.open(Held::Amount(7), RESOURCE);
        assert_eq!(buckets.take(rep), Ok(Held::Amount(7)));
        assert_eq!(buckets.take(rep), Err(SessionTrap::UnknownHandle(rep)));
        assert!(!buckets.carries_value());
    }

    /// A drop releases an empty slot and holds on to a full one, so what
    /// a body let go of is still what the table has to answer for.
    #[test]
    fn a_drop_loses_nothing() {
        let mut buckets = Buckets::default();
        let full = buckets.open(Held::Amount(3), RESOURCE);
        assert_eq!(buckets.drop(full), Ok(()));
        assert!(buckets.carries_value());
        let emptied = buckets.split(full, 0).expect("nothing comes off");
        assert_eq!(buckets.drop(emptied), Ok(()));
        assert!(buckets.carries_value(), "the full one is still held");
    }
}
