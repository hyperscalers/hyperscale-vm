//! The state vocabulary a contract body is written against.
//!
//! Every one of these types exists to make the access mode *derivable*.
//! State is reachable only through the handles here, and each method on
//! them names exactly one point of the mode lattice — `add` is commutative,
//! `reserve` is conditional, `set` is exclusive, `locked` excludes nothing.
//! So `#[blueprint]` reads the mode off the body rather than asking for it,
//! and a cell a method both reads and writes folds to `Write` because the
//! lattice says `Write` subsumes `Read`.
//!
//! That is the same argument the kernel's import surface makes in
//! `hyperscale:kernel/state`, one level up: there is one resource type per
//! mode, so an undeclared mode has no handle type to arrive in. These types
//! are the Rust-facing shadow of that surface, which is why the vocabulary
//! is closed rather than merely conventional.
//!
//! # On the host
//!
//! Host builds carry no kernel, so the bodies are never executed here —
//! `#[blueprint]` reads them, it does not run them. Every accessor below
//! panics if called outside a guest. The declaration these types exist to
//! derive is produced without executing a single one of them.

use hyperscale_vm_effects::Address;

/// An unsigned amount, in the kernel's cell width.
pub type Amount = u128;

const OFF_HOST: &str = "contract bodies execute in the guest, never on the host — \
                        `#[blueprint]` reads this body, it does not run it";

/// A value edge: a resource and an amount in flight between components.
///
/// Only the resource is ever declared. The amount is dynamic and never
/// reaches the DSL, which is what lets one declaration cover every size of
/// transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    resource: Address,
    amount: Amount,
}

impl Bucket {
    /// Mint a value edge carrying `resource`.
    ///
    /// The explicit spelling for an edge a method produces rather than
    /// moves; `#[blueprint]` reads the resource out of the first argument
    /// and records it as a declared output.
    #[must_use]
    pub const fn of(resource: Address, amount: Amount) -> Self {
        Self { resource, amount }
    }

    /// The resource this edge carries.
    #[must_use]
    pub const fn resource(&self) -> Address {
        self.resource
    }

    /// The amount in flight.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }
}

/// A permanently locked configuration leaf.
///
/// Read through [`Locked::locked`], which declares a locked read that excludes
/// nothing and carries no proof obligation. Its fields are the instance's
/// creation-fixed configuration slots, in declaration order.
#[derive(Clone, Copy, Debug, Default)]
pub struct Locked<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Locked<T> {
    /// The configuration. Locked at creation, so every version reads the
    /// same: no proof obligation, no participant.
    #[must_use]
    pub fn locked(&self) -> &T {
        unimplemented!("{OFF_HOST}")
    }
}

/// Configuration fields read straight off the component, with no claim.
///
/// The deref is the type-level statement of a rule the VM already has:
/// creation-fixed configuration is a locked substate, verified once and
/// cached process-wide, so consulting it costs no declaration and creates
/// no participant. Pinning the whole record is a separate, deliberate act —
/// [`Locked::locked`] — which a method performs only when it wants the
/// record stable rather than merely readable.
impl<T> core::ops::Deref for Locked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unimplemented!("{OFF_HOST}")
    }
}

/// One substate leaf under a role.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cell<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Cell<T> {
    /// A fresh coherent read.
    #[must_use]
    pub fn get(&self) -> T {
        unimplemented!("{OFF_HOST}")
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn set(&mut self, value: T) {
        let _ = value;
        unimplemented!("{OFF_HOST}")
    }
}

/// A family of leaves under one role, keyed by an address.
///
/// The canonical case is a vault family keyed by resource: `self.vaults.at(
/// funds.resource())` is the vault the arriving bucket belongs in, and the
/// key is pure computation over the argument, so another shard can name it
/// without reading anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keyed<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Keyed<T> {
    /// The leaf at `key`.
    #[must_use]
    pub fn at(&self, key: Address) -> Slot<T> {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }
}

/// An open handle on one leaf.
#[derive(Clone, Copy, Debug)]
pub struct Slot<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Slot<T> {
    /// A fresh coherent read.
    #[must_use]
    pub fn get(&self) -> T {
        unimplemented!("{OFF_HOST}")
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn set(&mut self, value: T) {
        let _ = value;
        unimplemented!("{OFF_HOST}")
    }
}

impl Slot<Amount> {
    /// A commutative credit; no declared amount, so it commutes with every
    /// other movement on the same cell.
    pub fn add(&mut self, amount: Amount) {
        let _ = amount;
        unimplemented!("{OFF_HOST}")
    }

    /// A commutative debit.
    pub fn sub(&mut self, amount: Amount) {
        let _ = amount;
        unimplemented!("{OFF_HOST}")
    }

    /// A conditional decrement, judged feasible against the declared
    /// amount, yielding the value edge it moved.
    #[must_use]
    pub fn reserve(&mut self, amount: Amount) -> Bucket {
        let _ = amount;
        unimplemented!("{OFF_HOST}")
    }
}

/// An ordered collection under one role.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ordered<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Ordered<T> {
    /// The entry at one order key.
    #[must_use]
    pub fn at(&self, order: Amount) -> Slot<T> {
        let _ = order;
        unimplemented!("{OFF_HOST}")
    }

    /// A declared interval of the order-key space.
    ///
    /// `cap` bounds the entries execution may touch and must be a literal:
    /// it is the work bound, so it is declaration rather than data. The
    /// interval's own magnitude is what `footprint` charges.
    #[must_use]
    pub fn range(&self, lo: Amount, hi: Amount, cap: u32) -> Interval<T> {
        let _ = (lo, hi, cap);
        unimplemented!("{OFF_HOST}")
    }
}

/// An open handle on a declared interval.
#[derive(Clone, Copy, Debug)]
pub struct Interval<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Interval<T> {
    /// Entries currently in the interval, bounded by the declared cap.
    #[must_use]
    pub fn count(&self) -> u32 {
        unimplemented!("{OFF_HOST}")
    }

    /// The order key of the entry at `index`, ascending.
    #[must_use]
    pub fn order(&self, index: u32) -> Amount {
        let _ = index;
        unimplemented!("{OFF_HOST}")
    }

    /// The value of the entry at `index`, ascending.
    #[must_use]
    pub fn entry(&self, index: u32) -> T {
        let _ = index;
        unimplemented!("{OFF_HOST}")
    }

    /// Replace the value at `index`.
    pub fn set(&mut self, index: u32, value: T) {
        let _ = (index, value);
        unimplemented!("{OFF_HOST}")
    }

    /// Insert at `order`, which must lie inside the declared interval.
    pub fn insert(&mut self, order: Amount, value: T) {
        let _ = (order, value);
        unimplemented!("{OFF_HOST}")
    }

    /// Remove the entry at `index`.
    pub fn remove(&mut self, index: u32) {
        let _ = index;
        unimplemented!("{OFF_HOST}")
    }
}

/// A 128-bit order key packed from a primary dimension over a tiebreaker.
#[must_use]
pub const fn pack(hi: u64, lo: u64) -> Amount {
    ((hi as Amount) << 64) | (lo as Amount)
}

/// A deterministic fresh id, unique within this call.
#[must_use]
pub fn fresh_id() -> u64 {
    unimplemented!("{OFF_HOST}")
}
