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
//! # Two builds, one vocabulary
//!
//! Host builds carry no kernel, so the bodies are never executed there —
//! `#[blueprint]` reads them, it does not run them, and every accessor
//! panics if reached. Guest builds carry the imports, and the same
//! accessors are the calls: each handle holds the index the kernel
//! materialized it at, and [`crate::guest`] turns that index back into a
//! borrow for the duration of one call.
//!
//! The index is not something an author writes. A handle reaches a body
//! as an export parameter, in the order the declaration fixed, and what
//! resolves a collection to one of those parameters is the lowering —
//! which is why [`Keyed`], [`Ordered`] and [`Unordered`] have no guest
//! body: a call to `at` is rewritten to the handle it named, never made.

use hyperscale_vm_effects::Address;

/// An unsigned amount, in the kernel's cell width.
pub type Amount = u128;

const OFF_HOST: &str = "contract bodies execute in the guest, never on the host — \
                        `#[blueprint]` reads this body, it does not run it";

/// A value a declared cell or entry can hold.
///
/// The kernel's substates are bytes; this is the vocabulary's statement
/// of which Rust values it will carry them as. Closed on purpose — a
/// contract that could name any encoding would put an author's choice
/// where a protocol representation belongs.
pub trait Cellular: Sized {
    /// Read the value from a substate. An absent substate reads empty,
    /// which every implementation takes as its zero.
    fn from_cell(cell: &[u8]) -> Self;

    /// The substate representation of this value.
    fn to_cell(&self) -> Vec<u8>;
}

impl Cellular for Amount {
    fn from_cell(cell: &[u8]) -> Self {
        cell.try_into().map_or(0, Self::from_le_bytes)
    }

    fn to_cell(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl Cellular for u64 {
    fn from_cell(cell: &[u8]) -> Self {
        cell.try_into().map_or(0, Self::from_le_bytes)
    }

    fn to_cell(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl Cellular for Vec<u8> {
    fn from_cell(cell: &[u8]) -> Self {
        cell.to_vec()
    }

    fn to_cell(&self) -> Vec<u8> {
        self.clone()
    }
}

/// The materialized handle a guest-side accessor calls through.
///
/// Carried only where there is a kernel to call. On the host the field
/// would name a table that does not exist, and a type that had one would
/// invite an author to write it down.
#[cfg(target_arch = "wasm32")]
pub use crate::guest::Handle;

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

impl<T: Cellular> Cell<T> {
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
///
/// Which mode the handle carries is fixed by the accessor the body
/// reaches for, not by the type: `get`/`set` is exclusive, `add`/`sub`
/// commutative, `reserve` conditional. That is the whole reason the
/// vocabulary is closed — the declaration is read off which of these a
/// body calls.
#[derive(Clone, Copy, Debug)]
pub struct Slot<T> {
    #[cfg(target_arch = "wasm32")]
    handle: Handle,
    _value: core::marker::PhantomData<fn() -> T>,
}

impl<T> Slot<T> {
    /// The leaf this materialized handle names.
    ///
    /// Called by generated code, never by an author: which handle a
    /// collection resolves to is the declaration's order, and which mode
    /// it carries is what the body's own accessors decided.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub const fn at(handle: Handle) -> Self {
        Self {
            handle,
            _value: core::marker::PhantomData,
        }
    }
}

impl<T: Cellular> Slot<T> {
    /// A fresh coherent read.
    #[must_use]
    pub fn get(&self) -> T {
        #[cfg(target_arch = "wasm32")]
        return T::from_cell(&crate::guest::cell_get(self.handle));
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // the authoring stub consumes nothing
    pub fn set(&mut self, value: T) {
        let _ = &value;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::cell_set(self.handle, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }
}

impl Slot<Amount> {
    /// A commutative credit; no declared amount, so it commutes with every
    /// other movement on the same cell.
    pub fn add(&mut self, amount: Amount) {
        let _ = amount;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::delta_add(self.handle, amount);
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// A commutative debit.
    pub fn sub(&mut self, amount: Amount) {
        let _ = amount;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::delta_sub(self.handle, amount);
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// A conditional decrement, judged feasible against the declared
    /// amount, yielding the value edge it moved.
    ///
    /// The declared amount is what admission judged and the kernel
    /// granted before this body ran, so the guest reads the reservation
    /// rather than performing one — a reserve handle is already the
    /// answer.
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

/// An unordered collection under one role: entries keyed by hash.
///
/// The same kernel kind as [`Ordered`], with the order key derived by
/// hashing the logical key — arbitrary-but-canonical placement, which is
/// what "unordered" means operationally. Point access by key stays pure
/// computation; [`Self::sweep`] walks the hash order from a cursor, so
/// iteration is a paginated crank rather than an unbounded scan.
///
/// A sweep yields entries, not keys — the order key is a truncated hash
/// and cannot be inverted — so a collection whose sweeps need the logical
/// key stores it inside the entry value.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unordered<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Unordered<T> {
    /// The entry at `key`. The key must be derivable from the method's
    /// arguments or the component's configuration, like any declared
    /// target.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn at<K>(&self, key: K) -> Slot<T> {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }

    /// Up to `cap` entries from `cursor`, in hash order.
    ///
    /// Resume by passing the last visited order key plus one as the next
    /// call's cursor; `0` starts the walk. `cap` must be a literal — it is
    /// the work bound, so it is declaration rather than data.
    #[must_use]
    pub fn sweep(&self, cursor: Amount, cap: u32) -> Interval<T> {
        let _ = (cursor, cap);
        unimplemented!("{OFF_HOST}")
    }
}

/// An open handle on a declared interval.
#[derive(Clone, Copy, Debug)]
pub struct Interval<T> {
    #[cfg(target_arch = "wasm32")]
    handle: Handle,
    _value: core::marker::PhantomData<fn() -> T>,
}

impl<T> Interval<T> {
    /// The interval this materialized handle names, on the terms
    /// [`Slot::at`] describes.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub const fn at(handle: Handle) -> Self {
        Self {
            handle,
            _value: core::marker::PhantomData,
        }
    }

    /// Entries currently in the interval, bounded by the declared cap.
    #[must_use]
    pub fn count(&self) -> u32 {
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_count(self.handle);
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// The order key of the entry at `index`, ascending.
    #[must_use]
    pub fn order(&self, index: u32) -> Amount {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_order(self.handle, index);
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }
}

impl<T: Cellular> Interval<T> {
    /// The value of the entry at `index`, ascending.
    #[must_use]
    pub fn entry(&self, index: u32) -> T {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return T::from_cell(&crate::guest::entry_get(self.handle, index));
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// Replace the value at `index`.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    pub fn set(&mut self, index: u32, value: T) {
        let _ = (index, &value);
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_set(self.handle, index, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// Insert at `order`, which must lie inside the declared interval.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    pub fn insert(&mut self, order: Amount, value: T) {
        let _ = (order, &value);
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_insert(self.handle, order, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        unimplemented!("{OFF_HOST}")
    }

    /// Remove the entry at `index`.
    pub fn remove(&mut self, index: u32) {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_remove(self.handle, index);
        #[cfg(not(target_arch = "wasm32"))]
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

/// An authority rule parameter, as a contract signature names it. Off
/// guest it is a marker: the rule arrives as canonical bytes the
/// admission gate already decoded under the vocabulary caps.
#[derive(Clone, Debug, Default)]
pub struct Rule(pub Vec<u8>);

/// A role-set parameter, as a contract signature names it. The same
/// marker shape as [`Rule`], for the three-rule form the
/// stored-authority cell holds.
#[derive(Clone, Debug, Default)]
pub struct RoleSet(pub Vec<u8>);
