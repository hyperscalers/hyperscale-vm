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
//! Each handle holds the index the kernel materialized it at, and what
//! turns that index into a call is the target: `crate::guest` borrows
//! the kernel resource an import takes, and [`crate::host`] reaches the
//! session an engine installed. One body, two resolutions, and nothing
//! between them that an author writes.
//!
//! The index is not something an author writes either. A handle reaches
//! a body as an export parameter, in the order the declaration fixed, and
//! what resolves a collection to one of those parameters is the lowering
//! — which is why [`Keyed`], [`Ordered`] and [`Unordered`] have no body
//! on either target: a call to `at` is rewritten to the handle it named,
//! never made. The same holds for [`issue`], [`issued`] and
//! [`fresh_id`], each of which the lowering answers from the declaration.
//! Reaching one at run time is reaching a stub, which is what makes an
//! authoring half that was called directly fail rather than execute.
//!
//! The accessors that do have a guest body are always inlined, because
//! each is one import behind a match on a mode its call site already
//! fixed. [`crate::guest`] states the argument; what it turns on is that
//! an out-of-line dead arm is an `unreachable` the totality scan reads as
//! a fault, and this vocabulary is what every derived body is written in.
//!
//! # The deterministic environment
//!
//! [`clock_ms`], [`randomness`] and [`hash`] are here for the same reason
//! the accessors are: a body is read on one target and run on another, so
//! everything it can name has to exist on both. They declare nothing —
//! each is identical on every replica by construction rather than by
//! exclusion — which is what separates them from a state read and why no
//! clause follows from calling one.

use hyperscale_vm_effects::Address;

#[cfg(not(target_arch = "wasm32"))]
use crate::host;
pub use crate::num::{MathError, Quantity, Rate, Ratio, Rounding, UnitFixed};

/// An unsigned amount, in the kernel's cell width.
pub type Amount = u128;

const OFF_HOST: &str = "the lowering answers this from the declaration — reaching it means a \
                        body was called directly rather than through the walk that materializes \
                        its capabilities";

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

impl Cellular for Quantity {
    /// The same sixteen little-endian bytes an amount cell has always
    /// held: the tag is the guest's and erases here, where a cell is a
    /// width and nothing else.
    fn from_cell(cell: &[u8]) -> Self {
        Self::from_subunits(cell.try_into().map_or(0, u128::from_le_bytes))
    }

    fn to_cell(&self) -> Vec<u8> {
        self.subunits().to_le_bytes().to_vec()
    }
}

impl Cellular for UnitFixed {
    /// # Panics
    ///
    /// On a cell holding a value above one. The range is checked where
    /// the value enters state, so a cell that holds a wider one was never
    /// written through a constructor — a defect in state rather than in
    /// the call that found it, on the same terms a malformed address is,
    /// and the trap is the deterministic answer to it.
    fn from_cell(cell: &[u8]) -> Self {
        let scaled = cell.try_into().map_or(0, u128::from_le_bytes);
        Self::new(scaled).expect("a bounded configuration cell")
    }

    fn to_cell(&self) -> Vec<u8> {
        self.scaled().to_le_bytes().to_vec()
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

impl Cellular for Address {
    /// # Panics
    ///
    /// On a cell that is not a well-formed address. The kernel builds one
    /// by evaluating the declaration, so a malformed one is a defect and
    /// the trap is the deterministic answer to it.
    fn from_cell(cell: &[u8]) -> Self {
        let bytes: [u8; 32] = cell.try_into().expect("an address cell is 32 bytes");
        Self::from_bytes(bytes).expect("an address cell names a class")
    }

    fn to_cell(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
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

pub use crate::handle::Handle;

/// A value edge: a resource and an amount in flight between components.
///
/// Only the resource is ever declared. The amount is dynamic and never
/// reaches the DSL, which is what lets one declaration cover every size of
/// transfer.
///
/// An edge's resource is static and its amount is dynamic, so the two
/// are known in different places: the amount crosses the boundary, and
/// the resource is the declaration's — which is why the field is carried
/// only where there is a declaration to read it from, on the same terms
/// [`Slot`] carries a handle only where there is a kernel to call.
///
/// A guest that wants the resource is asking for a value the kernel
/// evaluates, and `#[blueprint]` binds one — but only where a body
/// genuinely reads it, so an edge that is merely moved or returned costs
/// nothing.
/// Not `Copy`, and not `Clone`, on either target. The authoring half is
/// where an author's own tokens are type-checked — the guest build
/// compiles the rewritten export bodies instead — so a bucket that
/// duplicated here would let a body spend one edge twice and be told
/// about it, if at all, by a borrow error against generated code. What
/// makes the two halves agree is that value is linear in both.
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq, Eq))]
pub struct Bucket {
    #[cfg(not(target_arch = "wasm32"))]
    rep: u32,
    #[cfg(target_arch = "wasm32")]
    handle: crate::guest::kernel::state::Bucket,
}

impl Bucket {
    /// The edge an export was handed, under the name its author gave it.
    ///
    /// Called by generated code, never by an author: the only ways to
    /// hold value are to be handed some, to take some from a cell the
    /// method declared, and to issue some, and none of them is a
    /// constructor a body can reach.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub const fn held(handle: crate::guest::kernel::state::Bucket) -> Self {
        Self { handle }
    }

    /// The handle the kernel holds this value behind.
    #[cfg(target_arch = "wasm32")]
    #[must_use]
    pub fn into_handle(self) -> crate::guest::kernel::state::Bucket {
        self.handle
    }

    /// The edge the kernel holds at `rep`.
    ///
    /// Called by generated code, never by an author, on the same terms
    /// the guest's own constructor is: the ways to hold value are to be
    /// handed some, to take some from a declared cell, and to issue
    /// some, and none of them is a constructor a body can reach.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub const fn at(rep: u32) -> Self {
        Self { rep }
    }

    /// The table position the kernel holds this value at.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub const fn rep(&self) -> u32 {
        self.rep
    }

    /// The resource this edge carries, as the declaration names it.
    ///
    /// Read by the authoring half and never by the executing one: the
    /// lowering resolves it to a value the export is handed, so a body
    /// that asks reads an argument rather than an edge.
    #[must_use]
    pub fn resource(&self) -> Address {
        unimplemented!("{OFF_HOST}")
    }

    /// Split `amount` off, as a bucket.
    ///
    /// The one way a body composes value without a cell in it: what comes
    /// off and what is left are one subtraction the kernel performs, so
    /// a body dividing an edge writes down neither half.
    #[must_use]
    pub fn take(&mut self, quantity: Quantity) -> Self {
        let amount = quantity.subunits();
        let _ = amount;
        #[cfg(target_arch = "wasm32")]
        return Self::held(crate::guest::bucket_take(&self.handle, amount));
        #[cfg(not(target_arch = "wasm32"))]
        return Self::at(host::bucket_take(self.rep, amount));
    }

    /// Merge `other` in, consuming it.
    #[allow(clippy::needless_pass_by_value)] // a merge consumes what it takes
    pub fn put(&mut self, other: Self) {
        let _ = &other;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::bucket_put(&self.handle, other.into_handle());
        #[cfg(not(target_arch = "wasm32"))]
        return host::bucket_put(self.rep, other.rep());
    }

    /// How much is in hand.
    ///
    /// A borrow of the handle, so asking moves nothing. A body needs it
    /// wherever its own arithmetic turns on what it was paid — a curve, a
    /// budget, a receipt — and it is the one question about value that
    /// cannot produce any.
    #[must_use]
    pub fn quantity(&self) -> Quantity {
        #[cfg(target_arch = "wasm32")]
        return Quantity::from_subunits(crate::guest::bucket_amount(&self.handle));
        #[cfg(not(target_arch = "wasm32"))]
        return Quantity::from_subunits(host::bucket_amount(self.rep));
    }
}

/// A non-fungible value edge: the instances it moves rather than an
/// amount.
///
/// The same object, because a bucket is one thing — what separates the
/// two kinds is the cell they cross as, which is the declaration's
/// answer. Naming this in a signature is how a method says which kind it
/// consumes.
pub type NfBucket = Bucket;

/// Issue `amount` of the resource this instance derives from `mark`.
///
/// The one place value appears with no cell debited behind it, and it is
/// the instance's own resource by construction — `mark` separates one of
/// its resources from another exactly as [`issued`] derives an address
/// from one. The authority is a handle the kernel grants against this
/// method's declared outputs, so a body that never said it produces what
/// it issues has none.
#[must_use]
pub fn issue(mark: &[u8], quantity: Quantity) -> Bucket {
    let amount = quantity.subunits();
    let _ = (mark, amount);
    unimplemented!("{OFF_HOST}")
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

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl<T: Cellular> Cell<T> {
    /// A fresh coherent read.
    #[must_use]
    #[inline(always)]
    pub fn get(&self) -> T {
        unimplemented!("{OFF_HOST}")
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    #[inline(always)]
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
    ///
    /// The key is whatever material the declaration hashes under the
    /// field's role — an address is the commonest case and not the only
    /// one, and what makes any of them declarable is being derivable
    /// from the call's own inputs.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn at<K>(&self, key: K) -> Slot<T> {
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
    handle: Handle,
    _value: core::marker::PhantomData<fn() -> T>,
}

impl<T> Slot<T> {
    /// The leaf this materialized handle names.
    ///
    /// Called by generated code, never by an author: which handle a
    /// collection resolves to is the declaration's order, and which mode
    /// it carries is what the body's own accessors decided.
    #[must_use]
    pub const fn at(handle: Handle) -> Self {
        Self {
            handle,
            _value: core::marker::PhantomData,
        }
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl<T: Cellular> Slot<T> {
    /// A fresh coherent read.
    #[must_use]
    #[inline(always)]
    pub fn get(&self) -> T {
        #[cfg(target_arch = "wasm32")]
        return T::from_cell(&crate::guest::cell_get(self.handle));
        #[cfg(not(target_arch = "wasm32"))]
        return T::from_cell(&host::cell_get(self.handle));
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // the authoring stub consumes nothing
    #[inline(always)]
    pub fn set(&mut self, value: T) {
        let _ = &value;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::cell_set(self.handle, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        return host::cell_set(self.handle, &value.to_cell());
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl Slot<Quantity> {
    /// Move value into the cell, consuming the bucket.
    ///
    /// What lands is exactly what crossed: the body names no amount, so
    /// there is no second number for the credit to disagree with.
    #[inline(always)]
    #[allow(clippy::needless_pass_by_value)] // the credit consumes the edge; off host nothing runs
    pub fn put(&mut self, funds: Bucket) {
        let _ = &funds;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::cell_put(self.handle, funds.into_handle());
        #[cfg(not(target_arch = "wasm32"))]
        return host::cell_put(self.handle, funds.rep());
    }

    /// Move value out of the cell, as the bucket it becomes.
    ///
    /// The debit and the value now in hand are one operation, so a body
    /// cannot debit one number and hand back another.
    #[must_use]
    #[inline(always)]
    pub fn take(&mut self, quantity: Quantity) -> Bucket {
        let amount = quantity.subunits();
        let _ = amount;
        #[cfg(target_arch = "wasm32")]
        return Bucket::held(crate::guest::cell_take(self.handle, amount));
        #[cfg(not(target_arch = "wasm32"))]
        return Bucket::at(host::cell_take(self.handle, amount));
    }

    /// Declare a movement on this cell without making one.
    ///
    /// A method whose declaration has to cover a cell it does not always
    /// reach — a deposit that lands in the claims cell when the vault
    /// refuses it — has no value to move on the path that does not. The
    /// clause is what the kernel provisions and what a caller routes on,
    /// so it is stated here and exercised elsewhere; the handle is never
    /// opened, because there is nothing to do with it.
    #[inline(always)]
    pub const fn declared(&mut self) {}

    /// Take the reservation this method declared, as the value it grants.
    ///
    /// Feasibility was judged and the hold taken before this body ran, so
    /// the grant is the bucket and there is no amount to name. Once per
    /// reservation: the kernel refuses a second take of one grant, where
    /// the read this replaces answered every time it was asked.
    #[must_use]
    #[inline(always)]
    pub fn reserve(&mut self, quantity: Quantity) -> Bucket {
        let amount = quantity.subunits();
        let _ = amount;
        #[cfg(target_arch = "wasm32")]
        return Bucket::held(crate::guest::reserve_take(self.handle));
        #[cfg(not(target_arch = "wasm32"))]
        return Bucket::at(host::reserve_take(self.handle));
    }
}

/// An ordered collection under one role.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ordered<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Ordered<T> {
    /// The sub-collection this role holds at `key`.
    ///
    /// A collection is named by its owner, its role and the material
    /// folded into it, exactly as a keyed leaf is — so a family of
    /// collections is one collection per key rather than a shape of its
    /// own, and everything below reads the same under a key as without
    /// one. A holder's instances per resource are the canonical case.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn of<K>(&self, key: K) -> Self {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }

    /// The entry at one order key.
    #[must_use]
    pub fn at(&self, order: Amount) -> Entry<T> {
        let _ = order;
        unimplemented!("{OFF_HOST}")
    }

    /// The whole order-key space, at most `cap` entries of it.
    ///
    /// `cap` bounds the entries execution may touch and must be a literal,
    /// on the same terms [`Self::range`] states.
    #[must_use]
    pub fn all(&self, cap: u32) -> Interval<T> {
        let _ = cap;
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
    pub fn at<K>(&self, key: K) -> Entry<T> {
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

/// An open handle on one entry of a collection.
///
/// A collection's leaves live in an interval rather than at a key of
/// their own, so the handle the kernel materializes covers the interval
/// and the entry's own order is what picks it out — which is why an entry
/// carries the order beside the handle where a [`Slot`] carries only the
/// handle.
#[derive(Clone, Copy, Debug)]
pub struct Entry<T> {
    handle: Handle,
    order: Amount,
    _value: core::marker::PhantomData<fn() -> T>,
}

impl<T> Entry<T> {
    /// The entry at `order` of the interval this handle names, on the
    /// terms [`Slot::at`] describes.
    #[must_use]
    pub const fn at(handle: Handle, order: Amount) -> Self {
        Self {
            handle,
            order,
            _value: core::marker::PhantomData,
        }
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl<T: Cellular> Entry<T> {
    /// A fresh coherent read.
    #[must_use]
    #[inline(always)]
    pub fn get(&self) -> T {
        #[cfg(target_arch = "wasm32")]
        return T::from_cell(&crate::guest::entry_at(self.handle, self.order));
        #[cfg(not(target_arch = "wasm32"))]
        return T::from_cell(&host::entry_at(self.handle, self.order));
    }

    /// An exclusive read-modify-write. Writing an entry that is not there
    /// creates it, which is what makes one accessor cover both.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn set(&mut self, value: T) {
        let _ = &value;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_insert(self.handle, self.order, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_insert(self.handle, self.order, &value.to_cell());
    }
}

/// An open handle on a declared interval.
#[derive(Clone, Copy, Debug)]
pub struct Interval<T> {
    handle: Handle,
    _value: core::marker::PhantomData<fn() -> T>,
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl<T> Interval<T> {
    /// The interval this materialized handle names, on the terms
    /// [`Slot::at`] describes.
    #[must_use]
    pub const fn at(handle: Handle) -> Self {
        Self {
            handle,
            _value: core::marker::PhantomData,
        }
    }

    /// Entries currently in the interval, bounded by the declared cap.
    #[must_use]
    #[inline(always)]
    pub fn count(&self) -> u32 {
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_count(self.handle);
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_count(self.handle);
    }

    /// The order key of the entry at `index`, ascending.
    #[must_use]
    #[inline(always)]
    pub fn order(&self, index: u32) -> Amount {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_order(self.handle, index);
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_order(self.handle, index);
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl<T: Cellular> Interval<T> {
    /// The value of the entry at `index`, ascending.
    #[must_use]
    #[inline(always)]
    pub fn entry(&self, index: u32) -> T {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return T::from_cell(&crate::guest::entry_get(self.handle, index));
        #[cfg(not(target_arch = "wasm32"))]
        return T::from_cell(&host::entry_get(self.handle, index));
    }

    /// Replace the value at `index`.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn set(&mut self, index: u32, value: T) {
        let _ = (index, &value);
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_set(self.handle, index, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_set(self.handle, index, &value.to_cell());
    }

    /// Insert at `order`, which must lie inside the declared interval.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn insert(&mut self, order: Amount, value: T) {
        let _ = (order, &value);
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_insert(self.handle, order, &value.to_cell());
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_insert(self.handle, order, &value.to_cell());
    }

    /// Remove the entry at `index`.
    #[inline(always)]
    pub fn remove(&mut self, index: u32) {
        let _ = index;
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_remove(self.handle, index);
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_remove(self.handle, index);
    }

    /// File the instances a bucket carries, each at the order it was
    /// taken under, holding `value`.
    ///
    /// The filing is the kernel's, so a body hands the bucket over rather
    /// than walking it: an instance's id is its order key, and no
    /// accessor hands one back.
    ///
    /// One value for the whole set, so it crosses as the bytes the kernel
    /// stores rather than as a leaf encoded per instance — which is also
    /// what keeps a body filing a marker away from the allocator, and so
    /// eligible for the total mark.
    #[inline(always)]
    #[allow(clippy::needless_pass_by_value)] // the filing consumes the edge; off host nothing runs
    pub fn put(&mut self, funds: Bucket, value: &[u8]) {
        let _ = (&funds, value);
        #[cfg(target_arch = "wasm32")]
        return crate::guest::entry_put(self.handle, funds.into_handle(), value);
        #[cfg(not(target_arch = "wasm32"))]
        return host::entry_put(self.handle, funds.rep(), value);
    }

    /// Take the named instances out, as the bucket they become.
    ///
    /// The removal and the edge are one operation, exactly as a debit and
    /// its bucket are, so a body cannot hand on instances it left where
    /// they were. An id the collection does not hold refuses here.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // the take consumes the ids it names
    #[inline(always)]
    pub fn take(&mut self, ids: Ids) -> Bucket {
        let _ = &ids;
        #[cfg(target_arch = "wasm32")]
        return Bucket::held(crate::guest::entry_take(self.handle, ids.bytes()));
        #[cfg(not(target_arch = "wasm32"))]
        return Bucket::at(host::entry_take(self.handle, ids.bytes()));
    }
}

/// Take the reservation a declared handle grants, as the value it is.
///
/// Called by generated code, never by an author: the amount was judged
/// and held before the body ran, so what the lowering rewrites a
/// `reserve` to names no amount at all.
#[doc(hidden)]
#[must_use]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always)]
pub fn take_reservation(handle: Handle) -> Bucket {
    #[cfg(target_arch = "wasm32")]
    return Bucket::held(crate::guest::reserve_take(handle));
    #[cfg(not(target_arch = "wasm32"))]
    return Bucket::at(host::reserve_take(handle));
}

/// Create `amount` under this invocation's issuance grant.
///
/// Called by generated code, never by an author: the grant is a handle
/// the kernel lowered against the method's own declared outputs, and
/// which resource it creates is what the mark already fixed.
#[doc(hidden)]
#[must_use]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always)]
pub fn issue_granted(grant: u32, quantity: Quantity) -> Bucket {
    #[cfg(target_arch = "wasm32")]
    return Bucket::held(crate::guest::issue(grant, quantity.subunits()));
    #[cfg(not(target_arch = "wasm32"))]
    return Bucket::at(host::issue(grant, quantity.subunits()));
}

/// A 128-bit order key packed from a primary dimension over a tiebreaker.
#[must_use]
pub const fn pack(hi: u64, lo: u64) -> Amount {
    ((hi as Amount) << 64) | (lo as Amount)
}

/// A resource this instance issues, separated from its others by `mark`.
///
/// Derived from the instance rather than configured: an instance's
/// address commits its configuration, so a configured field naming a
/// value derived from that address would not be expressible. Pass an
/// empty mark for the instance's primary issue, and a distinguishing one
/// for anything beside it — a badge that operates the instance is the
/// same derivation over different material.
#[must_use]
pub fn issued(mark: &[u8]) -> Address {
    let _ = mark;
    unimplemented!("{OFF_HOST}")
}

/// A deterministic fresh id, unique within this call.
#[must_use]
pub fn fresh_id() -> u64 {
    unimplemented!("{OFF_HOST}")
}

/// The transaction clock, in milliseconds.
///
/// The canonical weighted-time anchor of the block that committed this
/// transaction — identical on every replica by construction, which is
/// what separates it from a wall clock a body must never read.
#[must_use]
pub fn clock_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    return crate::guest::clock_ms();
    #[cfg(not(target_arch = "wasm32"))]
    return host::clock_ms();
}

/// The transaction's randomness draw: 32 bytes, domain-separated per
/// transaction.
#[must_use]
pub fn randomness() -> Vec<u8> {
    #[cfg(target_arch = "wasm32")]
    return crate::guest::randomness();
    #[cfg(not(target_arch = "wasm32"))]
    return host::randomness();
}

/// The protocol hash function: a 32-byte digest.
///
/// The host's, never a guest's own — a package carrying its own
/// implementation would be a second answer to a question the protocol
/// has already fixed.
#[must_use]
pub fn hash(data: &[u8]) -> Vec<u8> {
    let _ = data;
    #[cfg(target_arch = "wasm32")]
    return crate::guest::hash(data);
    #[cfg(not(target_arch = "wasm32"))]
    return host::hash(data);
}

/// An authority rule parameter, as a contract signature names it.
///
/// The rule arrives as canonical bytes the admission gate already decoded
/// under the vocabulary caps, so a body carries them and judges nothing.
#[derive(Clone, Debug, Default)]
pub struct Rule(pub Vec<u8>);

/// A role-set parameter, as a contract signature names it. The same
/// shape as [`Rule`], for the three-rule form the stored-authority cell
/// holds.
#[derive(Clone, Debug, Default)]
pub struct RoleSet(pub Vec<u8>);

/// A set of non-fungible instance ids, as a contract signature names it.
///
/// Signed manifest content, carried in the framing a declared id list
/// crosses in — so a method moving the ids it was given passes them
/// straight through and reads none of them.
#[derive(Clone, Debug, Default)]
pub struct Ids(pub Vec<u8>);

macro_rules! opaque_bytes {
    ($($ty:ident),*) => {
        $(
            impl $ty {
                /// The canonical bytes, which is all a body may do with
                /// one: what they mean was settled at admission.
                #[must_use]
                pub fn bytes(&self) -> &[u8] {
                    &self.0
                }
            }

            impl Cellular for $ty {
                fn from_cell(cell: &[u8]) -> Self {
                    Self(cell.to_vec())
                }

                fn to_cell(&self) -> Vec<u8> {
                    self.0.clone()
                }
            }
        )*
    };
}

opaque_bytes!(Rule, RoleSet, Ids);
