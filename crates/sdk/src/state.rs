//! The state vocabulary a contract body is written against.
//!
//! Every one of these types exists to make the access mode *derivable*.
//! State is reachable only through the handles here, and each method on
//! them names exactly one point of the mode lattice — `add` is commutative,
//! `reserve` is conditional, `set` is exclusive.
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
//! turns that index into a call is which of the two this build is:
//! `crate::guest` borrows the kernel resource an import takes, and
//! [`crate::host`] reaches the session an engine installed. One body,
//! two resolutions, and nothing between them that an author writes.
//!
//! The index is not something an author writes either. A handle reaches
//! a body as an export parameter, in the order the declaration fixed, and
//! what resolves a collection to one of those parameters is the lowering
//! — which is why [`Keyed`], [`Ordered`] and [`Unordered`] have no body
//! on either target: a call to `at` is rewritten to the handle it named,
//! never made. The same holds for `<Resource>::mint(..)`,
//! `issued(<Resource>)` and [`fresh_id`], each of which the lowering
//! answers from the declaration — `issued` all the way down to the name,
//! which resolves to no function at all. Reaching a stub at run time is what makes an
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

use hyperscale_hbor::{
    DEFAULT_MAX_DEPTH, Hbor, HborDecode, HborEncode, from_slice_with_depth, to_vec_with_depth,
};
/// The record a resource's cell holds, in the shape a client reads.
///
/// Named here for the code the macro emits: a body never constructs one —
/// `create` on the record handle states at most a display width, and the
/// kind comes from the mark's own declaration.
pub use hyperscale_vm_effects::ResourceRecord;
/// The stored-authority vocabulary, named where a body's words live.
///
/// A role-table parameter is [`RoleTable`] — the same type a cell holds,
/// so a body that stores what it was handed converts nothing. The table's
/// skeleton is legible here; each rule's bytes stay opaque, decoded only
/// where a rule is judged.
pub use hyperscale_vm_effects::{AuthBase, AuthCell, Proposal, RoleBytes, RoleTable};
use hyperscale_vm_effects::{MAX_AUTH_CELL_WIRE_DEPTH, RECORD_WIRE_DEPTH};
use hyperscale_vm_types::{Address, CellKind, ResourceAddr};

#[cfg(not(component))]
use crate::host;
pub use crate::num::{Fixed, NumError, Quantity, Rate, Ratio, Rounding, UnitFixed, Wide};

/// Where an entry sits in a collection's ordering.
///
/// The kernel's cell width, in the one job it still has here: a
/// collection is ordered by this and a range is bounded by two of them.
/// Not a quantity and never conserved — what a leaf *holds* is a
/// [`Quantity`], and the two stopped being one type when the vocabulary
/// they were sharing was split.
pub type OrderKey = u128;

const OFF_HOST: &str = "the lowering answers this from the declaration — reaching it means a \
                        body was called directly rather than through the walk that materializes \
                        its capabilities";

/// A lookup table a package holds in its configuration.
///
/// The kernel's form is a list of `(key, value)` pairs, and the DSL walks
/// it with `Lookup` and `Contains`. This is that shape as a body names
/// it: a configuration field typed here reads `settings.routes.get(k)`
/// and `settings.routes.contains(k)`, and the lowering answers both from
/// the declaration.
///
/// So both methods are [`OFF_HOST`] stubs, like [`Bucket::resource`]. The
/// pairs are carried because whoever *creates* the instance writes them
/// down — a table is one configuration slot, and the value in that slot
/// is these rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table<K, V>(Vec<(K, V)>);

impl<K, V> Table<K, V> {
    /// The table holding `rows`.
    ///
    /// First match wins, as the walk reads it, so a key written twice
    /// takes the earlier row.
    #[must_use]
    pub const fn new(rows: Vec<(K, V)>) -> Self {
        Self(rows)
    }

    /// The rows, in the order a lookup walks them.
    #[must_use]
    pub fn rows(&self) -> &[(K, V)] {
        &self.0
    }

    /// The rows, owned — what the creation path encodes into the slot.
    #[must_use]
    pub fn into_rows(self) -> Vec<(K, V)> {
        self.0
    }

    /// The value at `key`.
    ///
    /// A miss is a routing refusal, so a package that would rather answer
    /// guards this on [`Table::contains`] — the untaken arm of a
    /// selection is never evaluated.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn get(&self, key: K) -> V {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }

    /// Whether the table holds `key`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn contains(&self, key: K) -> bool {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }
}

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

/// A type held in a cell as its own HBOR encoding.
///
/// The counterweight to [`Cellular`]'s closed vocabulary, and it does not
/// reopen it. What the closure argues against is an *author choosing a
/// format*, which puts a private decision where a protocol representation
/// belongs; a record chooses nothing — the author names fields and the
/// encoding is the protocol's, the same one every wire form in the system
/// already uses.
///
/// A record reaches a cell as `Cell<Option<T>>` and never as `Cell<T>`,
/// through the one blanket implementation below. That is what keeps
/// absence distinguishable: `Cellular` reads an absent substate as empty
/// bytes and every implementation takes that as its zero, and a struct has
/// no zero — HBOR decodes no fields from nothing. `None` is the zero the
/// type does have, so an unwritten cell reads as the absence it is rather
/// than as a record nobody stored.
pub trait Record: HborEncode + HborDecode {
    /// The decoder nesting cap this type is read under.
    ///
    /// The default is the encoder's own, which is the right bound for a
    /// record only its own package writes. A type whose content a caller
    /// supplies states a tighter one, so the admissible set is exact
    /// rather than merely bounded.
    const WIRE_DEPTH: usize = DEFAULT_MAX_DEPTH;
}

/// A record's cell: its encoding, or no bytes at all.
///
/// # Panics
///
/// On stored bytes that are not this record. Only the package owning the
/// cell writes it, so bytes that do not decode are a defect in state
/// rather than in the call that found them, and the trap is the
/// deterministic answer to it — the same standing an address cell has.
/// The readers that must *not* trap on one read the bytes directly and
/// fail closed there.
impl<T: Record> Cellular for Option<T> {
    fn from_cell(cell: &[u8]) -> Self {
        (!cell.is_empty())
            .then(|| from_slice_with_depth(cell, T::WIRE_DEPTH).expect("a well-formed record cell"))
    }

    fn to_cell(&self) -> Vec<u8> {
        self.as_ref().map_or_else(Vec::new, |record| {
            to_vec_with_depth(record, T::WIRE_DEPTH).expect("a record within its own cap")
        })
    }
}

/// The account's stored-authority cell, written on behalf of the crate
/// that defines it: [`crate::AuthCell`] is `hyperscale-vm-effects`', and
/// that crate does not depend on the SDK.
impl Record for AuthCell {
    const WIRE_DEPTH: usize = MAX_AUTH_CELL_WIRE_DEPTH;
}

impl Cellular for u128 {
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

impl<A, B> Cellular for Fixed<A, B> {
    /// Thirty-two little-endian bytes, one per limb, least significant
    /// first. A wider cell than an amount, and affordable for the reason
    /// balance cells are not: an index is one leaf per market where a
    /// balance is one per holder, so widening the O(pools) object costs
    /// at a scale widening the O(users) one never could.
    ///
    /// The kernel never parses it. A stored rate is not a bucket, so its
    /// site folds to an exclusive read-modify-write and the commutative
    /// movement semantics that read an amount cell are unreachable for
    /// it.
    fn from_cell(cell: &[u8]) -> Self {
        let mut limbs = [0u64; 4];
        let (chunks, _) = cell.as_chunks::<8>();
        for (limb, chunk) in limbs.iter_mut().zip(chunks) {
            *limb = u64::from_le_bytes(*chunk);
        }
        Self::from_scaled(Wide::from_limbs(limbs))
    }

    fn to_cell(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        for limb in self.scaled().limbs() {
            out.extend_from_slice(&limb.to_le_bytes());
        }
        out
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

/// A collection whose entries carry nothing: the entry existing is the
/// whole of what it says.
///
/// A membership set, an index of what has been seen — each is a
/// collection where the order key names the thing and there is nothing
/// else to store. Presence is read off the entry rather than out of it,
/// which is what every consumer already does: the kernel's own custody
/// check asks whether an entry is in range and never what it holds. A
/// unit collection holds no value, so the instance operations live on
/// [`NfVault`] and not here.
impl Cellular for () {
    fn to_cell(&self) -> Vec<u8> {
        Vec::new()
    }

    fn from_cell(_: &[u8]) -> Self {}
}

impl Cellular for Vec<u8> {
    fn from_cell(cell: &[u8]) -> Self {
        cell.to_vec()
    }

    fn to_cell(&self) -> Vec<u8> {
        self.clone()
    }
}

/// The width every value the protocol draws or digests carries.
pub const WORD_BYTES: usize = 32;

/// A protocol word: the fixed width a draw and a digest both come back
/// at.
///
/// A type rather than the bytes it is, on the same terms the kernel's
/// amount is a type rather than sixteen: the width is the protocol's, so
/// a package carrying it as a byte list would be restating a fact it was
/// never told and checking it at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
#[hbor(transparent, infallible)]
pub struct Word([u8; WORD_BYTES]);

impl Word {
    /// The word's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WORD_BYTES] {
        &self.0
    }

    /// A word from bytes the protocol produced.
    ///
    /// # Panics
    ///
    /// On any other width, which is the environment handing out a value
    /// narrower or wider than the one it fixes.
    #[must_use]
    pub fn from_protocol(bytes: &[u8]) -> Self {
        Self(bytes.try_into().expect("the protocol's own word"))
    }
}

impl Cellular for Word {
    /// # Panics
    ///
    /// On a cell that is not a word. Only the package owning the cell
    /// writes it, so bytes of another width are a defect in state rather
    /// than in the call that found them.
    fn from_cell(cell: &[u8]) -> Self {
        Self::from_protocol(cell)
    }

    fn to_cell(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// The draw a selection is made with.
///
/// Distinct from the [`Word`] it carries, and the distinction is the
/// point. A word is a value: storable, publishable, decodable from
/// anything that holds thirty-two bytes. A draw is a capability — the
/// environment is the only thing that makes one, it has no encoding, and
/// nothing reconstructs it from a cell or an argument. So a selection
/// made with one was made with the environment's own value, and a
/// package cannot pick a winner with bytes a caller supplied by
/// accident.
///
/// Not `Copy`, and every selection consumes it: two picks off one draw
/// are perfectly correlated, and a body that means two independent
/// selections needs two draws rather than one used twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draw(Word);

impl Draw {
    /// The draw as the value it is — what a package publishes beside
    /// what it decided, so a reader can check the one against the other.
    ///
    /// The one-way door: a word never becomes a draw again.
    #[must_use]
    pub const fn word(&self) -> Word {
        self.0
    }

    /// The draw the environment produced, from the bytes it produced it
    /// as. Called by the vocabulary, never by a package.
    #[doc(hidden)]
    #[must_use]
    pub fn from_protocol(bytes: &[u8]) -> Self {
        Self(Word::from_protocol(bytes))
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
#[cfg_attr(not(component), derive(Debug, PartialEq, Eq))]
pub struct Bucket {
    #[cfg(not(component))]
    rep: u32,
    #[cfg(component)]
    handle: crate::guest::kernel::state::Bucket,
}

impl Bucket {
    /// The edge an export was handed, under the name its author gave it.
    ///
    /// Called by generated code, never by an author: the only ways to
    /// hold value are to be handed some, to take some from a cell the
    /// method declared, and to mint some, and none of them is a
    /// constructor a body can reach.
    #[cfg(component)]
    #[must_use]
    pub const fn held(handle: crate::guest::kernel::state::Bucket) -> Self {
        Self { handle }
    }

    /// The handle the kernel holds this value behind.
    #[cfg(component)]
    #[must_use]
    pub fn into_handle(self) -> crate::guest::kernel::state::Bucket {
        self.handle
    }

    /// The edge the kernel holds at `rep`.
    ///
    /// Called by generated code, never by an author, on the same terms
    /// the guest's own constructor is: the ways to hold value are to be
    /// handed some, to take some from a declared cell, and to mint
    /// some, and none of them is a constructor a body can reach.
    #[cfg(not(component))]
    #[must_use]
    pub const fn at(rep: u32) -> Self {
        Self { rep }
    }

    /// The table position the kernel holds this value at.
    #[cfg(not(component))]
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
    pub fn resource(&self) -> ResourceAddr {
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
        #[cfg(component)]
        return Self::held(crate::guest::bucket_take(&self.handle, amount));
        #[cfg(not(component))]
        return Self::at(host::bucket_take(self.rep, amount));
    }

    /// Divide this edge by `share`: the part, and the remainder.
    ///
    /// The primitive a linear value model can have and a non-linear one
    /// cannot. The first output is `floor(held * share)` and the second
    /// is what is left — derived by subtraction inside the kernel, not
    /// computed a second time — so the two sum to the input exactly.
    /// That is conservation by construction: there is no rounding
    /// argument to supply and no way to write the bug where distributed
    /// parts do not sum to the whole.
    ///
    /// One knob decides where the truncated subunit lands, and it is the
    /// argument order: **the party that should absorb the dust is named
    /// second.** A second knob pointing the other way would make the same
    /// question answerable two ways.
    ///
    /// # Panics
    ///
    /// On a share above one, which would leave a negative remainder and
    /// denominates nothing.
    #[must_use]
    pub fn split(mut self, share: Ratio) -> (Self, Self) {
        let (num, den) = share.terms();
        let _ = (num, den);
        #[cfg(component)]
        let part = Self::held(crate::guest::bucket_split(&self.handle, num, den));
        #[cfg(not(component))]
        let part = Self::at(host::bucket_split(self.rep, num, den));
        let _ = &mut self;
        (part, self)
    }

    /// Divide this edge by each share in turn: the parts, and what no
    /// share claimed.
    ///
    /// Every share is of the *whole*, which is what a caller writing a
    /// weight table means, so the parts do not depend on the order they
    /// are taken in. The remainder is returned rather than folded into
    /// the last part: a slice whose shares fall short of one would
    /// otherwise hand its final claimant everything the others left,
    /// which is a silent answer to a question nobody asked — and the
    /// kernel refuses a dropped bucket, so an explicit remainder is one
    /// the body must dispose of rather than one it can ignore.
    ///
    /// Conservation still holds by construction: each part leaves through
    /// the kernel's own subtraction and the remainder is whatever is
    /// still in hand, so no number here is written twice.
    ///
    /// # Panics
    ///
    /// Where the shares claim more than the whole, which the kernel
    /// refuses when a take runs past what is left.
    #[must_use]
    pub fn split_n(mut self, shares: &[Ratio]) -> (Vec<Self>, Self) {
        let whole = self.quantity();
        let mut parts = Vec::with_capacity(shares.len());
        for share in shares {
            parts.push(self.take(whole.scale(*share, Rounding::Down)));
        }
        (parts, self)
    }

    /// Divide this edge by shares that must claim all of it.
    ///
    /// For a distribution where truncating is worse than refusing — a
    /// treasury schedule, a merkle drop — a non-zero remainder is the
    /// refusal, and giving that its own name is cheaper than every such
    /// body asserting on it.
    ///
    /// # Errors
    ///
    /// The parts and the leftover edge, where the shares did not claim
    /// all of it. The caller still holds every piece, which is what lets
    /// it decline without dropping any.
    pub fn split_exact(self, shares: &[Ratio]) -> Result<Vec<Self>, (Vec<Self>, Self)> {
        let (parts, rest) = self.split_n(shares);
        if rest.quantity().is_zero() {
            Ok(parts)
        } else {
            Err((parts, rest))
        }
    }

    /// Merge `other` in, consuming it.
    #[allow(clippy::needless_pass_by_value)] // a merge consumes what it takes
    pub fn put(&mut self, other: Self) {
        let _ = &other;
        #[cfg(component)]
        return crate::guest::bucket_put(&self.handle, other.into_handle());
        #[cfg(not(component))]
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
        #[cfg(component)]
        return Quantity::from_subunits(crate::guest::bucket_amount(&self.handle));
        #[cfg(not(component))]
        return Quantity::from_subunits(host::bucket_amount(self.rep));
    }
}

/// A non-fungible value edge: the instances it moves rather than an
/// amount.
///
/// A type of its own rather than an alias, so a body that splits one by
/// amount or merges one into a fungible edge is refused at the author's
/// build — the kernel would have refused the same call at run time as
/// the wrong edge kind, but a signature that cannot express the mistake
/// is cheaper than a receipt reporting it. What it carries instead of
/// the amount surface is the instance-oriented one: its resource, and a
/// merge with its own kind.
#[cfg_attr(not(component), derive(Debug, PartialEq, Eq))]
pub struct NfBucket(Bucket);

impl NfBucket {
    /// The edge an export was handed, under the name its author gave it.
    ///
    /// Called by generated code, never by an author, on the terms
    /// [`Bucket::held`] states.
    #[cfg(component)]
    #[must_use]
    pub const fn held(handle: crate::guest::kernel::state::Bucket) -> Self {
        Self(Bucket::held(handle))
    }

    /// The handle the kernel holds these instances behind.
    #[cfg(component)]
    #[must_use]
    pub fn into_handle(self) -> crate::guest::kernel::state::Bucket {
        self.0.into_handle()
    }

    /// The edge the kernel holds at `rep`, on the terms [`Bucket::at`]
    /// states.
    #[cfg(not(component))]
    #[must_use]
    pub const fn at(rep: u32) -> Self {
        Self(Bucket::at(rep))
    }

    /// The table position the kernel holds these instances at.
    #[cfg(not(component))]
    #[must_use]
    pub const fn rep(&self) -> u32 {
        self.0.rep()
    }

    /// The resource this edge carries, as the declaration names it.
    ///
    /// Read by the authoring half and never by the executing one, on the
    /// terms [`Bucket::resource`] states.
    #[must_use]
    pub fn resource(&self) -> ResourceAddr {
        self.0.resource()
    }

    /// Merge `other` in, consuming it.
    #[allow(clippy::needless_pass_by_value)] // a merge consumes what it takes
    pub fn put(&mut self, other: Self) {
        self.0.put(other.0);
    }

    /// How many instances this edge carries, on the terms
    /// [`Bucket::resource`] states: read by the authoring half and
    /// never by the executing one. The natural cap for the interval a
    /// move files into — a move declares exactly the walk it performs.
    #[must_use]
    pub fn count(&self) -> u64 {
        unimplemented!("{OFF_HOST}")
    }
}

/// The instance's creation-fixed configuration.
///
/// Its fields are the configuration slots the record holds, in
/// declaration order. Reading one declares nothing: the record is what
/// admission resolved the target with, so a body consults it without
/// claiming anything and every method's fence already holds the leaf it
/// was sealed into present.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config<T>(core::marker::PhantomData<fn() -> T>);

/// Configuration fields read straight off the component.
impl<T> core::ops::Deref for Config<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unimplemented!("{OFF_HOST}")
    }
}

/// One substate leaf under a slot.
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

/// What a record cell says about the leaf it is writing.
///
/// Only on the `Option<T>` shape, and that is the whole distinction: a
/// record's absence is a `None` a body can tell from every value it
/// holds, where a scalar cell's absence reads as its zero and "was it
/// already there" is a question its own value cannot answer. A cell that
/// cannot tell the difference gets no word for it.
///
/// The requirement is judged by the shard holding the cell, before the
/// body runs, where a reservation is judged — so a one-way door refuses
/// with the protocol's own verdict rather than with a trap the guest
/// wrote.
#[allow(clippy::inline_always)] // one import behind a dispatch its call site fixes
impl<T: Record> Cell<Option<T>> {
    /// Write `value` to a leaf that must not already hold one.
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    #[inline(always)]
    pub fn create(&mut self, value: T) {
        let _ = value;
        unimplemented!("{OFF_HOST}")
    }

    /// The value in a leaf that must already hold one.
    ///
    /// Answers `T` where [`Cell::get`] answers `Option<T>`: the absence
    /// the option is there to carry is what the declaration has ruled
    /// out, so a body that asked has nothing left to unwrap.
    #[must_use]
    #[inline(always)]
    pub fn existing(&self) -> T {
        unimplemented!("{OFF_HOST}")
    }

    /// Declare this leaf held exclusively and present, and read nothing
    /// from it.
    ///
    /// The mirror of [`Slot::declared`]: that one declares a movement
    /// the body does not make, and this one declares the access the body
    /// does not use. What a method like it is about is holding the leaf
    /// — that the pool operates this validator is the whole of what the
    /// call asserts — so the value is beside the point and the handle
    /// the guest would take for it is one nothing calls.
    #[inline(always)]
    pub fn exclusive(&self) {
        unimplemented!("{OFF_HOST}")
    }
}

impl Cell<Vault> {
    /// The handle on this vault.
    ///
    /// A vault is reached through a handle rather than accessed in place,
    /// because what a body does to one is move value — and a movement is
    /// an operation on an open access, the same as every other. The
    /// resource is the field's own declaration and no argument names it.
    #[must_use]
    #[allow(clippy::unused_self)] // the authoring stub reaches nothing
    pub fn vault(&self) -> Slot<Vault> {
        unimplemented!("{OFF_HOST}")
    }
}

/// A family of leaves under one slot, keyed by an address.
///
/// The canonical case is a vault family keyed by resource: `self.vaults.at(
/// funds.resource())` is the vault the arriving bucket belongs in, and the
/// key is pure computation over the argument, so another shard can name it
/// without reading anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keyed<T>(core::marker::PhantomData<fn() -> T>);

impl<T: Cellular> Keyed<T> {
    /// The leaf at `key`.
    ///
    /// The key is whatever material the declaration hashes under the
    /// field's slot — an address is the commonest case and not the only
    /// one, and what makes any of them declarable is being derivable
    /// from the call's own inputs.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn at<K>(&self, key: K) -> Slot<T> {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }
}

impl Keyed<Vault> {
    /// The vault at `key`.
    ///
    /// A keyed vault's denomination is its key, so the key is the one
    /// type a denomination has — which is what makes a family keyed by
    /// a component address unwritable rather than merely refused.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // an authoring stub consumes nothing
    pub fn at(&self, key: impl Into<ResourceAddr>) -> Slot<Vault> {
        let _ = key;
        unimplemented!("{OFF_HOST}")
    }
}

/// One `for-each` site's whole expansion, borrowed once and walked by
/// the index of the element that declared each entry.
///
/// Built by generated code, never by an author: what a body writes is
/// the loop it wrote, and this is what the emission rewrites the loop's
/// accesses to. The index is the *element's* throughout, so two sites in
/// one body agree on what it means and a site whose guard did not fire
/// reads as undeclared rather than shortening the walk.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    kind: CellKind,
    rep: u32,
}

#[allow(clippy::inline_always)] // one import behind a dispatch its call site fixes
impl Run {
    /// The run at `rep`, whose entries are lent at `kind`.
    #[must_use]
    pub const fn at(kind: CellKind, rep: u32) -> Self {
        Self { kind, rep }
    }

    /// How many elements the site's loop mapped over.
    #[must_use]
    #[inline(always)]
    pub fn len(&self) -> u32 {
        #[cfg(component)]
        return crate::guest::run_len(self.kind, self.rep);
        #[cfg(not(component))]
        return host::run_len(self.rep);
    }

    /// Whether the loop mapped over no elements at all.
    #[must_use]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the site declared anything for the element at `index`.
    ///
    /// A body branches on this rather than on a second copy of the
    /// guard, so the two cannot disagree — and reaching an entry it says
    /// nothing about is a defect that traps by its own name.
    #[must_use]
    #[inline(always)]
    pub fn declared(&self, index: u32) -> bool {
        #[cfg(component)]
        return crate::guest::run_declared(self.kind, self.rep, index);
        #[cfg(not(component))]
        return host::run_declared(self.rep, index);
    }

    /// The handle the entry at `index` acts through.
    #[must_use]
    pub const fn handle(&self, index: u32) -> Handle {
        Handle::Run(self.kind, self.rep, index)
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
        #[cfg(component)]
        return T::from_cell(&crate::guest::cell_get(self.handle));
        #[cfg(not(component))]
        return T::from_cell(&host::cell_get(self.handle));
    }

    /// An exclusive read-modify-write.
    #[allow(clippy::needless_pass_by_value)] // the authoring stub consumes nothing
    #[inline(always)]
    pub fn set(&mut self, value: T) {
        let _ = &value;
        #[cfg(component)]
        return crate::guest::cell_set(self.handle, &value.to_cell());
        #[cfg(not(component))]
        return host::cell_set(self.handle, &value.to_cell());
    }
}

/// The executing half of a record cell's presence-carrying calls; the
/// authoring half is on [`Cell`], which is where the requirement is
/// declared.
#[allow(clippy::inline_always)] // one import behind a dispatch its call site fixes
impl<T: Record> Slot<Option<T>> {
    /// Write `value` to a leaf the declaration required to be absent.
    #[allow(clippy::needless_pass_by_value)] // the value is consumed into the cell
    #[inline(always)]
    pub fn create(&mut self, value: T) {
        self.set(Some(value));
    }

    /// The value in a leaf the declaration required to be there.
    ///
    /// # Panics
    ///
    /// Never reachably: a handle exists only where materialization
    /// admitted the requirement, so an absent leaf here is a kernel that
    /// materialized what it refused.
    #[must_use]
    #[inline(always)]
    pub fn existing(&self) -> T {
        self.get()
            .expect("materialization required this leaf to be present")
    }

    /// Replace the value in a leaf the declaration required to be there.
    ///
    /// [`Slot::create`]'s door read the other way: what a mint filed
    /// where nothing was, the issuer may refile where something is.
    #[allow(clippy::needless_pass_by_value)] // the value is consumed into the cell
    #[inline(always)]
    pub fn rewrite(&mut self, value: T) {
        self.set(Some(value));
    }

    /// Declare this leaf held exclusively and present, and read nothing
    /// from it.
    ///
    /// Reaches no handle: the clause is what the kernel provisions and
    /// what a caller routes on, so a body that only needs the leaf held
    /// is handed nothing to call. Present on the executing half for the
    /// authoring half to type against, and run nowhere.
    #[inline(always)]
    #[allow(clippy::unused_self)] // the clause is the whole of it
    pub const fn exclusive(&self) {}
}

/// A cell that holds value.
///
/// Deliberately not [`Cellular`]: the generic accessors read and *assign*
/// a leaf, and a balance a body can assign is value from nowhere. What a
/// vault offers instead is movement — a credit consuming an edge, a debit
/// producing one — so every change to a balance is value that came from
/// or went to somewhere the same transaction accounts for.
///
/// Which resource it holds is its declaration's answer, and the
/// declaration states it one of two ways: a `Keyed<Vault>` is denominated
/// by its own key, and a `Cell<Vault>` by the `#[denomination(..)]` its
/// field carries. There is no third way and no undenominated vault.
#[derive(Clone, Copy, Debug, Default)]
pub struct Vault;

/// The element of a holder's non-fungible instances, reached by
/// `holdings(resource)`.
///
/// A marker type, not the unit it encodes as: an instance's id is the
/// entry's own order key, so the entry holds nothing and writes nothing
/// in bytes — but the instance operations live on this element alone,
/// so a collection of anything else has no value surface to reach. The
/// name is what the derivation reads to learn that the interval holds
/// value and is therefore narrowed by a resource — a package's own field
/// cannot declare it, so only the accessor's collections denominate by
/// key.
#[derive(Clone, Copy, Debug, Default)]
pub struct NfVault;

/// The record cell decodes under the same cap the protocol reads it at.
impl Record for ResourceRecord {
    const WIRE_DEPTH: usize = RECORD_WIRE_DEPTH;
}

/// As the unit entry: presence is the whole of what a holdings entry
/// says, so there is nothing to write and nothing to decode.
impl Cellular for NfVault {
    fn to_cell(&self) -> Vec<u8> {
        Vec::new()
    }

    fn from_cell(_: &[u8]) -> Self {
        Self
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl Slot<Vault> {
    /// What the vault holds.
    ///
    /// A read, not a handle on the balance: what a body does with the
    /// figure is arithmetic, and the only way to change it is to move
    /// value.
    #[must_use]
    #[inline(always)]
    pub fn balance(&self) -> Quantity {
        #[cfg(component)]
        return Quantity::from_subunits(crate::guest::cell_balance(self.handle));
        #[cfg(not(component))]
        return Quantity::from_subunits(host::cell_balance(self.handle));
    }

    /// Move value into the cell, consuming the bucket.
    ///
    /// What lands is exactly what crossed: the body names no amount, so
    /// there is no second number for the credit to disagree with.
    #[inline(always)]
    #[allow(clippy::needless_pass_by_value)] // the credit consumes the edge; off host nothing runs
    pub fn put(&mut self, funds: Bucket) {
        let _ = &funds;
        #[cfg(component)]
        return crate::guest::cell_put(self.handle, funds.into_handle());
        #[cfg(not(component))]
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
        #[cfg(component)]
        return Bucket::held(crate::guest::cell_take(self.handle, amount));
        #[cfg(not(component))]
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
        #[cfg(component)]
        return Bucket::held(crate::guest::reserve_take(self.handle));
        #[cfg(not(component))]
        return Bucket::at(host::reserve_take(self.handle));
    }
}

/// An ordered collection under one slot.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ordered<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Ordered<T> {
    /// The sub-collection this slot holds at `key`.
    ///
    /// A collection is named by its owner, its slot and the material
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
    pub fn at(&self, order: OrderKey) -> Entry<T> {
        let _ = order;
        unimplemented!("{OFF_HOST}")
    }

    /// The whole order-key space, capped implicitly at what the body's
    /// own moves walk.
    ///
    /// The cap of a pure move is not a choice: a take walks the ids it
    /// names and a file walks the instances its edge carries, so the
    /// lowering derives the cap from the moves themselves — summed,
    /// where a body moves more than once — and the declaration cannot
    /// under-state the walk. An interval that reads or rewrites walks a
    /// page somebody chose — it names that page with [`Self::range`].
    #[must_use]
    pub fn all(&self) -> Interval<T> {
        unimplemented!("{OFF_HOST}")
    }

    /// A declared interval of the order-key space.
    ///
    /// `cap` bounds the entries execution may touch, and is derivable
    /// like the bounds beside it — a literal, an argument, or a
    /// configured value. The interval's magnitude is charged as the
    /// exclusion it is and the cap as the walk it buys, so a caller
    /// choosing a page pays for the page it chose.
    #[must_use]
    pub fn range(&self, lo: OrderKey, hi: OrderKey, cap: u64) -> Interval<T> {
        let _ = (lo, hi, cap);
        unimplemented!("{OFF_HOST}")
    }
}

/// An unordered collection under one slot: entries keyed by hash.
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
    /// call's cursor; `0` starts the walk. `cap` is derivable like the
    /// cursor, so the page a sweep reads can be the caller's choice —
    /// priced as the walk it buys.
    #[must_use]
    pub fn sweep(&self, cursor: OrderKey, cap: u64) -> Interval<T> {
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
    order: OrderKey,
    _value: core::marker::PhantomData<fn() -> T>,
}

impl<T> Entry<T> {
    /// The entry at `order` of the interval this handle names, on the
    /// terms [`Slot::at`] describes.
    #[must_use]
    pub const fn at(handle: Handle, order: OrderKey) -> Self {
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
        #[cfg(component)]
        return T::from_cell(&crate::guest::entry_at(self.handle, self.order));
        #[cfg(not(component))]
        return T::from_cell(&host::entry_at(self.handle, self.order));
    }

    /// An exclusive read-modify-write. Writing an entry that is not there
    /// creates it, which is what makes one accessor cover both.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn set(&mut self, value: T) {
        let _ = &value;
        #[cfg(component)]
        return crate::guest::entry_insert(self.handle, self.order, &value.to_cell());
        #[cfg(not(component))]
        return host::entry_insert(self.handle, self.order, &value.to_cell());
    }
}

#[allow(clippy::inline_always)] // the accessor is one import behind a dispatch its call site fixes
impl Interval<NfVault> {
    /// File the instances a bucket carries, each at the order it was
    /// taken under, holding nothing.
    ///
    /// What a holdings entry says is that the holder holds it, and the
    /// instance's id is the entry's own order key — so there is no value
    /// to name. The filing is the kernel's, so a body hands the bucket
    /// over rather than walking it, which is also what keeps it away
    /// from the allocator and so eligible for the total mark.
    #[inline(always)]
    #[allow(clippy::needless_pass_by_value)] // the filing consumes the edge; off host nothing runs
    pub fn file(&mut self, funds: NfBucket) {
        let _ = &funds;
        #[cfg(component)]
        return crate::guest::entry_put(self.handle, funds.into_handle(), &[]);
        #[cfg(not(component))]
        return host::entry_put(self.handle, funds.rep(), &[]);
    }

    /// Take the named instances out, as the edge they become.
    ///
    /// The removal and the edge are one operation, exactly as a debit and
    /// its bucket are, so a body cannot hand on instances it left where
    /// they were. An id the collection does not hold refuses here.
    ///
    /// On the holdings element alone, with `file`: moving instances is
    /// what a value-bearing collection does, and this is the one element
    /// that names one.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // the take consumes the ids it names
    #[inline(always)]
    pub fn take(&mut self, ids: Ids) -> NfBucket {
        let _ = &ids;
        #[cfg(component)]
        return NfBucket::held(crate::guest::entry_take(self.handle, ids.named()));
        #[cfg(not(component))]
        return NfBucket::at(host::entry_take(self.handle, ids.named()));
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
        #[cfg(component)]
        return crate::guest::entry_count(self.handle);
        #[cfg(not(component))]
        return host::entry_count(self.handle);
    }

    /// Whether this page holds every entry the interval does — the
    /// proof a body settles a whole set on.
    ///
    /// A page short of its cap exhausted the interval and answers by
    /// itself; a full page is answered by the kernel probing past its
    /// last entry, so a page exactly the set's size still covers. What
    /// a `false` says is that entries past the cap exist, and whoever
    /// bought the page did not pay to walk them.
    #[must_use]
    #[inline(always)]
    pub fn covered(&self) -> bool {
        #[cfg(component)]
        return crate::guest::entry_covered(self.handle);
        #[cfg(not(component))]
        return host::entry_covered(self.handle);
    }

    /// The index `draw` selects over the entries currently here, or
    /// `None` where there are none.
    ///
    /// Uniform over the entries *in the interval*, which is not the same
    /// as uniform over everything the collection holds: a sweep sees at
    /// most its declared cap, so a selection over a collection larger
    /// than one page is uniform over that page and the rest cannot be
    /// picked. A package that means the whole set gates the pick on
    /// [`Interval::covered`], or cranks — sweeping pages across
    /// transactions and reducing as it goes — because no declaration
    /// sizes itself by reading state.
    ///
    /// The selection reasoning, once, because it is the protocol's
    /// rather than a package's. A draw is a whole word and an index
    /// needs far fewer bits, so the low 128 are taken and reduced: the
    /// modulo's bias is over a space no entry count approaches, and the
    /// remainder is below a count that is a `u32` to begin with, so the
    /// narrowing cannot fail. A package reasoning about either would be
    /// reasoning about widths it was never told.
    ///
    /// **Rejected: rejection sampling.** Removing the bias entirely
    /// costs an unbounded retry, and a declaration prices the work it
    /// declares — a body that might loop is a body whose cost is not a
    /// function of its signature. The bias is bounded, computable and
    /// stated here rather than argued again in every package that picks.
    ///
    /// # Panics
    ///
    /// Never reachably: the remainder is below an entry count that is a
    /// `u32` to begin with, so the narrowing has nothing to refuse.
    #[must_use]
    #[inline(always)]
    pub fn picked(&self, draw: &Draw) -> Option<u32> {
        let entries = self.count();
        if entries == 0 {
            return None;
        }
        // Half a word is sixteen bytes whatever it holds, so the
        // fallback stands for a case the width rules out — written as
        // one rather than as an unwrap, because an unwrap is a panic in
        // a body that has nothing to panic about.
        let low = *draw
            .word()
            .as_bytes()
            .first_chunk::<16>()
            .unwrap_or(&[0; 16]);
        let index = u128::from_le_bytes(low) % u128::from(entries);
        Some(u32::try_from(index).expect("a remainder below a `u32` count is one"))
    }

    /// The order key of the entry at `index`, ascending.
    #[must_use]
    #[inline(always)]
    pub fn order(&self, index: u32) -> OrderKey {
        let _ = index;
        #[cfg(component)]
        return crate::guest::entry_order(self.handle, index);
        #[cfg(not(component))]
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
        #[cfg(component)]
        return T::from_cell(&crate::guest::entry_get(self.handle, index));
        #[cfg(not(component))]
        return T::from_cell(&host::entry_get(self.handle, index));
    }

    /// The entry `draw` selects, or `None` over an empty interval.
    ///
    /// [`Interval::picked`] carries the reasoning; this is it beside the
    /// read, because a body that picks wants what was picked.
    #[must_use]
    #[inline(always)]
    #[allow(clippy::needless_pass_by_value)] // one draw, one selection
    pub fn pick(&self, draw: Draw) -> Option<T> {
        self.picked(&draw).map(|index| self.entry(index))
    }

    /// Replace the value at `index`.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn set(&mut self, index: u32, value: T) {
        let _ = (index, &value);
        #[cfg(component)]
        return crate::guest::entry_set(self.handle, index, &value.to_cell());
        #[cfg(not(component))]
        return host::entry_set(self.handle, index, &value.to_cell());
    }

    /// Insert at `order`, which must lie inside the declared interval.
    #[allow(clippy::needless_pass_by_value)] // a stored value is consumed
    #[inline(always)]
    pub fn insert(&mut self, order: OrderKey, value: T) {
        let _ = (order, &value);
        #[cfg(component)]
        return crate::guest::entry_insert(self.handle, order, &value.to_cell());
        #[cfg(not(component))]
        return host::entry_insert(self.handle, order, &value.to_cell());
    }

    /// Remove the entry at `index`.
    #[inline(always)]
    pub fn remove(&mut self, index: u32) {
        let _ = index;
        #[cfg(component)]
        return crate::guest::entry_remove(self.handle, index);
        #[cfg(not(component))]
        return host::entry_remove(self.handle, index);
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
    #[cfg(component)]
    return Bucket::held(crate::guest::reserve_take(handle));
    #[cfg(not(component))]
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
pub fn mint_granted(grant: u32, quantity: Quantity) -> Bucket {
    #[cfg(component)]
    return Bucket::held(crate::guest::mint(grant, quantity.subunits()));
    #[cfg(not(component))]
    return Bucket::at(host::mint(grant, quantity.subunits()));
}

/// Create the named instance of the granted resource, as an edge.
///
/// Called by generated code, never by an author, on the terms
/// [`mint_granted`] states — and always beside the instance-cell write
/// the same lowering emitted, so a minted instance's data cell is filed
/// where the instance comes into existence.
///
/// One id, because one call is one declared cell. The kernel seats a
/// batch and genesis uses that; a body asking for several says so by
/// minting several and merging the edges, which is a line rather than a
/// second spelling.
#[doc(hidden)]
#[must_use]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always)]
pub fn mint_nf_granted(grant: u32, id: u64) -> NfBucket {
    #[cfg(component)]
    return NfBucket::held(crate::guest::mint_instances(grant, &[id]));
    #[cfg(not(component))]
    return NfBucket::at(host::mint_instances(grant, &[id]));
}

/// File one minted instance's data cell: the presence marker, written
/// where the declaration required absence.
///
/// Called by generated code, never by an author. One byte rather than
/// nothing, so the cell reads as present wherever presence is asked; a
/// genesis-seated instance writes the same byte, which is what holds an
/// instantiated object and a seeded one to the same cells.
#[doc(hidden)]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always)]
pub fn file_instance(handle: Handle) {
    #[cfg(component)]
    return crate::guest::cell_set(handle, &[1]);
    #[cfg(not(component))]
    return host::cell_set(handle, &[1]);
}

/// End the instance data cell `handle` names.
///
/// Called by generated code, never by an author. The mirror of
/// [`file_instance`], and it ends the cell whatever the mark filed there
/// — the presence byte of a bare instance or the record of a fielded
/// one — because what a burn retires is the instance rather than its
/// contents. Removing rather than emptying is what lets the id be minted
/// again and what keeps an issuer's state from growing with churn: the
/// cells of every instance a component issues sit under its own prefix,
/// and nothing else knows the instance is gone.
#[doc(hidden)]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always)]
pub fn clear_instance(handle: Handle) {
    #[cfg(component)]
    return crate::guest::cell_clear(handle);
    #[cfg(not(component))]
    return host::cell_clear(handle);
}

/// Destroy the value at `funds` against the grant at `grant`.
///
/// Called by generated code, never by an author, on the same terms
/// [`mint_granted`] is: the grant is a handle the kernel lowered against
/// the method's own declaration, and which resource it destroys is what
/// the mark already fixed.
#[doc(hidden)]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always, clippy::needless_pass_by_value)]
pub fn burn_granted(grant: u32, funds: Bucket) {
    let _ = &funds;
    #[cfg(component)]
    return crate::guest::burn(grant, funds.into_handle());
    #[cfg(not(component))]
    return host::burn(grant, funds.rep());
}

/// Destroy the instances at `funds` against the grant at `grant`.
///
/// [`burn_granted`] over a non-fungible edge: the same grant in the same
/// direction, and what leaves circulation is the instances the edge
/// carries rather than an amount. The data cell each of them filed is
/// ended beside this, which is the burn's other half.
#[doc(hidden)]
#[inline(always)] // one import behind a cfg both targets resolve at compile time
#[allow(clippy::inline_always, clippy::needless_pass_by_value)]
pub fn burn_nf_granted(grant: u32, funds: NfBucket) {
    let _ = &funds;
    #[cfg(component)]
    return crate::guest::burn(grant, funds.into_handle());
    #[cfg(not(component))]
    return host::burn(grant, funds.rep());
}

/// A 128-bit order key packed from a primary dimension over a tiebreaker.
#[must_use]
pub const fn pack(hi: u64, lo: u64) -> OrderKey {
    ((hi as OrderKey) << 64) | (lo as OrderKey)
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
    #[cfg(component)]
    return crate::guest::clock_ms();
    #[cfg(not(component))]
    return host::clock_ms();
}

/// The transaction's randomness draw.
#[must_use]
pub fn randomness() -> Draw {
    #[cfg(component)]
    return Draw::from_protocol(&crate::guest::randomness());
    #[cfg(not(component))]
    return Draw::from_protocol(&host::randomness());
}

/// The protocol hash function: a 32-byte digest.
///
/// The host's, never a guest's own — a package carrying its own
/// implementation would be a second answer to a question the protocol
/// has already fixed.
#[must_use]
pub fn hash(data: &[u8]) -> Vec<u8> {
    let _ = data;
    #[cfg(component)]
    return crate::guest::hash(data);
    #[cfg(not(component))]
    return host::hash(data);
}

/// A set of non-fungible instance ids, as a contract signature names it.
///
/// Signed manifest content, carried in the framing a declared id list
/// crosses in — so a method moving the ids it was given passes them
/// straight through and reads none of them.
#[derive(Clone, Debug, Default)]
pub struct Ids(pub Vec<u64>);

/// The id at one position, which is what a body walking a declared list
/// by index reads out of it.
impl core::ops::Index<usize> for Ids {
    type Output = u64;

    fn index(&self, at: usize) -> &u64 {
        &self.0[at]
    }
}

/// The wire form a list of ids crosses in, under the name a body reads
/// it at.
impl From<Vec<u64>> for Ids {
    fn from(ids: Vec<u64>) -> Self {
        Self(ids)
    }
}

impl Ids {
    /// The ids themselves, which is all a body may do with one: what
    /// they mean was settled at admission.
    #[must_use]
    pub fn named(&self) -> &[u64] {
        &self.0
    }

    /// How many ids the argument names — the natural cap for the
    /// interval a withdrawal takes them from, so a move declares
    /// exactly the walk it performs.
    #[must_use]
    pub fn count(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }
}

/// An authority rule parameter, as a contract signature names it.
///
/// The rule arrives as canonical bytes the admission gate already decoded
/// under the vocabulary caps, so a body carries them and judges nothing.
#[derive(Clone, Debug, Default)]
pub struct Rule(pub Vec<u8>);

impl Rule {
    /// The canonical bytes, which is all a body may do with one: what
    /// they mean was settled at admission.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Cellular for Rule {
    fn from_cell(cell: &[u8]) -> Self {
        Self(cell.to_vec())
    }

    fn to_cell(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// A role-table parameter crosses the boundary as its canonical bytes.
impl Cellular for RoleTable {
    fn from_cell(cell: &[u8]) -> Self {
        Self::from_slice(cell).expect("the write path admits only a canonical table")
    }

    fn to_cell(&self) -> Vec<u8> {
        self.to_bytes().expect("the table cap is the codec's own")
    }
}
