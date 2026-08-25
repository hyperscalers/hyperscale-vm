//! The kernel's host surface: what an engine calls, and what the session
//! answers.

use hyperscale_vm_types::math::U256;
use hyperscale_vm_types::{AbortReason, Drawn};

/// The kernel's operations, as reps and bytes.
///
/// Implementations hold per-transaction state: the materialized capability
/// table, the transaction clock and epoch, and the emission
/// buffer a completed outcome turns into receipt events. Reps are indexes
/// the host itself assigned when materializing handles, so lookups are
/// infallible by construction; fallible operations return a deterministic
/// [`AbortReason`] that becomes the receipt's abort class on every
/// replica. The host classifies; the boundary transports.
///
/// `Send`, because the blessed engine's store carries the implementation
/// across a call boundary that requires it, and because a conflict group
/// executes on its own thread.
pub trait KernelHost: Send {
    /// How many elements a run's site mapped over.
    ///
    /// The element count rather than the count of expansions that fired,
    /// so two sites in one body agree on what an index means.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn run_len(&mut self, rep: u32) -> Result<u32, AbortReason>;

    /// Whether a run's site declared anything for the element at
    /// `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn run_declared(&mut self, rep: u32, index: u32) -> Result<bool, AbortReason>;

    /// The capability a run's site declared for the element at `index`,
    /// as the rep every other operation here takes.
    ///
    /// An expansion whose guard did not fire answers a rep no capability
    /// occupies, so the operation it is handed to refuses by its own
    /// name — a body reaching one disagrees with its own declaration,
    /// exactly as one reaching a guarded-out handle does.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn run_at(&mut self, rep: u32, index: u32) -> Result<u32, AbortReason>;

    /// The cell's current bytes; empty if absent.
    ///
    /// One read for both byte modes: what the exclusive mode adds is the
    /// writes, not a second answer to the same question.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the cell's bytes.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Remove the cell, so nothing is there.
    ///
    /// A write capability's other end: the same exclusive hold over one
    /// leaf, ending it rather than restating it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_clear(&mut self, rep: u32) -> Result<(), AbortReason>;

    /// What an amount cell holds.
    ///
    /// The read beside the two movements, and the only question about a
    /// balance that cannot change it. A quantity rather than the bytes
    /// it is stored as: the width is the protocol's, and a cell holding
    /// value has no byte surface for a body to read one through.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn amount_cell_balance(&mut self, rep: u32) -> Result<u128, AbortReason>;

    /// Create value under this invocation's issuance grant, returning
    /// the bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal, including an invocation granted none.
    fn mint(&mut self, amount: u128) -> Result<u32, AbortReason>;

    /// Debit the amount cell and hand the value out as a bucket, whose
    /// rep this returns.
    ///
    /// One debit for both value modes. Which one the capability carries
    /// decides when an over-take is refused — at the call for the
    /// exclusive hold, at the fold for the commutative movement.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn cell_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;

    /// Destroy what this invocation issues, consuming the bucket.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn burn(&mut self, funds: u32) -> Result<(), AbortReason>;

    /// Create the named instances under this invocation's grant; the
    /// bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn mint_instances(&mut self, ids: &[u64]) -> Result<u32, AbortReason>;

    /// Take the named entries as the instances they were; the bucket's
    /// rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn range_take(&mut self, rep: u32, ids: &[u64]) -> Result<u32, AbortReason>;

    /// File every instance the bucket at `funds` carries as an entry,
    /// consuming it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn range_put(&mut self, rep: u32, funds: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Split `amount` off the bucket at `rep`; the new bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;

    /// Split `num/den` off the bucket at `rep`; the new bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, AbortReason>;

    /// Merge the bucket at `other` into the one at `rep`, consuming it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason>;

    /// What the bucket at `rep` carries.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason>;

    /// Credit the amount cell with what the bucket at `funds` carries,
    /// consuming it.
    ///
    /// One credit for both value modes, on the terms [`Self::cell_take`]
    /// states.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn cell_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;

    /// Take the reservation as a bucket, whose rep this returns.
    ///
    /// # Errors
    ///
    /// A deterministic refusal, including a second take of one grant.
    fn reserve_take(&mut self, rep: u32) -> Result<u32, AbortReason>;

    /// What interval scans lifted out of the store since this was last
    /// asked, in the boundary-byte terms the fuel schedule prices.
    ///
    /// Materializing an interval crosses no ABI boundary — the page stays
    /// host-side until an accessor asks it for one entry — so the copy
    /// metering that prices every other host call is blind to it. Asked
    /// after every range function, each of which can reach a scan.
    fn take_scan_debt(&mut self) -> usize;

    /// Entries currently in the interval, bounded by the declared cap.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason>;

    /// Whether the materialized page holds every entry the interval
    /// does: a page short of its cap exhausted the interval, and a full
    /// one is answered by probing past its last entry.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn range_covered(&mut self, rep: u32) -> Result<bool, AbortReason>;

    /// The order key of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason>;

    /// The value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Insert or replace the entry at `order` within the declared interval.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (an order outside the interval).
    fn range_insert(&mut self, rep: u32, order: u128, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Remove the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason>;

    /// Seal this cell on the epoch now running.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a handle that names no write).
    fn seal(&mut self, rep: u32) -> Result<(), AbortReason>;

    /// The draw the seal in this cell matures into.
    ///
    /// The word mixes the cell's own key, so a package holding two
    /// sealed cells gets two draws and neither names a nonce.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a handle that names no write, or a cell
    /// holding something that is not a seal).
    fn open_seal(&mut self, rep: u32) -> Result<Drawn, AbortReason>;

    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;

    /// The protocol hash function.
    fn hash(&self, data: &[u8]) -> [u8; 32];

    /// A bucket handle the guest let go of.
    ///
    /// The canonical ABI routes a discarded owned handle here and the
    /// host decides what it means. Delivery is the property an owned
    /// handle has and a value type cannot be given: a record can carry an
    /// amount, and it cannot notice being forgotten.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason>;

    /// Emit an event from the executing instance; the host stamps the
    /// emitter.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a cap or the event-type ceiling).
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason>;
}
