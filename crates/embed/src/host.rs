//! The kernel's host surface: what an engine calls, and what the session
//! answers.

use hyperscale_vm_types::AbortReason;
use hyperscale_vm_types::math::U256;

/// The kernel's operations, as reps and bytes.
///
/// Implementations hold per-transaction state: the materialized capability
/// table, the transaction clock, the randomness draw, and the emission
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
    /// The cell's current bytes; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// The cell's pinned bytes; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// The cell's current bytes under a write capability; empty if absent.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the cell's bytes.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason>;

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
    fn mint(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;

    /// Debit the amount cell and hand the value out as a bucket, whose
    /// rep this returns.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;

    /// Destroy what this invocation issues, consuming the bucket.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn burn(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;

    /// Create the named instances under this invocation's grant; the
    /// bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn mint_instances(&mut self, rep: u32, ids: &[u64]) -> Result<u32, AbortReason>;

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
    /// # Errors
    ///
    /// A deterministic refusal.
    fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;

    /// Credit the absolute amount cell with what the bucket at `funds`
    /// carries, consuming it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason>;

    /// Debit the absolute amount cell and hand the value out as a
    /// bucket, whose rep this returns.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason>;

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

    /// The transaction clock in milliseconds.
    fn clock_ms(&self) -> u64;

    /// The transaction's randomness draw.
    fn randomness(&self) -> [u8; 32];

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
