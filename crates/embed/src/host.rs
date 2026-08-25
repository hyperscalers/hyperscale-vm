//! The kernel's host surface: what an engine calls, and what the session
//! answers.

use hyperscale_vm_types::math::U256;
use hyperscale_vm_types::{AbortReason, Drawn};

/// The kernel's operations, one per world function, as reps and bytes.
///
/// Named for the world functions themselves, so the correspondence
/// between what a guest imports, what the meter prices and what the
/// host answers is one name rather than three.
///
/// Implementations hold per-transaction state: the materialized
/// capability table, the sites lent over it, the transaction clock and
/// epoch, and the emission buffer a completed outcome turns into receipt
/// events. A site rep is an index the host itself assigned, but the
/// element beside it is the guest's own number, so every site operation
/// is fallible — and so is every operation the capability behind that
/// element does not grant. A refusal is a deterministic [`AbortReason`]
/// that becomes the receipt's abort class on every replica. The host
/// classifies; the boundary transports.
///
/// `Send`, because the blessed engine's store carries the implementation
/// across a call boundary that requires it, and because a conflict group
/// executes on its own thread.
pub trait KernelHost: Send {
    /// How many elements the site covers.
    ///
    /// The element count rather than the count of expansions that fired,
    /// so two sites in one body agree on what an index means.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_len(&mut self, site: u32) -> Result<u32, AbortReason>;

    /// Whether the site declared anything for the element at `element`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_declared(&mut self, site: u32, element: u32) -> Result<bool, AbortReason>;

    /// The cell's current bytes; empty if absent.
    ///
    /// One read for both byte modes: what the exclusive mode adds is the
    /// writes, not a second answer to the same question.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the cell's bytes.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_set(&mut self, site: u32, element: u32, value: Vec<u8>) -> Result<(), AbortReason>;

    /// Remove the cell, so nothing is there.
    ///
    /// A write capability's other end: the same exclusive hold over one
    /// leaf, ending it rather than restating it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_clear(&mut self, site: u32, element: u32) -> Result<(), AbortReason>;

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
    fn site_balance(&mut self, site: u32, element: u32) -> Result<u128, AbortReason>;

    /// Create value under this invocation's issuance grant, returning
    /// the bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal, including an index naming no grant this
    /// invocation holds.
    fn mint(&mut self, grant: u32, amount: u128) -> Result<u32, AbortReason>;

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
    fn site_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, AbortReason>;

    /// Destroy value this invocation was granted, consuming the bucket.
    ///
    /// Names no grant: the bucket carries the resource it holds, and a
    /// mark names one grant, so at most one of the invocation's can be
    /// the bucket's.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn burn(&mut self, funds: u32) -> Result<(), AbortReason>;

    /// Create the named instances under the grant at `grant`; the
    /// bucket's rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn mint_instances(&mut self, grant: u32, ids: &[u64]) -> Result<u32, AbortReason>;

    /// Take the named entries as the instances they were; the bucket's
    /// rep.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_instance_take(
        &mut self,
        site: u32,
        element: u32,
        ids: &[u64],
    ) -> Result<u32, AbortReason>;

    /// File every instance the bucket at `funds` carries as an entry,
    /// consuming it.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_instance_put(
        &mut self,
        site: u32,
        element: u32,
        funds: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason>;

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
    /// One credit for both value modes, on the terms [`Self::site_take`]
    /// states.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), AbortReason>;

    /// Take the reservation as a bucket, whose rep this returns.
    ///
    /// # Errors
    ///
    /// A deterministic refusal, including a second take of one grant.
    fn site_reserve_take(&mut self, site: u32, element: u32) -> Result<u32, AbortReason>;

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
    fn site_count(&mut self, site: u32, element: u32) -> Result<u32, AbortReason>;

    /// Whether the materialized page holds every entry the interval
    /// does: a page short of its cap exhausted the interval, and a full
    /// one is answered by probing past its last entry.
    ///
    /// # Errors
    ///
    /// A deterministic refusal.
    fn site_covered(&mut self, site: u32, element: u32) -> Result<bool, AbortReason>;

    /// The order key of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn site_order(&mut self, site: u32, element: u32, index: u32) -> Result<u128, AbortReason>;

    /// The value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn site_entry(&mut self, site: u32, element: u32, index: u32) -> Result<Vec<u8>, AbortReason>;

    /// Replace the value of the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn site_entry_set(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason>;

    /// Insert or replace the entry at `order` within the declared interval.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (an order outside the interval).
    fn site_insert(
        &mut self,
        site: u32,
        element: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), AbortReason>;

    /// Remove the entry at `index`.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (index out of bounds).
    fn site_remove(&mut self, site: u32, element: u32, index: u32) -> Result<(), AbortReason>;

    /// Seal this cell on the epoch now running.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a handle that names no write).
    fn site_seal(&mut self, site: u32, element: u32) -> Result<(), AbortReason>;

    /// The draw the seal in this cell matures into.
    ///
    /// The word mixes the cell's own key, so a package holding two
    /// sealed cells gets two draws and neither names a nonce.
    ///
    /// # Errors
    ///
    /// A deterministic refusal (a handle that names no write, or a cell
    /// holding something that is not a seal).
    fn site_open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, AbortReason>;

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
