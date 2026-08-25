//! The session as the engines' host.
//!
//! [`KernelHost`] is the engine-facing projection of the session's own
//! API: the same operations, with [`SessionTrap`](crate::SessionTrap)
//! narrowed to the class the boundary transports. The session keeps the
//! richer error for its own callers — a wrong mode and an unknown handle
//! are different defects to the kernel and one abort class to a guest.
//!
//! Written against the session itself rather than a wrapper, so an
//! embedder hands its store the session and takes the same value back.
//! Each method here is named for the world function an engine reached it
//! through, and each body calls the session operation that answers it —
//! which is what makes the two vocabularies meet in exactly one file.

use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_types::math::U256;
use hyperscale_vm_types::{AbortReason, Drawn};

use crate::session::{KernelSession, SessionTrap};

/// A session refusal, narrowed to the class the boundary transports.
///
/// Typed to [`SessionTrap`] rather than to anything an [`AbortReason`]
/// converts from. Where a world function and the session operation behind
/// it share a name, a body that resolved to the trait method instead
/// would recur forever — and would type-check, because a class converts
/// from itself. Spelling the conversion here leaves only the session's
/// own error satisfying it.
fn refused<T>(answer: Result<T, SessionTrap>) -> Result<T, AbortReason> {
    answer.map_err(AbortReason::from)
}

impl KernelHost for KernelSession {
    fn site_len(&mut self, site: u32) -> Result<u32, AbortReason> {
        refused(Self::site_len(self, site))
    }
    fn site_declared(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        refused(Self::site_declared(self, site, element))
    }

    fn site_get(&mut self, site: u32, element: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::cell_get(self, site, element))
    }
    fn site_set(&mut self, site: u32, element: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::write_cell_set(self, site, element, value))
    }
    fn site_clear(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        refused(Self::write_cell_clear(self, site, element))
    }

    fn site_balance(&mut self, site: u32, element: u32) -> Result<u128, AbortReason> {
        refused(self.amount_cell_balance(site, element))
    }
    fn burn(&mut self, funds: u32) -> Result<(), AbortReason> {
        refused(Self::burn(self, funds))
    }
    fn mint_instances(&mut self, grant: u32, ids: &[u64]) -> Result<u32, AbortReason> {
        refused(Self::mint_instances(self, grant, ids))
    }
    fn site_instance_take(
        &mut self,
        site: u32,
        element: u32,
        ids: &[u64],
    ) -> Result<u32, AbortReason> {
        refused(Self::range_take(self, site, element, ids))
    }
    fn site_instance_put(
        &mut self,
        site: u32,
        element: u32,
        funds: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        refused(Self::range_put(self, site, element, funds, &value))
    }
    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::bucket_take(self, rep, amount))
    }
    fn bucket_split(&mut self, rep: u32, num: U256, den: U256) -> Result<u32, AbortReason> {
        refused(Self::bucket_split(self, rep, num, den))
    }
    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason> {
        refused(Self::bucket_put(self, rep, other))
    }
    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason> {
        refused(Self::bucket_amount(self, rep))
    }
    fn site_put(&mut self, site: u32, element: u32, funds: u32) -> Result<(), AbortReason> {
        refused(Self::cell_put(self, site, element, funds))
    }
    fn mint(&mut self, grant: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::mint(self, grant, amount))
    }
    fn site_take(&mut self, site: u32, element: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::cell_take(self, site, element, amount))
    }
    fn site_reserve_take(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        refused(Self::reserve_take(self, site, element))
    }
    fn take_scan_debt(&mut self) -> usize {
        Self::take_scan_debt(self)
    }
    fn site_count(&mut self, site: u32, element: u32) -> Result<u32, AbortReason> {
        refused(Self::range_count(self, site, element))
    }
    fn site_covered(&mut self, site: u32, element: u32) -> Result<bool, AbortReason> {
        refused(Self::range_covered(self, site, element))
    }
    fn site_order(&mut self, site: u32, element: u32, index: u32) -> Result<u128, AbortReason> {
        refused(Self::range_order(self, site, element, index))
    }
    fn site_entry(&mut self, site: u32, element: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::range_entry(self, site, element, index))
    }
    fn site_entry_set(
        &mut self,
        site: u32,
        element: u32,
        index: u32,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        refused(Self::range_set(self, site, element, index, value))
    }
    fn site_insert(
        &mut self,
        site: u32,
        element: u32,
        order: u128,
        value: Vec<u8>,
    ) -> Result<(), AbortReason> {
        refused(Self::range_insert(self, site, element, order, value))
    }
    fn site_remove(&mut self, site: u32, element: u32, index: u32) -> Result<(), AbortReason> {
        refused(Self::range_remove(self, site, element, index))
    }
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
        refused(Self::drop_bucket(self, rep))
    }
    fn site_seal(&mut self, site: u32, element: u32) -> Result<(), AbortReason> {
        refused(Self::seal(self, site, element))
    }
    fn site_open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, AbortReason> {
        refused(Self::open_seal(self, site, element))
    }
    fn clock_ms(&self) -> u64 {
        Self::clock_ms(self)
    }
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        Self::hash(self, data)
    }
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::emit(self, event_type, payload))
    }
}
