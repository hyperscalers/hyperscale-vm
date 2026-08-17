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
//! That puts each trait method in front of the session method it names,
//! so every body reaches past itself by path — and [`refused`] is what
//! makes reaching the wrong one fail to compile.

use hyperscale_vm_effects::AbortReason;
use hyperscale_vm_embed::KernelHost;
use hyperscale_vm_embed::math::U256;

use crate::session::{KernelSession, SessionTrap};

/// A session refusal, narrowed to the class the boundary transports.
///
/// Typed to [`SessionTrap`] rather than to anything an [`AbortReason`]
/// converts from, which is the point: a body below calls the session
/// method its own name shadows, and one that resolved to the trait method
/// instead would recur forever. It would also type-check, because a class
/// converts from itself — so the conversion is spelled here, where only
/// the session's own error satisfies it.
fn refused<T>(answer: Result<T, SessionTrap>) -> Result<T, AbortReason> {
    answer.map_err(AbortReason::from)
}

impl KernelHost for KernelSession {
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::read_cell(self, rep))
    }
    fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::locked_cell(self, rep))
    }
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::write_cell_get(self, rep))
    }
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::write_cell_set(self, rep, value))
    }
    fn burn(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        refused(Self::burn(self, rep, funds))
    }
    fn mint_instances(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason> {
        refused(Self::mint_instances(self, rep, ids))
    }
    fn range_take(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason> {
        refused(Self::range_take(self, rep, ids))
    }
    fn range_put(&mut self, rep: u32, funds: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::range_put(self, rep, funds, &value))
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
    fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        refused(Self::delta_put(self, rep, funds))
    }
    fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        refused(Self::write_put(self, rep, funds))
    }
    fn mint(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::mint(self, rep, amount))
    }
    fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::delta_take(self, rep, amount))
    }
    fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        refused(Self::write_take(self, rep, amount))
    }
    fn reserve_take(&mut self, rep: u32) -> Result<u32, AbortReason> {
        refused(Self::reserve_take(self, rep))
    }
    fn take_scan_debt(&mut self) -> usize {
        Self::take_scan_debt(self)
    }
    fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason> {
        refused(Self::range_count(self, rep))
    }
    fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason> {
        refused(Self::range_order(self, rep, index))
    }
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
        refused(Self::range_entry(self, rep, index))
    }
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::range_set(self, rep, index, value))
    }
    fn range_insert(&mut self, rep: u32, order: u128, value: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::range_insert(self, rep, order, value))
    }
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason> {
        refused(Self::range_remove(self, rep, index))
    }
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
        refused(Self::drop_bucket(self, rep))
    }
    fn clock_ms(&self) -> u64 {
        Self::clock_ms(self)
    }
    fn randomness(&self) -> [u8; 32] {
        Self::randomness(self)
    }
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        Self::hash(self, data)
    }
    fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason> {
        refused(Self::emit(self, event_type, payload))
    }
}
