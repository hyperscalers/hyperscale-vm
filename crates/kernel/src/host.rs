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

use hyperscale_vm_effects::AbortReason;
use hyperscale_vm_embed::KernelHost;

use crate::session::KernelSession;

impl KernelHost for KernelSession {
    fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        Self::read_cell(self, rep).map_err(AbortReason::from)
    }
    fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        Self::locked_cell(self, rep).map_err(AbortReason::from)
    }
    fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
        Self::write_cell_get(self, rep).map_err(AbortReason::from)
    }
    fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        Self::write_cell_set(self, rep, value).map_err(AbortReason::from)
    }
    fn issuer_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        Self::issuer_put(self, rep, funds).map_err(AbortReason::from)
    }
    fn issuer_mint(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason> {
        Self::issuer_mint(self, rep, ids).map_err(AbortReason::from)
    }
    fn range_take(&mut self, rep: u32, ids: &[u8]) -> Result<u32, AbortReason> {
        Self::range_take(self, rep, ids).map_err(AbortReason::from)
    }
    fn range_put(&mut self, rep: u32, funds: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        Self::range_put(self, rep, funds, &value).map_err(AbortReason::from)
    }
    fn bucket_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        Self::bucket_take(self, rep, amount).map_err(AbortReason::from)
    }
    fn bucket_put(&mut self, rep: u32, other: u32) -> Result<(), AbortReason> {
        Self::bucket_put(self, rep, other).map_err(AbortReason::from)
    }
    fn bucket_amount(&mut self, rep: u32) -> Result<u128, AbortReason> {
        Self::bucket_amount(self, rep).map_err(AbortReason::from)
    }
    fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        Self::delta_put(self, rep, funds).map_err(AbortReason::from)
    }
    fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
        Self::write_put(self, rep, funds).map_err(AbortReason::from)
    }
    fn issuer_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        Self::issuer_take(self, rep, amount).map_err(AbortReason::from)
    }
    fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        Self::delta_take(self, rep, amount).map_err(AbortReason::from)
    }
    fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
        Self::write_take(self, rep, amount).map_err(AbortReason::from)
    }
    fn reserve_take(&mut self, rep: u32) -> Result<u32, AbortReason> {
        Self::reserve_take(self, rep).map_err(AbortReason::from)
    }
    fn take_scan_debt(&mut self) -> usize {
        Self::take_scan_debt(self)
    }
    fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason> {
        Self::range_count(self, rep).map_err(AbortReason::from)
    }
    fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason> {
        Self::range_order(self, rep, index).map_err(AbortReason::from)
    }
    fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
        Self::range_entry(self, rep, index).map_err(AbortReason::from)
    }
    fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), AbortReason> {
        Self::range_set(self, rep, index, value).map_err(AbortReason::from)
    }
    fn range_insert(&mut self, rep: u32, order: u128, value: Vec<u8>) -> Result<(), AbortReason> {
        Self::range_insert(self, rep, order, value).map_err(AbortReason::from)
    }
    fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason> {
        Self::range_remove(self, rep, index).map_err(AbortReason::from)
    }
    fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
        Self::drop_bucket(self, rep).map_err(AbortReason::from)
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
        Self::emit(self, event_type, payload).map_err(AbortReason::from)
    }
}
