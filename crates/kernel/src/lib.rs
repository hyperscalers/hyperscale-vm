//! The kernel's object model and mode semantics, in isolation.
//!
//! Three pieces, each deterministic by construction: the substate store
//! traits and their in-memory access-recording implementation; the mode
//! lattice's execution semantics (amount cells, the order-invariant delta
//! fold, reservation feasibility in canonical transaction-hash order,
//! capped interval scans); and the per-shard supply
//! accumulators that substrate conservation.
//!
//! The mode semantics stand on a store's view rather than on a store:
//! [`AmountLedger`] derives every reservation and movement verdict from
//! the committed content and outstanding holds [`Baseline`] already
//! answers, so the plain store and the layered one share one
//! implementation of what a floor is and differ only in what they show.
//!
//! The trace-subset oracle lives here too: the recording store's access
//! log checked against a declared effect set, the standing assertion that
//! execution touches nothing it did not declare.

// The pairwise conflict oracle: the executor's grouping is differentially
// tested against it.
#[cfg(test)]
mod conflict;
pub mod escrow;
pub mod executor;
pub mod host;
pub mod ledger;
pub mod locality;
pub mod modes;
pub mod oracle;
pub mod overlay;
pub mod session;
pub mod store;
pub mod supply;
pub mod walk;
pub mod work;

pub use escrow::{Crossed, EscrowDelta, LegPlan, PlanTooWide};
pub use executor::{
    BatchError, BatchOutcome, BatchTx, ExecutionMode, GuestRunner, RunResult, Unavailable,
    execute_batch,
};
pub use hyperscale_vm_embed::{GuestArg, Invoked, KernelHost};
pub use ledger::AmountLedger;
pub use locality::{Locality, OwnedDelta};
pub use modes::{DeltaOp, Feasibility, ModeError, decode_amount, fold_deltas, judge};
pub use oracle::{covered, multiply_held_ids, permits, target_covers, undeclared_accesses};
pub use overlay::OverlayStore;
pub use session::{
    Capability, DOMAIN_SEALED_DRAW, DeltaMap, EnvInputs, FinishError, Held, Interval,
    KernelSession, MaterializeError, Receipt, SessionTrap, StateDelta,
};
pub use store::{
    Access, AppliedDelta, Baseline, Fault, MemoryStore, StoreError, Substates, WorkingStore,
};
pub use supply::SupplyDelta;
pub use walk::{GuestBackend, GuestCall, InvokeResult, ManifestWalk};
pub use work::Work;
