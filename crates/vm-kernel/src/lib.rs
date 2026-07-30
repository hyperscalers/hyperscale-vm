//! The kernel's object model and mode semantics, in isolation.
//!
//! Four pieces, each deterministic by construction: the substate store
//! trait and its in-memory access-recording implementation; structural
//! ownership (creation under the owning context, explicit move, never a
//! re-parent); the mode lattice's execution semantics (amount cells, the
//! order-invariant delta fold, reservation feasibility in canonical
//! transaction-hash order, locked substates, capped interval scans); and
//! the per-shard supply accumulators that substrate conservation.
//!
//! The trace-subset oracle lives here too: the recording store's access
//! log checked against a declared effect set, the standing assertion that
//! execution touches nothing it did not declare.

pub mod conflict;
pub mod executor;
pub mod modes;
pub mod oracle;
pub mod ownership;
pub mod session;
pub mod store;
pub mod supply;

pub use conflict::{conflicts, targets_overlap};
pub use executor::{
    BatchError, BatchOutcome, BatchTx, ExecutionMode, GuestRunner, RunResult, execute_batch,
};
pub use modes::{
    AMOUNT_CELL_BYTES, DeltaOp, Feasibility, ModeError, TxHash, decode_amount, encode_amount,
    fold_deltas, judge,
};
pub use oracle::{covered, permits, target_covers, undeclared_accesses};
pub use ownership::{CreationContext, MoveError, move_object};
pub use session::{
    Capability, EnvInputs, FinishError, KernelSession, MaterializeError, Movement, Outcome,
    Receipt, SessionTrap, StateDelta,
};
pub use store::{Access, AppliedDelta, MemoryStore, StoreError, SubstateStore};
pub use supply::SupplyLedger;
