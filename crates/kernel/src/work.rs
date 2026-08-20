//! What one shard attests it did for one transaction.
//!
//! Beside a receipt rather than on it, and the distinction is load-bearing.
//! A receipt is the outbound effect record every participant of a
//! cross-shard transaction derives identically — locality decides what is
//! *applied* from it, never what it *says*, which is what lets two shards
//! check each other's copy. Work is the opposite kind of quantity: it is
//! this shard's share, and two participants of one transaction are meant to
//! report different numbers. Putting it inside the receipt would make the
//! two disagree on a structure whose whole value is that they agree.
//!
//! So the executor derives it alongside the receipts, from the same
//! declaration and the same [`Locality`] the receipts were applied under.
//!
//! [`Locality`]: crate::locality::Locality

use hyperscale_vm_types::work_units;

/// One transaction's attested work at one shard.
///
/// [`Work::units`] is the scalar built for a consumer that hashes and signs
/// it; the two components are carried beside it so a surprising total can
/// be read back to the half that moved. A consumer that agrees on the total
/// has no obligation to agree on how it was reached — but it cannot debug a
/// total it cannot decompose.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Fuel consumed, as the engine reported it — priced into
    /// [`Work::units`] only on a completed execution.
    pub fuel: u64,
    /// The declared footprint of the part of the declaration this shard
    /// owns. Unchanged by the verdict.
    pub footprint: u64,
    /// The attested scalar, under the VM's schedule.
    pub units: u64,
}

impl Work {
    /// Price one execution.
    ///
    /// Only a completed execution attests its fuel. An abort attests its
    /// footprint alone — not a pricing judgement but a determinism one:
    /// fuel at a core trap is engine-defined, wasmtime's in-register
    /// counter never having flushed, where `vm-ref` charges every executed
    /// operator (`spike_trap_fuel`). A scalar carrying that number could
    /// not be agreed on across the two runtimes, and prorating the
    /// footprint by how far execution got fails the same way — progress
    /// being the thing that diverges. What survives is the declaration,
    /// which the verdict does not touch, and which the transaction put
    /// through admission, routing, and locking in full whichever way it
    /// ended.
    #[must_use]
    pub const fn attest(completed: bool, fuel: u64, footprint: u64) -> Self {
        Self {
            fuel,
            footprint,
            units: work_units(if completed { fuel } else { 0 }, footprint),
        }
    }
}
