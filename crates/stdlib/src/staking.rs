//! The stake pool: delegation for stake units, the validators a
//! pool operates, and the one governance vote it holds.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text. What stays here is the roles a
//! consumer keys by, which a signature does not supply.

use hyperscale_vm_effects::PackageMetadata;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/staking/src/lib.rs"]
mod package;

pub use package::staking::client::*;
/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a test running
/// this is running the code the artifact was built from rather than a
/// stand-in for it.
pub use package::staking::invoke;
pub use package::staking::{ParamVote, Validator};

/// The material separating a pool's owner badge from the unit it issues.
pub const OWNER_BADGE: &[u8] = b"owner-badge";

/// The stake pool.
///
/// `stake(funds)`: the delegation lands in the pool's vault for the
/// resource it is denominated in, and the call returns a bucket of the
/// pool's own stake-unit resource — the delegator's position, held as an
/// ordinary fungible balance in their own account rather than as a record
/// only the pool can read. `unstake(units)`: the returned units are
/// destroyed, and the event is what records that the pool owes their
/// stake back.
///
/// Both are `delta`, and that is the whole contention story: a delegation
/// commutes with every other delegation, so a pool's popularity costs its
/// shard throughput and never serialization. Nothing reads a pool
/// aggregate. The beacon accumulates per-pool totals from the events these
/// methods emit and spends them on its own capacity tests, so a total kept
/// here would be a second copy of a number consensus already holds, on a
/// cell every delegator would have to take a turn on.
///
/// The operator surface — `register-validator`, `deactivate-validator`,
/// `unjail` — is the pool speaking about validators rather than about
/// stake, and it has an actor a delegation does not. Each writes the
/// pool's own leaf for the validator it names, keyed by that validator, so
/// two operators of two validators never take turns and the pool's shard
/// is a participant in the tick that carries the fact. That participation
/// is the reason the leaf exists at all: an event is kept by the shard
/// owning its emitter, and a method declaring no access would leave the
/// pool's shard out of the transaction that emitted from it.
///
/// The governance surface — `cast-param-vote`, `clear-param-vote` — is
/// the same actor again, on the pool's single vote leaf. Its arguments
/// are the network parameters themselves rather than an opaque
/// encoding: the set is three numbers, so carrying them positionally
/// costs nothing and lets a malformed vote fail its transaction instead
/// of succeeding and being dropped where nobody sees it. It does weld
/// this package to the parameter set, which is the right coupling —
/// adding a governed parameter is a protocol change, and the package
/// that votes on them is versioned with them.
///
/// One creation-fixed field configures an instance: the resource it
/// stakes. The resource it *issues* is not among them — it derives from
/// the pool, which is what keeps the configuration writable at all,
/// since a pool's address commits its configuration and a configured
/// field naming a value derived from that address could not be written
/// down. Neither is the operator: the operator surface admits whoever
/// presents the pool's owner badge, itself derived from the pool, so
/// selling the pool is transferring the badge rather than rewriting a
/// configuration no instance can rewrite. There is deliberately no field
/// naming the pool either, because a pool that named itself could name a
/// different one: the kernel stamps an event's emitter, so the instance
/// is the subject and nothing about it is the guest's to choose.
///
/// `stake` and `unstake` are public, and that is not an oversight. A pool
/// instance is owned by nobody; the authority behind a delegation is the
/// funds the caller supplies, and those were gated upstream at the
/// withdrawal that produced them. The operator surface supplies no funds,
/// so it has no such authority to inherit and names the one its
/// configuration carries.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::staking::blueprint().metadata()
}
