//! The stake pool: delegation for stake units, the validators a
//! pool operates, and the one governance vote it holds.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the roles a consumer keys by and the wrappers a client calls it
//! through, neither of which a signature supplies.

use hyperscale_vm_effects::{ComponentAddr, PackageMetadata, RoleId, package_role};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/staking/src/lib.rs"]
mod package;

/// A stake pool's total awaiting release to the delegators who returned
/// their units.
pub const UNBONDING: RoleId = package_role(0);
/// A stake pool's record of one validator it operates.
pub const VALIDATORS: RoleId = package_role(1);
/// A stake pool's one active network-parameter vote.
pub const VOTE: RoleId = package_role(2);

/// The material separating a pool's owner badge from the unit it issues.
pub const OWNER_BADGE: &[u8] = b"owner-badge";

/// The stake pool.
///
/// `stake(funds)`: the delegation lands in the pool's vault for the
/// resource it is denominated in, and the call returns a bucket of the
/// pool's own stake-unit resource — the delegator's position, held as an
/// ordinary fungible balance in their own account rather than as a record
/// only the pool can read. `unstake(units)`: the returned units are
/// consumed and the pool's unbonding total grows by what they represent.
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

// ─── calls ─────────────────────────────────────────────────────────────

/// Delegate `funds` to `pool`, receiving the pool's own stake units —
/// an edge typed by the pool rather than by what was staked.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `stake`.
pub fn stake(
    builder: &mut TypedBuilder<'_>,
    pool: ComponentAddr,
    funds: impl BucketArg,
) -> Result<Bucket, TypedError> {
    builder.call(pool, "stake", (funds,))?.one()
}

/// Return `units` to `pool`, growing what it owes on release.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `unstake`.
pub fn unstake(
    builder: &mut TypedBuilder<'_>,
    pool: ComponentAddr,
    units: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(pool, "unstake", (units,))?.none()
}

/// Record `validator` on `pool`'s own leaf for it, under the key it
/// will sign with and the proof it holds the key.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `register-validator`.
pub fn register_validator(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
    key: Vec<u8>,
    possession_proof: Vec<u8>,
) -> Result<(), TypedError> {
    builder
        .call_as(
            operator,
            pool,
            "register-validator",
            (validator, key, possession_proof),
        )?
        .none()
}

/// Retire `validator` from `pool`'s operating set.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `deactivate-validator`.
pub fn deactivate_validator(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "deactivate-validator", (validator,))?
        .none()
}

/// Return `validator` to service.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `unjail`.
pub fn unjail(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    validator: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "unjail", (validator,))?
        .none()
}

/// Replace `pool`'s single network-parameter vote with this one. The
/// parameters travel as themselves, so a malformed vote fails its
/// transaction rather than being counted and discarded.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `cast-param-vote`.
pub fn cast_param_vote(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
    split_bytes: u64,
    impound_epochs: u64,
    activate_at: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(
            operator,
            pool,
            "cast-param-vote",
            (split_bytes, impound_epochs, activate_at),
        )?
        .none()
}

/// Empty `pool`'s vote leaf, so it backs nothing.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against
/// `clear-param-vote`.
pub fn clear_param_vote(
    builder: &mut TypedBuilder<'_>,
    operator: Proof,
    pool: ComponentAddr,
) -> Result<(), TypedError> {
    builder
        .call_as(operator, pool, "clear-param-vote", ())?
        .none()
}
