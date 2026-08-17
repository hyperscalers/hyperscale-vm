//! The fungible account: the package every principal answers.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them are read off one text. What stays here is
//! the wrappers a client calls it through, which a signature cannot
//! supply.

use hyperscale_vm_effects::{PackageMetadata, PrincipalAddr, ResourceRef, RoleSet, Rule, Value};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/account/src/lib.rs"]
mod package;

/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a test running
/// this is running the code the artifact was built from rather than a
/// stand-in for it.
pub use package::account::invoke;

/// The fungible account.
///
/// `withdraw(resource, amount)`: reserve `amount` on the caller's vault
/// for `resource`. `deposit(bucket)`: delta on the recipient's vault plus
/// the claims-area fallback cell, both keyed by the bucket's resource.
/// `authorize()`: nothing but its own gate — naming it mints the
/// account's identity as evidence for later nodes of the intent, which
/// is how an account acts through calls its own signature proof would
/// not open. `securify(roles, delay)`: create the stored-authority cell
/// `authorize` reads, refusing one that already exists — the transition
/// off the address-derived rule, one-way. `propose(roles, delay)`,
/// `cancel()`, `confirm()`: the timed recovery surface, each judged
/// against the stored role its accessibility names — recovery proposes a
/// full replacement that matures after the stored delay, primary cancels
/// one that has not, confirmation enacts one early.
///
/// `deposit-nf` and `withdraw-nf` are the same pair over instances: the
/// entries of the holder's per-resource holdings interval, created at
/// deposit and removed at withdrawal, gated exactly as the fungible pair
/// is. `present-badge` is the custody gate — the holder's own rule, since
/// nobody else presents its badges, plus possession of the named badge,
/// minting the badge's address as evidence.
///
/// Spending and writing require the account's own authority; being paid
/// does not. Anyone may credit you, and a transfer therefore still
/// composes under the sender's single signature — the recipient is not
/// asked for one, because nothing about a deposit is theirs to refuse.
/// A method writing a leaf under the target's prefix is gated for the
/// same reason a withdrawal is, though it moves nothing.
///
/// No method reads another account's balance. A precondition on mutable
/// state is a fresh read, which makes the read's owner a participant —
/// the account surface has no shape that wants one yet.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::account::blueprint().metadata()
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Reserve `amount` of `resource` on the proof holder's vault,
/// producing it as an edge typed by the resource named here. The
/// proof is the actor: the withdrawal is from whoever authorized.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw`.
pub fn withdraw(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    resource: impl Into<ResourceRef>,
    amount: u128,
) -> Result<Bucket, TypedError> {
    builder
        .call_as(proof, proof.target(), "withdraw", (resource.into(), amount))?
        .one()
}

/// Credit `funds` to `who`'s vault. Anyone may.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit`.
pub fn deposit(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(who, "deposit", (funds,))?.none()
}

/// Sign in as `who`: mint the account's identity as a proof later
/// calls of the same graph present.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `authorize`.
pub fn authorize(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<Proof, TypedError> {
    builder.call_minting(who, "authorize")
}

/// Sign in as `who` through an identity minted earlier — the way in
/// when `who`'s stored rule names another account rather than a key
/// the intent could carry.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `authorize`.
pub fn authorize_as(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    who: PrincipalAddr,
) -> Result<Proof, TypedError> {
    builder.call_minting_as(proof, who, "authorize")
}

/// Create the proof holder's stored-authority cell — three roles
/// and the recovery delay.
///
/// The one-way transition off the rule the account's address
/// derives. Refused at execution if the cell already exists.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `securify`.
pub fn securify(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    roles: RoleSet,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(
            proof,
            proof.target(),
            "securify",
            (roles, recovery_delay_ms),
        )?
        .none()
}

/// Securify with one rule as all three roles.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `securify`.
pub fn securify_uniform(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    rule: Rule,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    securify(builder, proof, RoleSet::uniform(rule), recovery_delay_ms)
}

/// Propose a full replacement for `who`'s roles and delay, judged by
/// the governing recovery rule against the intent's own signature.
/// The proposal matures after the delay the cell currently stores.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `propose`.
pub fn propose(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    roles: RoleSet,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    builder
        .call(who, "propose", (roles, recovery_delay_ms))?
        .none()
}

/// Drop `who`'s unmatured proposal, judged by the governing primary
/// rule against the intent's own signature.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `cancel`.
pub fn cancel(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<(), TypedError> {
    builder.call(who, "cancel", ())?.none()
}

/// Enact `who`'s pending proposal now, judged by the governing
/// confirmation rule against the intent's own signature.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `confirm`.
pub fn confirm(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<(), TypedError> {
    builder.call(who, "confirm", ())?.none()
}

/// File `funds`' instances as entries of `who`'s holdings. Anyone
/// may, exactly as with the fungible deposit.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit-nf`.
pub fn deposit_nf(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(who, "deposit-nf", (funds,))?.none()
}

/// Remove the named `ids` of `resource` from the proof holder's
/// holdings, producing their edge; an id not held traps at
/// execution.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw-nf`.
pub fn withdraw_nf(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    resource: impl Into<ResourceRef>,
    ids: &[u64],
) -> Result<Bucket, TypedError> {
    let ids = Value::List(ids.iter().copied().map(Value::U64).collect());
    builder
        .call_as(proof, proof.target(), "withdraw-nf", (resource.into(), ids))?
        .one()
}

/// Present `who`'s custody of `badge`: the holder's own rule plus
/// possession, minting the badge's address as evidence for later
/// nodes of the same intent.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `present-badge`.
pub fn present_badge(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    badge: impl Into<ResourceRef>,
) -> Result<Proof, TypedError> {
    builder.call_minting_args(who, "present-badge", (badge.into(),))
}
