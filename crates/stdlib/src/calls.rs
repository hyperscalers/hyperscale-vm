//! The account and stake pool methods as functions.
//!
//! A typed call still spells its method as a string and its arguments as
//! a tuple, so the two things left for an author to get wrong are the
//! name and the order. These wrappers spend the last of it: one function
//! per method, named parameters in the declared order, narrow address
//! classes where a position admits one, and a return type that *is* the
//! method's output arity.
//!
//! They are hand-written rather than generated, because the parts worth
//! having are the parts metadata does not carry. A signature declares
//! kinds and counts; it does not name a parameter `amount`, and nothing
//! in it says an account method is addressed to a principal. Generating
//! from the signatures would reproduce exactly the positional surface
//! these exist to replace.
//!
//! What that costs is a wrapper that can drift from the signature it
//! mirrors — the error class the builder exists to remove, reintroduced
//! one level up. So every wrapper is exercised against the authored
//! metadata, and every method a package declares is checked to have one.

use hyperscale_vm_effects::{ComponentAddr, PrincipalAddr, ResourceRef, RoleSet, Rule};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

/// The fungible account: every principal answers these.
pub mod account {
    use hyperscale_vm_effects::Value;

    use super::{
        Bucket, BucketArg, PrincipalAddr, Proof, ResourceRef, RoleSet, Rule, TypedBuilder,
        TypedError,
    };

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
    pub fn authorize(
        builder: &mut TypedBuilder<'_>,
        who: PrincipalAddr,
    ) -> Result<Proof, TypedError> {
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
}

/// The stake pool: a delegation surface anyone may use, and an operator
/// surface for whoever presents the configured operator's proof.
pub mod staking {
    use super::{Bucket, BucketArg, ComponentAddr, Proof, TypedBuilder, TypedError};

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
}
