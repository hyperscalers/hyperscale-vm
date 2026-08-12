//! The stdlib's methods as functions.
//!
//! A typed call still spells its method as a string and its arguments as a
//! tuple, so the two things left for an author to get wrong are the name
//! and the order. These wrappers spend the last of it: one function per
//! stdlib method, named parameters in the declared order, narrow address
//! classes where a position admits one, and a return type that *is* the
//! method's output arity — `Bucket`, `(Bucket, Bucket)`, or nothing.
//!
//! They are hand-written rather than generated, because the parts worth
//! having are the parts metadata does not carry. A signature declares
//! kinds and counts; it does not name a parameter `amount`, and nothing in
//! it says an account method is addressed to a principal. Generating from
//! `stdlib.rs` would reproduce exactly the positional surface these exist
//! to replace.
//!
//! What that costs is a wrapper that can drift from the signature it
//! mirrors — the error class the builder exists to remove, reintroduced
//! one level up. So every wrapper is exercised against the authored
//! metadata, and every method the stdlib declares is checked to have one.
//! Arity, kinds and output count are pinned by the typed layer refusing
//! the call; a method added without a wrapper is pinned by the count.

use hyperscale_vm_effects::{ComponentAddr, PrincipalAddr, ResourceRef};

use crate::args::BucketArg;
use crate::builder::Bucket;
use crate::typed::{TypedBuilder, TypedError};

/// The fungible account: every principal answers these.
pub mod account {
    use super::{Bucket, BucketArg, PrincipalAddr, ResourceRef, TypedBuilder, TypedError};

    /// Reserve `amount` of `resource` on `who`'s vault, producing it as an
    /// edge typed by the resource named here.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `withdraw`.
    pub fn withdraw(
        builder: &mut TypedBuilder<'_>,
        who: PrincipalAddr,
        resource: impl Into<ResourceRef>,
        amount: u128,
    ) -> Result<Bucket, TypedError> {
        builder
            .call(who, "withdraw", (resource.into(), amount))?
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

    /// Write the transaction's randomness draw into `who`'s entropy leaf.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `stamp-entropy`.
    pub fn stamp_entropy(
        builder: &mut TypedBuilder<'_>,
        who: PrincipalAddr,
    ) -> Result<(), TypedError> {
        builder.call(who, "stamp-entropy", ())?.none()
    }
}

/// The stake pool: a delegation surface anyone may use, and an operator
/// surface the pool's configured principal may.
pub mod staking {
    use super::{Bucket, BucketArg, ComponentAddr, TypedBuilder, TypedError};

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
        pool: ComponentAddr,
        validator: u64,
        key: Vec<u8>,
        possession_proof: Vec<u8>,
    ) -> Result<(), TypedError> {
        builder
            .call(
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
        pool: ComponentAddr,
        validator: u64,
    ) -> Result<(), TypedError> {
        builder
            .call(pool, "deactivate-validator", (validator,))?
            .none()
    }

    /// Return `validator` to service.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `unjail`.
    pub fn unjail(
        builder: &mut TypedBuilder<'_>,
        pool: ComponentAddr,
        validator: u64,
    ) -> Result<(), TypedError> {
        builder.call(pool, "unjail", (validator,))?.none()
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
        pool: ComponentAddr,
        split_bytes: u64,
        impound_epochs: u64,
        activate_at: u64,
    ) -> Result<(), TypedError> {
        builder
            .call(
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
        pool: ComponentAddr,
    ) -> Result<(), TypedError> {
        builder.call(pool, "clear-param-vote", ())?.none()
    }
}

/// The constant-product pool.
pub mod amm {
    use super::{Bucket, BucketArg, ComponentAddr, TypedBuilder, TypedError};

    /// Trade `input` through `pool`, refusing to settle for less than
    /// `min_out`. The proceeds are typed by the pool's configured output
    /// resource.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `swap`.
    pub fn swap(
        builder: &mut TypedBuilder<'_>,
        pool: ComponentAddr,
        input: impl BucketArg,
        min_out: u128,
    ) -> Result<Bucket, TypedError> {
        builder.call(pool, "swap", (input, min_out))?.one()
    }
}

/// The order book.
pub mod book {
    use super::{Bucket, BucketArg, ComponentAddr, TypedBuilder, TypedError};

    /// Offer `funds` on `book` at `price`, escrowed until filled.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `place-ask`.
    pub fn place_ask(
        builder: &mut TypedBuilder<'_>,
        book: ComponentAddr,
        price: u64,
        funds: impl BucketArg,
    ) -> Result<(), TypedError> {
        builder.call(book, "place-ask", (price, funds))?.none()
    }

    /// Spend `payment` against `book`'s asks priced within `from..=to`,
    /// answering what was bought and then what of the payment was not
    /// spent, in that order.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `fill-asks`.
    pub fn fill_asks(
        builder: &mut TypedBuilder<'_>,
        book: ComponentAddr,
        from: u64,
        to: u64,
        payment: impl BucketArg,
    ) -> Result<[Bucket; 2], TypedError> {
        builder
            .call(book, "fill-asks", (from, to, payment))?
            .into_array()
    }
}

/// The bucket splitter.
pub mod splitter {
    use super::{Bucket, BucketArg, ComponentAddr, TypedBuilder, TypedError};

    /// Split `amount` off `funds`, answering the part taken and then the
    /// rest — both typed by what went in, and both of which linearity
    /// forces the graph to route.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `take`.
    pub fn take(
        builder: &mut TypedBuilder<'_>,
        splitter: ComponentAddr,
        funds: impl BucketArg,
        amount: u128,
    ) -> Result<[Bucket; 2], TypedError> {
        builder
            .call(splitter, "take", (funds, amount))?
            .into_array()
    }
}
