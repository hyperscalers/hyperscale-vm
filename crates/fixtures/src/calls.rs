//! The fixture packages' methods as functions.
//!
//! The same hand-written wrappers the protocol's packages carry, for the
//! same reason: a signature declares kinds and counts, never that a
//! position takes a price or an entrant, so generating them would
//! reproduce the positional surface they exist to replace. Each is
//! exercised against the authored metadata it mirrors.

use hyperscale_vm_effects::{ComponentAddr, PrincipalAddr, ResourceRef};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

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

/// The lottery: a pot anyone may enter, and a winner nobody chooses.
pub mod lottery {
    use super::{BucketArg, ComponentAddr, PrincipalAddr, TypedBuilder, TypedError};

    /// Enter `who` in `lottery`'s round, staking `funds` into the pot.
    ///
    /// Whoever composes the call names the entrant, which is what buying
    /// somebody a ticket looks like: the authority behind an entry is the
    /// funds, gated at the withdrawal that produced them.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `enter`.
    pub fn enter(
        builder: &mut TypedBuilder<'_>,
        lottery: ComponentAddr,
        who: PrincipalAddr,
        funds: impl BucketArg,
    ) -> Result<(), TypedError> {
        builder.call(lottery, "enter", (who, funds))?.none()
    }

    /// Settle `lottery`'s round on the transaction's randomness draw.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `draw`.
    pub fn draw(builder: &mut TypedBuilder<'_>, lottery: ComponentAddr) -> Result<(), TypedError> {
        builder.call(lottery, "draw", ())?.none()
    }
}

/// The non-fungible fixture: an issuer that mints and burns, holders
/// whose instances are holdings entries.
pub mod nf {
    use hyperscale_vm_effects::Value;

    use super::{Bucket, BucketArg, ComponentAddr, ResourceRef, TypedBuilder, TypedError};

    /// Mint one fresh instance of `issuer`'s resource, producing its
    /// one-id edge.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `mint`.
    pub fn mint(
        builder: &mut TypedBuilder<'_>,
        issuer: ComponentAddr,
    ) -> Result<Bucket, TypedError> {
        builder.call(issuer, "mint", ())?.one()
    }

    /// File `funds`' instances as entries of `holder`'s holdings.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `deposit`.
    pub fn deposit(
        builder: &mut TypedBuilder<'_>,
        holder: ComponentAddr,
        funds: impl BucketArg,
    ) -> Result<(), TypedError> {
        builder.call(holder, "deposit", (funds,))?.none()
    }

    /// Remove the named `ids` of `resource` from `holder`'s holdings,
    /// producing their edge; an id not held traps at execution.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `withdraw`.
    pub fn withdraw(
        builder: &mut TypedBuilder<'_>,
        holder: ComponentAddr,
        resource: impl Into<ResourceRef>,
        ids: &[u64],
    ) -> Result<Bucket, TypedError> {
        let ids = Value::List(ids.iter().copied().map(Value::U64).collect());
        builder
            .call(holder, "withdraw", (resource.into(), ids))?
            .one()
    }

    /// Consume `funds` outright: its instances stop being held anywhere.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `burn`.
    pub fn burn(
        builder: &mut TypedBuilder<'_>,
        issuer: ComponentAddr,
        funds: impl BucketArg,
    ) -> Result<(), TypedError> {
        builder.call(issuer, "burn", (funds,))?.none()
    }

    /// Act on the badge-gated instance, presenting the badge identity a
    /// custody gate minted.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `operate`.
    pub fn operate(
        builder: &mut TypedBuilder<'_>,
        gated: ComponentAddr,
        proof: super::Proof,
    ) -> Result<(), TypedError> {
        builder.call_as(proof, gated, "operate", ())?.none()
    }
}

/// The name registry.
pub mod registry {
    use super::{ComponentAddr, TypedBuilder, TypedError};

    /// Bind `name` to `value` on `registry`, overwriting any prior
    /// binding.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `bind`.
    pub fn bind(
        builder: &mut TypedBuilder<'_>,
        registry: ComponentAddr,
        name: u64,
        value: u128,
    ) -> Result<(), TypedError> {
        builder.call(registry, "bind", (name, value))?.none()
    }

    /// Read the binding for `name`; execution traps unless it holds
    /// exactly `expected`.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `check`.
    pub fn check(
        builder: &mut TypedBuilder<'_>,
        registry: ComponentAddr,
        name: u64,
        expected: u128,
    ) -> Result<(), TypedError> {
        builder.call(registry, "check", (name, expected))?.none()
    }

    /// Remove one crank's worth of bindings from `cursor` up the hash
    /// order; resume from the last removed order plus one.
    ///
    /// # Errors
    ///
    /// Any [`TypedError`] the call does not type against `drain`.
    pub fn drain(
        builder: &mut TypedBuilder<'_>,
        registry: ComponentAddr,
        cursor: u128,
    ) -> Result<(), TypedError> {
        builder.call(registry, "drain", (cursor,))?.none()
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
