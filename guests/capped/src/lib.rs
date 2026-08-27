//! Supply that cannot grow, supply that can only shrink, and minting
//! somebody else does.
//!
//! Three resources and no movement entry between them, which is the
//! point: an authority entry answers for itself — absence withholds the
//! capability rather than permitting a movement — so all three addresses
//! stay plain `Resource` and a holder pays nothing on the transfer path.
//! Anyone re-cutting the class byte around "has grants" breaks this
//! package first.
//!
//! What separates them is which entries they carry.
//!
//! `Founded` carries none. Its whole supply is founded where its record is
//! written, and founding is not minting — no `Mint` entry governs a
//! creation — so the supply is exactly what the component came up
//! holding and nothing can add to it. That is capped supply spelled as
//! an absence: an integrator reads it off the address, without reading a
//! line of this package.
//!
//! `Retired` carries `burn` and no `Mint`, so its supply is founded once
//! and only ever falls. The pair is what makes the two entries
//! independent rather than two directions of one right: a resource can
//! be destroyed by an authority that could never create it.
//!
//! `Circulating` carries the same entry open to anyone, which is the
//! other half of that: destroying is the *holder's* where minting is the
//! issuer's, so it happens through the holder's own account and this
//! package is not in the path at all.
//!
//! `Seat` carries `mint` naming a configured badge, and nothing else.
//! Minting is a credential rather than a fact about the issuer's
//! address, so whoever holds the badge mints and the component's own
//! code has no say — the requirement is injected from the resource's own
//! entry and judged against what the call presented.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod capped {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// Founded in full and never minted again.
    ///
    /// Granting nothing at all, which is what leaves the address unable
    /// to admit a mint however the caller is authorized: publish refuses
    /// a body that mints this, so there is no such method to reach.
    #[resource(initial(1_000_000), display_digits = 0)]
    struct Founded;

    /// Founded in full, and burnable by its issuer.
    ///
    /// The deflationary shape: supply starts where creation put it and
    /// moves one way. `burn` without `mint` is only spellable because
    /// the two are independent entries rather than two readings of one
    /// grant.
    #[resource(initial(500), grants(burn = self), display_digits = 0)]
    struct Retired;

    /// Founded in full, and destroyed by whoever holds it.
    ///
    /// The deflationary token: `burn = anyone` is an entry rather than a
    /// permission the kernel hands out, so retiring it goes through the
    /// holder's own account and the issuer is not a party to it. Absence
    /// of the entry is what makes that the exception — `Founded` beside it
    /// grants none, and nobody may destroy it at all.
    #[resource(initial(1_000), grants(burn = anyone), display_digits = 0)]
    struct Circulating;

    /// Minted by whoever holds the configured badge, and by nobody else.
    ///
    /// The issuing instance's own claim does not satisfy this rule, so
    /// the requirement reaches the call and a caller answers for
    /// whatever `config.minter` names. What that makes a credential is
    /// the authority rather than the seat: name a badge there and
    /// minting splits, delegates and is taken back on the badge's own
    /// terms, none of which this mark states or needs to.
    #[resource(grants(mint = config.minter), display_digits = 0)]
    struct Seat;

    /// Who may mint the seat.
    #[config]
    struct Terms {
        minter: Address,
    }

    impl Capped {
        /// Retire `funds`, which shrinks the supply and cannot grow it.
        pub fn retire(&mut self, funds: Bucket) {
            Retired::burn(funds);
        }

        /// Issue seats.
        ///
        /// No authored gate: what holds this method is the resource's
        /// own `mint` entry, injected onto the frame at admission — so a
        /// package that wrote nothing about authority is bound anyway,
        /// which is the property the whole design exists for.
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Seat::mint(amount)
        }
    }
}
