//! A redemption window at a price that moves both ways: hand in the
//! stable, take reserve at parity plus whatever the oracle says the
//! market has done to it.
//!
//! # Why the deviation is signed
//!
//! A pegged asset trades above parity as often as below, and the two are
//! the same fact with a sign on it. A market that could only say "how far
//! below" would need a second method for the other direction, a flag
//! beside the number, or a convention that a number under one means one
//! thing and over it another — and every one of those is a sign held by
//! hand.
//!
//! This is the shape a signed stored rate is *for*: a value that is
//! **set** rather than accumulated. Nothing here sums a series of signed
//! increments — the oracle overwrites, and what the last post said is the
//! whole of what the market knows. A pair of monotone counters, which is
//! the right answer for a funding accumulator, says nothing at all about
//! a value somebody assigns.
//!
//! # Why the price never becomes one number
//!
//! What a redeemer receives is parity plus the deviation, and the window
//! keeps the truncated subunit whichever way that points. That is one
//! rule and two operations: above parity the gain is floored, below it
//! the loss is *ceilinged*, because rounding down for the redeemer means
//! rounding opposite ways at the arithmetic. A single signed figure
//! converted once cannot say that — by the time it is one number the two
//! directions are indistinguishable.
//!
//! So the deviation splits into a magnitude and the way it points, the
//! body branches, and each arm names the rounding it means. That is the
//! whole reason a signed rate has no `convert`.
//!
//! # What this deliberately is not
//!
//! One direction: the window redeems and does not mint. The reserve is
//! funded from outside and the stable is somebody else's resource, so
//! there is no supply here to defend a peg with — what is here is the
//! arithmetic a peg is wrong about when it is wrong, which is the price
//! and the band it is allowed to move in.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod peg {
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Fixed, Quantity, Rounding, Sign, SignedFixed, UnitFixed,
    };
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// What the window redeems.
    pub struct Stable;
    /// What it pays out in.
    pub struct Reserve;

    /// The window's creation-fixed terms.
    #[config]
    struct Terms {
        /// The asset a redeemer hands in.
        stable: ResourceAddr,
        /// The asset the window pays out.
        reserve: ResourceAddr,
        /// Who may say what the stable is trading at. A price anyone
        /// could post is a redemption anyone could mispriced.
        oracle: Address,
        /// How far from parity the window still quotes, either way.
        ///
        /// A band rather than a floor, because a peg that quotes any
        /// price is not a peg: a deviation past this is a market the
        /// window has nothing useful to say about, and refusing is what
        /// stops it paying out against a number nobody believes.
        band: UnitFixed,
    }

    /// What a redemption declines with.
    #[error]
    enum Error {
        /// The posted deviation is outside the band the window quotes in.
        OutsideBand,
        /// The redemption is too small to be worth a subunit of reserve.
        NothingRedeemed,
    }

    #[state]
    struct Peg {
        /// How far one stable subunit sits from one reserve subunit.
        ///
        /// Signed, set, and the only thing this market knows: positive
        /// where the stable trades above parity, negative below, and zero
        /// at it. An unwritten cell reads as zero, which is parity — the
        /// one starting value that needs no special case.
        deviation: Cell<SignedFixed<Reserve, Stable>>,
    }

    impl Peg {
        /// Post what the stable is trading at, as its distance from
        /// parity.
        ///
        /// The oracle signs a rate, so what it means travels with it: the
        /// reserve a stable subunit is worth over parity, or under it.
        /// Neither the scale nor the direction is a convention this body
        /// and the caller have to agree on separately.
        #[requires(oracle)]
        pub fn post_deviation(&mut self, deviation: SignedFixed<Reserve, Stable>) {
            self.deviation.set(deviation);
        }

        /// Hand in stable, take reserve at parity plus the deviation.
        pub fn redeem(&mut self, funds: Bucket) -> Result<Bucket, Error> {
            let terms = self.config();
            let (distance, way) = self.deviation.get().split();
            if distance > band(terms.band) {
                return Err(Error::OutsideBand);
            }

            let handed_in = funds.quantity();
            let payout = payout(handed_in, distance, way);
            if payout.is_zero() {
                return Err(Error::NothingRedeemed);
            }

            self.vault(terms.stable).put(funds);
            Ok(self.vault(terms.reserve).take(payout))
        }

        /// What `amount` of stable would fetch, without sending any.
        ///
        /// What a redeemer asks before signing. It answers with a
        /// quantity rather than with the deviation, because a signed rate
        /// crossing back out would make every reader agree with this
        /// package about a sign convention — and the number they wanted
        /// is this one.
        pub fn quote(&self, amount: Quantity) -> Quantity {
            let (distance, way) = self.deviation.get().split();
            payout(amount, distance, way)
        }
    }

    /// What `handed_in` fetches at a deviation of `distance` in the
    /// direction `way`.
    ///
    /// A free function over values already read, which is how two bodies
    /// share one calculation here: a method cannot call another method of
    /// its own component, because each declares only its own accesses.
    /// Lifting the reads to parameters is what the refusal points at, and
    /// it is cheaper than the alternative both bodies writing it out.
    ///
    /// Rounded down *for the redeemer* on both sides, which is one rule
    /// spelled as two operations: a floor on a sum and a floor on a
    /// difference round opposite ways at the arithmetic, and only the
    /// second of them is a ceiling. That is the whole reason the
    /// deviation is split before it is applied rather than converted
    /// whole — one signed figure has nowhere to put two directions.
    fn payout(handed_in: Quantity, distance: Fixed<Reserve, Stable>, way: Sign) -> Quantity {
        match way {
            Sign::Positive => handed_in + handed_in.convert(distance.rate(), Rounding::Down),
            Sign::Negative => handed_in
                .try_sub(handed_in.convert(distance.rate(), Rounding::Up))
                .unwrap_or(Quantity::ZERO),
        }
    }

    /// The band as the rate a deviation is compared against.
    ///
    /// A `UnitFixed` runs to one at its own scale, and a deviation is a
    /// rate at the stored scale, so the two meet as rates rather than as
    /// the integers they are held in.
    fn band(bound: UnitFixed) -> Fixed<Reserve, Stable> {
        bound.ratio().quantize_as(Rounding::Down)
    }
}
