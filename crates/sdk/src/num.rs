//! The numeric vocabulary a contract body computes in.
//!
//! Three jobs the `u128` this replaces was doing at once. A **quantity**
//! is an amount of a resource: linear, conserved, exact, and closed under
//! nothing but addition and subtraction. A **ratio** is a quotient of two
//! quantities, held unevaluated so that applying it is one rounding
//! rather than two. A **rate** is the same fraction with a dimension on
//! each term. What makes `y * dx` inexpressible is that the first has no
//! multiplication at all: the only products that typecheck are a quantity
//! against a fraction, which is the grouping that cannot overflow.
//!
//! # Nothing here is an operator
//!
//! [`Quantity`] has no `Mul` and no `Div`. Every product and quotient is
//! a named method, because a lossy one takes a [`Rounding`] argument and
//! an operator has nowhere to put it. A default direction would answer
//! silently the one question a reader most needs answered — which side
//! keeps the truncated subunit — so there is none.
//!
//! Composition and comparison are named for a second reason: each is a
//! boundary crossing, and a crossing hiding behind `*` or `<` is a fuel
//! surprise.
//!
//! # One implementation, three callers
//!
//! The arithmetic is the host's. On the guest it is
//! `hyperscale:kernel/math`; on the native lane it is the same functions
//! called directly. So an author's fast lane, the blessed engine and the
//! reference interpreter do not agree about money — they share one body.
//!
//! Addition, subtraction and comparison of quantities stay inline: they
//! have no width subtlety and no rounding question, and a crossing per
//! addition would be absurd.

use core::cmp::Ordering;
use core::marker::PhantomData;

use hyperscale_hbor::{Hbor, HborDecode, HborEncode, HborShape, HborWidth};

// The arithmetic, from whichever side of the boundary this build is on.
// One alias rather than a branch per call site: the two modules expose
// the same five functions under the same names, because they stand for
// one implementation reached two ways.
#[cfg(component)]
use crate::guest as arith;
#[cfg(not(component))]
use crate::host as arith;

/// The scale a stored rate is quantized to: `10^36`.
pub const FIXED_SCALE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// The largest value a [`UnitFixed`] may hold: one, at its own scale.
pub const UNIT_SCALE: u128 = 1_000_000_000_000_000_000;

/// Which way a lossy operation resolves a non-zero remainder — the
/// arithmetic's own type, required wherever a lossy operation happens.
/// §"Dust" in the design notes states which direction is correct where;
/// the type only insists that a body say which it took.
pub use hyperscale_vm_types::math::Rounding;

/// Why a construction refused its inputs.
///
/// Constructors return; applications trap. A zero denominator or an
/// out-of-range configuration value is a state condition an author can
/// decline on, and a body that meets one knows what it means. A quotient
/// past the width on well-formed inputs is a defect, and there is nothing
/// for a caller to do with it but stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumError {
    /// A fraction with a zero denominator: an empty pool, a rate against
    /// nothing.
    ZeroDenominator,
    /// A configuration value outside the range its type admits.
    OutOfRange,
}

/// A 256-bit unsigned value, as four limbs, least significant first.
///
/// Storage only, and deliberately not the arithmetic's
/// [`U256`](hyperscale_vm_types::math::U256): every lossy operation on
/// one is the host's, so this carries exact guest-side addition and
/// ordering and nothing else — it is the shape a fraction's terms travel
/// and live in, wide enough that composing two quantity-derived rates
/// does not overflow at the depth a cross rate reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Wide([u64; 4]);

impl Wide {
    /// Zero.
    pub const ZERO: Self = Self([0; 4]);
    /// One.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// The value `n`, widened.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
    pub const fn from_u128(n: u128) -> Self {
        Self([n as u64, (n >> 64) as u64, 0, 0])
    }

    /// The limbs, least significant first.
    #[must_use]
    pub const fn limbs(self) -> [u64; 4] {
        self.0
    }

    /// The value these limbs name.
    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    /// The sum, or `None` past the width.
    ///
    /// Guest-side and exact. A stored rate is a thing bodies add to, and
    /// a cumulative index is added to once per update forever — a
    /// boundary crossing per addition would be absurd, and there is no
    /// rounding question for one to answer.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        let (sum, carry) = limb_add(self.0, other.0);
        if carry { None } else { Some(Self(sum)) }
    }

    /// The difference, or `None` below zero.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        let (difference, borrow) = limb_sub(self.0, other.0);
        if borrow { None } else { Some(Self(difference)) }
    }

    /// The sum, discarding the carry.
    ///
    /// What a two's complement value adds through, where the carry out of
    /// the top limb is the wrap the representation is defined by rather
    /// than a loss. [`Wide::checked_add`] is the one an unsigned value
    /// wants.
    #[must_use]
    pub const fn wrapping_add(self, other: Self) -> Self {
        let (sum, _) = limb_add(self.0, other.0);
        Self(sum)
    }

    /// The two's complement negation: every bit flipped, plus one.
    ///
    /// Its own fixed point at the top of the range, which is the one
    /// value a signed reading cannot negate — the caller that reads this
    /// as signed is the one that owes that check.
    #[must_use]
    pub const fn wrapping_neg(self) -> Self {
        let mut flipped = [0u64; 4];
        let mut limb = 0;
        while limb < 4 {
            flipped[limb] = !self.0[limb];
            limb += 1;
        }
        let (negated, _) = limb_add(flipped, [1, 0, 0, 0]);
        Self(negated)
    }

    /// Whether the top bit is set, which is what a two's complement
    /// reading calls negative.
    #[must_use]
    pub const fn top_bit(self) -> bool {
        self.0[3] >> 63 == 1
    }

    /// The canonical little-endian bytes: each limb's own eight, least
    /// significant limb first.
    ///
    /// The one place the width's byte form is written. A configuration
    /// slot holds these, a leaf holds these, and a guest decodes these,
    /// so a second spelling anywhere would be a second answer to what a
    /// stored rate looks like.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut limb = 0;
        while limb < 4 {
            let word = self.0[limb].to_le_bytes();
            let mut byte = 0;
            while byte < 8 {
                bytes[limb * 8 + byte] = word[byte];
                byte += 1;
            }
            limb += 1;
        }
        bytes
    }

    /// The value those bytes name.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        let mut limb = 0;
        while limb < 4 {
            let mut word = [0u8; 8];
            let mut byte = 0;
            while byte < 8 {
                word[byte] = bytes[limb * 8 + byte];
                byte += 1;
            }
            limbs[limb] = u64::from_le_bytes(word);
            limb += 1;
        }
        Self(limbs)
    }

    /// The value as a `u128`, or nothing past the amount width.
    ///
    /// What a body reaches for on a wide value it *stored* — a rate a
    /// market has been compounding — because how far that can grow is a
    /// fact about the market rather than about the arithmetic, and a
    /// reader asking for a number that will not fit should hear so rather
    /// than lose the transaction.
    #[must_use]
    pub const fn try_to_u128(self) -> Option<u128> {
        if self.0[2] == 0 && self.0[3] == 0 {
            Some((self.0[0] as u128) | ((self.0[1] as u128) << 64))
        } else {
            None
        }
    }

    /// The value as a `u128`.
    ///
    /// For the narrowings the vocabulary's own arithmetic proves: an
    /// amount scaled by a fraction at most one, a root, the mean of two
    /// amounts. [`Wide::try_to_u128`] is the one to reach for where the
    /// width is a fact about what a guest stored.
    ///
    /// # Panics
    ///
    /// Past the amount width.
    #[must_use]
    pub const fn to_u128(self) -> u128 {
        assert!(
            self.0[2] == 0 && self.0[3] == 0,
            "a wide value past the amount width"
        );
        (self.0[0] as u128) | ((self.0[1] as u128) << 64)
    }
}

impl Ord for Wide {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Wide {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn limb_add(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (partial, first) = a[i].overflowing_add(b[i]);
        let (total, second) = partial.overflowing_add(carry);
        out[i] = total;
        carry = if first || second { 1 } else { 0 };
        i += 1;
    }
    (out, carry != 0)
}

const fn limb_sub(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (partial, first) = a[i].overflowing_sub(b[i]);
        let (total, second) = partial.overflowing_sub(borrow);
        out[i] = total;
        borrow = if first || second { 1 } else { 0 };
        i += 1;
    }
    (out, borrow != 0)
}

/// An amount of one resource, in integer subunits.
///
/// Conserved and exact. Addition and subtraction are the whole of its
/// closed arithmetic; everything else leaves the type, because everything
/// else is either a fraction of it or a comparison against another
/// resource's.
/// Encoded as the width it is: a `u128` of subunits, with the tag erased,
/// which is the same form its cell holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Hash, Hbor, HborShape)]
#[hbor(transparent, infallible)]
pub struct Quantity(u128);

impl Quantity {
    /// Nothing.
    pub const ZERO: Self = Self(0);

    /// The quantity `subunits` names.
    ///
    /// The one way to make one from a bare integer, and deliberately the
    /// only one: a quantity that could be summoned from any `u128` would
    /// put the vocabulary's whole point back where it was.
    #[must_use]
    pub const fn from_subunits(subunits: u128) -> Self {
        Self(subunits)
    }

    /// The subunits this carries.
    ///
    /// For the boundaries the vocabulary does not reach: an order key, a
    /// modulus, an event payload. Not for arithmetic — anything computed
    /// out here is computed outside every rule this module states.
    #[must_use]
    pub const fn subunits(self) -> u128 {
        self.0
    }

    /// Whether this is nothing.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The difference, or `None` where it would go below zero.
    ///
    /// The spelling for insufficient funds, which is a business condition
    /// and deserves a declared refusal rather than a discarded
    /// transaction.
    #[must_use]
    pub const fn try_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// The difference, floored at nothing.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// The smaller of two.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }

    /// The larger of two.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

    /// Whether this is a whole multiple of `step`.
    ///
    /// Nothing on-chain consults a resource's display width, so a contract
    /// that wants granularity enforces it. A zero step divides nothing
    /// and answers false rather than trapping.
    #[must_use]
    pub const fn is_multiple_of(self, step: Self) -> bool {
        step.0 != 0 && self.0.is_multiple_of(step.0)
    }

    /// This quantity moved to a whole multiple of `step`.
    ///
    /// A zero step is no quantization and returns the quantity unchanged.
    #[must_use]
    pub const fn round_to_multiple(self, step: Self, rounding: Rounding) -> Self {
        if step.0 == 0 {
            return self;
        }
        let floor = self.0 - self.0 % step.0;
        match rounding {
            Rounding::Down => Self(floor),
            Rounding::Up if floor == self.0 => self,
            Rounding::Up => Self(floor + step.0),
        }
    }

    /// The integer square root: the largest `r` with `r * r <= self`.
    ///
    /// What a quadratic weighting needs, and half of what an initial
    /// liquidity mint does — the other half is [`Quantity::geometric_mean`],
    /// which holds the product whole.
    #[must_use]
    pub fn sqrt(self) -> Self {
        Self(arith::geometric_mean(Wide::from_u128(self.0), Wide::ONE).to_u128())
    }

    /// `floor(sqrt(self * other))`, the product held whole.
    ///
    /// The mint an author cannot write as `(x * y).sqrt()`: for any pool
    /// a real market reaches, the product leaves the amount width and the
    /// root does not.
    #[must_use]
    pub fn geometric_mean(self, other: Self) -> Self {
        Self(arith::geometric_mean(Wide::from_u128(self.0), Wide::from_u128(other.0)).to_u128())
    }

    /// This quantity over another of the same resource, as a
    /// dimensionless ratio.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] against nothing — an empty pool,
    /// which is a refusal an author can word rather than a trap.
    pub const fn ratio_to(self, other: Self) -> Result<Ratio, NumError> {
        Ratio::of(self.0, other.0)
    }

    /// This quantity over one of another resource, as a rate.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] against nothing.
    pub const fn per<A, B>(self, other: Self) -> Result<Rate<A, B>, NumError> {
        match Ratio::of(self.0, other.0) {
            Ok(ratio) => Ok(Rate {
                ratio,
                dimension: PhantomData,
            }),
            Err(error) => Err(error),
        }
    }

    /// This quantity partitioned by `share`: the part, and the remainder.
    ///
    /// Both halves, because both are real. A partition divides an amount
    /// a body holds, so the residue belongs somewhere and returning it is
    /// what stops it being dropped — the bookkeeping sibling of what
    /// `Bucket::split` does to value. The part is floored, so the
    /// remainder absorbs the truncated subunit: name the side that should
    /// absorb it second.
    ///
    /// # Panics
    ///
    /// Where `share` exceeds one, which would make the remainder
    /// negative and denominates nothing.
    #[must_use]
    pub fn divide(self, share: Ratio) -> (Self, Self) {
        let part = self.scale(share, Rounding::Down);
        let rest = self
            .try_sub(part)
            .expect("a partition by a share of at most one");
        (part, rest)
    }

    /// This quantity scaled by `share`.
    ///
    /// For value a body computes *about* rather than divides: a quote, a
    /// floor, a slippage limit, a fee charged against a figure rather
    /// than taken out of one. Where the input is a total the body holds,
    /// [`Quantity::divide`] is the operation that conserves.
    ///
    /// One rounding, at full precision: the numerator multiplies before
    /// the denominator divides, and the product is held whole in between.
    ///
    /// # Panics
    ///
    /// Where the result leaves the amount width.
    #[must_use]
    pub fn scale(self, share: Ratio, rounding: Rounding) -> Self {
        Self(arith::mul_div(Wide::from_u128(self.0), share.num, share.den, rounding).to_u128())
    }

    /// Whether this quantity over `other` is greater than `share`.
    ///
    /// Total, which is the whole point. Materializing the fraction first
    /// refuses a zero `other` — and a position owing something against
    /// nothing posted is the most exceeded a threshold ever gets, not a
    /// question with no answer. The comparison cross-multiplies at a
    /// width the products fit, so neither side is rounded on the way.
    #[must_use]
    pub fn exceeds(self, other: Self, share: Ratio) -> bool {
        // Nothing to divide by: anything at all is over any share of it,
        // and nothing over nothing is not.
        Ratio::of(self.0, other.0).map_or_else(
            |_| !self.is_zero(),
            |ratio| ratio.cmp_with(share) == Ordering::Greater,
        )
    }

    /// This quantity converted through `rate` into the resource the
    /// rate's numerator names.
    ///
    /// # Panics
    ///
    /// Where the result leaves the amount width.
    #[must_use]
    pub fn convert<A, B>(self, rate: Rate<A, B>, rounding: Rounding) -> Self {
        self.scale(rate.ratio, rounding)
    }
}

impl core::ops::Add for Quantity {
    type Output = Self;

    /// # Panics
    ///
    /// Past the amount width, which is a defect: nothing in a conserved
    /// ledger sums past what the ledger can hold.
    fn add(self, other: Self) -> Self {
        Self(
            self.0
                .checked_add(other.0)
                .expect("a total within the amount width"),
        )
    }
}

impl core::ops::Sub for Quantity {
    type Output = Self;

    /// # Panics
    ///
    /// Below zero. [`Quantity::try_sub`] is the spelling for a difference
    /// a body expects might not exist.
    fn sub(self, other: Self) -> Self {
        Self(
            self.0
                .checked_sub(other.0)
                .expect("a difference at or above zero"),
        )
    }
}

impl core::ops::AddAssign for Quantity {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl core::ops::SubAssign for Quantity {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

/// An exact unevaluated fraction, dimensionless.
///
/// Not fixed-point, and that is the point: evaluating `dx / (x + dx)` to
/// a scale throws away the remainder before [`Quantity::scale`] can use
/// it, where holding the two terms lets the whole thing fuse into one
/// multiplication and one division with the product held whole between
/// them.
///
/// Never stored. A stored exact fraction is a denominator that grows
/// without bound across updates; what outlives a transaction is a
/// [`UnitFixed`] or the quantized rate the design notes call `Fixed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ratio {
    num: Wide,
    den: Wide,
}

impl Ratio {
    /// One.
    pub const ONE: Self = Self {
        num: Wide::ONE,
        den: Wide::ONE,
    };

    /// Nothing.
    pub const ZERO: Self = Self {
        num: Wide::ZERO,
        den: Wide::ONE,
    };

    /// `num / den`.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] on a zero denominator.
    pub const fn of(num: u128, den: u128) -> Result<Self, NumError> {
        if den == 0 {
            return Err(NumError::ZeroDenominator);
        }
        Ok(Self {
            num: Wide::from_u128(num),
            den: Wide::from_u128(den),
        })
    }

    /// `bps` basis points.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past ten thousand, which is one.
    pub const fn bps(bps: u16) -> Result<Self, NumError> {
        if bps > 10_000 {
            return Err(NumError::OutOfRange);
        }
        Self::of(bps as u128, 10_000)
    }

    /// `percent` per hundred.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past a hundred.
    pub const fn percent(percent: u8) -> Result<Self, NumError> {
        if percent > 100 {
            return Err(NumError::OutOfRange);
        }
        Self::of(percent as u128, 100)
    }

    /// The two terms, for the one operation that carries a fraction
    /// across the boundary rather than applying it.
    #[must_use]
    pub const fn terms(self) -> (Wide, Wide) {
        (self.num, self.den)
    }

    /// Whether the fraction is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.num.is_zero()
    }

    /// The reciprocal: exact, because it is the same two terms swapped.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] on zero, which has no reciprocal.
    pub fn recip(self) -> Result<Self, NumError> {
        if self.num.is_zero() {
            return Err(NumError::ZeroDenominator);
        }
        Ok(Self {
            num: self.den,
            den: self.num,
        })
    }

    /// This fraction times another.
    ///
    /// One crossing. The terms reduce only where the product would not
    /// fit, because two integers drawn from a quantity quotient are
    /// coprime more often than not and reducing every composition would
    /// be paying for the uncommon case.
    ///
    /// # Panics
    ///
    /// Where the product does not fit even reduced, which is composition
    /// deep enough that the accumulating value wanted a quantized
    /// representation several steps earlier.
    #[must_use]
    pub fn compose(self, other: Self) -> Self {
        let (num, den) = arith::fraction_compose(self.num, self.den, other.num, other.den);
        Self { num, den }
    }

    /// This fraction against another, at a width their cross-products
    /// fit.
    ///
    /// A named method rather than [`Ord`], because it is a crossing: two
    /// `u128` terms cross-multiply past `u128`, so a guest comparing them
    /// itself would be comparing the wrong numbers.
    #[must_use]
    pub fn cmp_with(self, other: Self) -> Ordering {
        arith::fraction_cmp(self.num, self.den, other.num, other.den)
    }

    /// This fraction quantized as a stored rate under a stated
    /// dimension.
    ///
    /// A dimensionless fraction has no dimension of its own, so storing
    /// one means saying what it is a rate *of* — which is a claim the
    /// author makes rather than one the type carries.
    #[must_use]
    pub fn quantize_as<A, B>(self, rounding: Rounding) -> Fixed<A, B> {
        Fixed::from_scaled(arith::mul_div(
            self.num,
            Wide::from_u128(FIXED_SCALE),
            self.den,
            rounding,
        ))
    }

    /// The smaller of two, by value.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        if self.cmp_with(other) == Ordering::Greater {
            other
        } else {
            self
        }
    }

    /// The larger of two, by value.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if self.cmp_with(other) == Ordering::Less {
            other
        } else {
            self
        }
    }
}

/// An exact unevaluated fraction with a dimension on each term: a
/// quantity of `A` per quantity of `B`.
///
/// The phantoms erase at the ABI boundary and carry no runtime cost. What
/// they buy is that a rate cannot be applied to the wrong side: converting
/// with one takes a `B` and yields an `A`, in that order, always.
pub struct Rate<A, B> {
    ratio: Ratio,
    dimension: PhantomData<(A, B)>,
}

/// The terms, without asking the dimensions to be printable.
///
/// A derived one would want `A: Debug` for a phantom that holds nothing,
/// and a dimension is a marker nobody derives anything on — so deriving
/// here would make a rate unprintable in every contract that has one.
impl<A, B> core::fmt::Debug for Rate<A, B> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.debug_tuple("Rate")
            .field(&self.ratio.num)
            .field(&self.ratio.den)
            .finish()
    }
}

impl<A, B> Clone for Rate<A, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, B> Copy for Rate<A, B> {}

impl<A, B> PartialEq for Rate<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.ratio == other.ratio
    }
}

impl<A, B> Eq for Rate<A, B> {}

impl<A, B> Rate<A, B> {
    /// The dimensionless fraction underneath.
    #[must_use]
    pub const fn ratio(self) -> Ratio {
        self.ratio
    }

    /// This rate through another: `A` per `B` and `B` per `C` give `A`
    /// per `C`.
    ///
    /// The composition the dimensions exist for. A chain of rates through
    /// an intermediate — a price through a numeraire, an index against a
    /// growth factor — is where a mismatched pair is easiest to write and
    /// hardest to see, and taking the product here rather than on the
    /// bare fraction is what makes the middle term cancel by construction
    /// instead of by the author checking.
    ///
    /// Exact, on the same terms [`Ratio::compose`] is: both fractions are
    /// unevaluated and the product is two multiplications.
    ///
    /// A dimensionless factor is a rate from a thing to itself, so
    /// scaling a `Rate<A, B>` composes with a `Rate<B, B>` and the answer
    /// keeps the dimensions it went in with.
    #[must_use]
    pub fn compose<C>(self, other: Rate<B, C>) -> Rate<A, C> {
        Rate {
            ratio: self.ratio.compose(other.ratio),
            dimension: PhantomData,
        }
    }

    /// `count` of `A` for every one of `B`.
    ///
    /// Total, where [`Quantity::per`] has a denominator that could be
    /// nothing: the denominator here is one. What a body reaches for
    /// where a number *is* a rate against a unit — ticks per base unit,
    /// a reward per share — rather than the quotient of two amounts it
    /// happens to hold.
    #[must_use]
    pub const fn per_unit(count: u128) -> Self {
        Self {
            ratio: Ratio {
                num: Wide::from_u128(count),
                den: Wide::ONE,
            },
            dimension: PhantomData,
        }
    }

    /// The rate the other way round: exact, because it is the same two
    /// terms swapped.
    ///
    /// What stops an author inverting a quantized rate and multiplying
    /// back, which does not round-trip. Here the inversion happens on the
    /// exact fraction, where it is free.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] on a zero rate.
    pub fn recip(self) -> Result<Rate<B, A>, NumError> {
        Ok(Rate {
            ratio: self.ratio.recip()?,
            dimension: PhantomData,
        })
    }
}

/// A stored rate: a quantity of `A` per quantity of `B`, quantized.
///
/// The storage half of the rate story, and the only numeric object here
/// that outlives a transaction. An oracle reading, a redemption index, a
/// share price, a funding rate and a reward-per-share accumulator are one
/// object — a rate that has to persist — so they are one type.
///
/// # Why 256 bits at `10^36`
///
/// Because a `Fixed` is a rate between *subunits*, the two resources'
/// decimal offsets span `1e-18` to `1e18` before any market price enters,
/// so the useful part of the range is the bottom. `u128` at `10^18` is
/// not merely tight — it is the wrong end. Rescaling moves the floor
/// instead of the ceiling: the range here is `1e-36` to roughly `1.16e41`
/// with significance holding to about `1e-30`, which needs a whole-unit
/// price under `1e-12` against an eighteen-decimal spread to reach.
///
/// A scale-free representation — a normalized fraction, or a mantissa and
/// an exponent — holds its digits wherever the value sits, and is
/// rejected for two reasons that bind harder. Addition at one scale is
/// **exact**, and a cumulative index is a thing you add to a billion
/// times; every scale-free form re-rounds on every addition. And a
/// fixed-point cell is canonically encoded by construction, where a
/// fraction needs reduction and a mantissa needs normalization before two
/// equal values are one state root.
///
/// # Nothing lossy happens here
///
/// `Fixed` has no arithmetic of its own beyond exact addition. It
/// converts to a [`Rate`] for free — a `Fixed` *is* the fraction
/// `scaled / 10^36` — and every lossy operation happens there, at full
/// precision, quantizing once at the end where the author writes a
/// [`Rounding`]. That is what removes the bug where a fixed-point rate is
/// inverted and multiplied back: the reciprocal is taken on the exact
/// fraction, where it is free and lossless.
pub struct Fixed<A, B> {
    scaled: Wide,
    dimension: PhantomData<(A, B)>,
}

/// The scaled integer, without asking the dimensions to be printable.
impl<A, B> core::fmt::Debug for Fixed<A, B> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.debug_tuple("Fixed").field(&self.scaled).finish()
    }
}

impl<A, B> Clone for Fixed<A, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, B> Copy for Fixed<A, B> {}

impl<A, B> PartialEq for Fixed<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.scaled == other.scaled
    }
}

impl<A, B> Eq for Fixed<A, B> {}

impl<A, B> PartialOrd for Fixed<A, B> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A, B> Ord for Fixed<A, B> {
    /// Cheap: two values at one scale compare as their scaled integers,
    /// where two fractions would need a cross-multiplication.
    fn cmp(&self, other: &Self) -> Ordering {
        self.scaled.cmp(&other.scaled)
    }
}

impl<A, B> Default for Fixed<A, B> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<A, B> Fixed<A, B> {
    /// Nothing.
    pub const ZERO: Self = Self {
        scaled: Wide::ZERO,
        dimension: PhantomData,
    };

    /// One of `A` per one of `B`.
    pub const ONE: Self = Self {
        scaled: Wide::from_u128(FIXED_SCALE),
        dimension: PhantomData,
    };

    /// The value `scaled` names, at [`FIXED_SCALE`].
    #[must_use]
    pub const fn from_scaled(scaled: Wide) -> Self {
        Self {
            scaled,
            dimension: PhantomData,
        }
    }

    /// The scaled integer this holds.
    #[must_use]
    pub const fn scaled(self) -> Wide {
        self.scaled
    }

    /// The scaled integer as its canonical little-endian bytes.
    ///
    /// What a configuration slot holds and what crosses to a guest, on
    /// the same terms an amount's sixteen bytes do.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.scaled.to_le_bytes()
    }

    /// The rate those bytes name.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self::from_scaled(Wide::from_le_bytes(bytes))
    }

    /// Whether the rate is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.scaled.is_zero()
    }

    /// This rate as an exact fraction: `scaled / 10^36`.
    ///
    /// Free and lossless, which is what makes every operation on a stored
    /// rate an operation on a transient one.
    #[must_use]
    pub const fn rate(self) -> Rate<A, B> {
        Rate {
            ratio: Ratio {
                num: self.scaled,
                den: Wide::from_u128(FIXED_SCALE),
            },
            dimension: PhantomData,
        }
    }

    /// The reciprocal, as an exact fraction: `10^36 / scaled`.
    ///
    /// # Errors
    ///
    /// [`NumError::ZeroDenominator`] on a zero rate.
    pub fn recip_rate(self) -> Result<Rate<B, A>, NumError> {
        self.rate().recip()
    }

    /// This rate raised to `exp`, at the scale.
    ///
    /// What per-period compounding needs. The rounding applies to each
    /// multiplication rather than to the result, which is the most a
    /// fixed intermediate width allows.
    #[must_use]
    pub fn pow_int(self, exp: u32, rounding: Rounding) -> Self {
        Self::from_scaled(arith::fixed_pow(self.scaled, exp, rounding))
    }
}

impl<A, B> core::ops::Add for Fixed<A, B> {
    type Output = Self;

    /// Exact, and an operator for the same reason a quantity's is: at one
    /// scale there is no width subtlety and no rounding question, which
    /// is the whole argument for storing at a scale rather than as a
    /// fraction.
    ///
    /// # Panics
    ///
    /// Past the width, which for an accumulator means the increments were
    /// computed against a denominator far smaller than the contract
    /// intends — a minimum stake is what bounds it.
    fn add(self, other: Self) -> Self {
        Self::from_scaled(
            self.scaled
                .checked_add(other.scaled)
                .expect("a stored rate within the width"),
        )
    }
}

impl<A, B> core::ops::Sub for Fixed<A, B> {
    type Output = Self;

    /// The shape every reward accumulator settles through: what a holder
    /// is owed is the index now less the index when they last settled.
    ///
    /// # Panics
    ///
    /// Below zero, which for a monotone accumulator is a defect.
    fn sub(self, other: Self) -> Self {
        Self::from_scaled(
            self.scaled
                .checked_sub(other.scaled)
                .expect("a monotone accumulator"),
        )
    }
}

impl<A, B> core::ops::AddAssign for Fixed<A, B> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

/// Which way a signed value points.
///
/// Zero is positive, because a sign has to be one of the two and nothing
/// downstream can tell: what a body does with a magnitude of nothing is
/// the same either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    /// At or above zero.
    Positive,
    /// Below zero.
    Negative,
}

/// A stored rate that may point either way: a quantity of `A` per
/// quantity of `B`, signed.
///
/// What [`Fixed`] is for a rate that cannot fall below nothing, this is
/// for one that can — an oracle-posted basis, a negative interest rate, a
/// rebase that gives back. A separate type rather than a sign on `Fixed`,
/// because the rates that are non-negative by nature are most of them and
/// should pay neither a bit of range nor a branch.
///
/// # Two's complement, in the same thirty-two bytes
///
/// Every thirty-two byte string is exactly one value of this type, so a
/// stored one is canonically encoded by construction and there is no
/// negative zero to normalize away. A magnitude beside a sign flag would
/// need both — a rule that zero is never negative, and a check at
/// [`Cellular::from_cell`] that a stored pair obeys it — and a state root
/// is the wrong place to hold an invariant something has to remember.
///
/// The range halves, to roughly `±5.8e40` at the scale. That is the
/// harmless direction: a rate between subunits lives at the bottom of the
/// range, which is where `Fixed`'s own note says the useful part is.
///
/// [`Cellular::from_cell`]: crate::state::Cellular::from_cell
///
/// # Nothing lossy happens here either
///
/// Addition, subtraction, negation and comparison are exact. There is
/// deliberately **no** `convert`: `Rounding::Down` against a value that
/// may be negative is two different operations — toward negative
/// infinity, or toward zero — and answering that silently is the one
/// thing this vocabulary refuses everywhere else.
///
/// So applying one goes through [`SignedFixed::split`], which hands back
/// a magnitude and the way it points. The body names the rounding for the
/// direction it is in, which is what a contract wants anyway: what a
/// position pays and what it is paid round opposite ways, and a single
/// figure cannot say so.
pub struct SignedFixed<A, B> {
    bits: Wide,
    dimension: PhantomData<(A, B)>,
}

/// The magnitude and the way it points, which is what a reader wants —
/// two's complement bits read as a number nobody recognises.
impl<A, B> core::fmt::Debug for SignedFixed<A, B> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (magnitude, sign) = self.split();
        out.debug_tuple("SignedFixed")
            .field(&sign)
            .field(&magnitude.scaled())
            .finish()
    }
}

impl<A, B> Clone for SignedFixed<A, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, B> Copy for SignedFixed<A, B> {}

impl<A, B> PartialEq for SignedFixed<A, B> {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
    }
}

impl<A, B> Eq for SignedFixed<A, B> {}

impl<A, B> PartialOrd for SignedFixed<A, B> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A, B> Ord for SignedFixed<A, B> {
    /// The sign decides where the signs differ, and the bits decide
    /// where they agree — which holds for two negatives too, because
    /// two's complement orders them the same way it orders two
    /// positives.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.bits.top_bit(), other.bits.top_bit()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.bits.cmp(&other.bits),
        }
    }
}

impl<A, B> Default for SignedFixed<A, B> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<A, B> SignedFixed<A, B> {
    /// Nothing.
    pub const ZERO: Self = Self {
        bits: Wide::ZERO,
        dimension: PhantomData,
    };

    /// One of `A` per one of `B`.
    pub const ONE: Self = Self {
        bits: Wide::from_u128(FIXED_SCALE),
        dimension: PhantomData,
    };

    /// The two's complement bits this holds.
    #[must_use]
    pub const fn bits(self) -> Wide {
        self.bits
    }

    /// The value these bits name.
    ///
    /// Total: every thirty-two byte string is a value, which is what
    /// makes a stored one need no check on the way in.
    #[must_use]
    pub const fn from_bits(bits: Wide) -> Self {
        Self {
            bits,
            dimension: PhantomData,
        }
    }

    /// Whether the value is nothing.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.bits.is_zero()
    }

    /// Whether the value is below nothing.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.bits.top_bit()
    }

    /// The magnitude, and the way it points.
    ///
    /// The only route from a signed rate to an unsigned one, and the seam
    /// where a body says which rounding it means. The magnitude is a
    /// [`Fixed`] because that is what it is — a rate that cannot be
    /// negative — and it may exceed what a `SignedFixed` holds, at the one
    /// value whose negation does not fit.
    #[must_use]
    pub const fn split(self) -> (Fixed<A, B>, Sign) {
        if self.is_negative() {
            (Fixed::from_scaled(self.bits.wrapping_neg()), Sign::Negative)
        } else {
            (Fixed::from_scaled(self.bits), Sign::Positive)
        }
    }

    /// The two's complement integer as its canonical little-endian
    /// bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.bits.to_le_bytes()
    }

    /// The value those bytes name.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self::from_bits(Wide::from_le_bytes(bytes))
    }

    /// The same value the other way round.
    ///
    /// # Panics
    ///
    /// At the one value with no opposite: the bottom of the range, whose
    /// magnitude is one past the top.
    #[must_use]
    pub fn negate(self) -> Self {
        let negated = self.bits.wrapping_neg();
        assert!(
            !(self.is_negative() && negated.top_bit()),
            "a signed rate at the bottom of its range has no opposite"
        );
        Self::from_bits(negated)
    }
}

impl<A, B> Fixed<A, B> {
    /// This magnitude, pointing the way `sign` says.
    ///
    /// The inverse of [`SignedFixed::split`], and the only route from an
    /// unsigned rate to a signed one.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past what the signed range holds, which
    /// is half what an unsigned one does.
    pub fn signed(self, sign: Sign) -> Result<SignedFixed<A, B>, NumError> {
        let bits = match sign {
            Sign::Positive => self.scaled(),
            Sign::Negative => self.scaled().wrapping_neg(),
        };
        // A magnitude fits where negating it lands on the sign it was
        // given. Nothing else does, and zero passes either way because
        // its negation is itself.
        let fits = self.scaled().is_zero()
            || match sign {
                Sign::Positive => !bits.top_bit(),
                Sign::Negative => bits.top_bit(),
            };
        if fits {
            Ok(SignedFixed::from_bits(bits))
        } else {
            Err(NumError::OutOfRange)
        }
    }
}

impl<A, B> core::ops::Add for SignedFixed<A, B> {
    type Output = Self;

    /// Exact, and an operator for the same reason an unsigned rate's is.
    ///
    /// # Panics
    ///
    /// Past either end of the range. Two values of one sign summing to
    /// the other sign is the whole of what overflow looks like here, and
    /// two of different signs cannot overflow at all.
    fn add(self, other: Self) -> Self {
        let sum = Self::from_bits(self.bits.wrapping_add(other.bits));
        assert!(
            self.is_negative() != other.is_negative() || sum.is_negative() == self.is_negative(),
            "a signed rate within the range"
        );
        sum
    }
}

impl<A, B> core::ops::Sub for SignedFixed<A, B> {
    type Output = Self;

    /// Its own operation rather than the addition of a negation: the one
    /// value with no opposite can still be subtracted, and `-1` less the
    /// bottom of the range is a difference that fits.
    ///
    /// # Panics
    ///
    /// Past either end of the range. Two values of one sign cannot
    /// overflow a difference; two of different signs do exactly when the
    /// answer comes back wearing the subtrahend's.
    fn sub(self, other: Self) -> Self {
        let difference = Self::from_bits(self.bits.wrapping_add(other.bits.wrapping_neg()));
        assert!(
            self.is_negative() == other.is_negative()
                || difference.is_negative() == self.is_negative(),
            "a signed rate within the range"
        );
        difference
    }
}

impl<A, B> core::ops::AddAssign for SignedFixed<A, B> {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<A, B> core::ops::SubAssign for SignedFixed<A, B> {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<A, B> Rate<A, B> {
    /// This exact rate, quantized for storage.
    ///
    /// The one lossy step between a computed rate and a stored one, and
    /// it names its direction.
    #[must_use]
    pub fn quantize(self, rounding: Rounding) -> Fixed<A, B> {
        Fixed::from_scaled(arith::mul_div(
            self.ratio.num,
            Wide::from_u128(FIXED_SCALE),
            self.ratio.den,
            rounding,
        ))
    }
}

/// A rate encodes as the thirty-two bytes it is, wherever it travels.
///
/// A cell already holds one this way, so a record holding one holds the
/// same bytes in the same order — which is what lets a rate be a field of
/// a stored record rather than only a leaf of its own. Fixed width, so a
/// record carrying one still has a minimum length nothing has to walk to
/// find.
macro_rules! rate_hbor {
    ($ty:ident, $bytes:ident, $from:ident) => {
        impl<A, B> HborWidth for $ty<A, B> {
            const MIN_ENCODED_LEN: usize = 32;
        }

        impl<A, B> HborEncode for $ty<A, B> {
            fn encode<S: hyperscale_hbor::Sink>(
                &self,
                encoder: &mut hyperscale_hbor::Encoder<S>,
            ) -> Result<(), hyperscale_hbor::EncodeError> {
                encoder.write_fixed(&self.$bytes());
                Ok(())
            }
        }

        impl<A, B> HborDecode for $ty<A, B> {
            fn decode(
                decoder: &mut hyperscale_hbor::Decoder<'_>,
            ) -> Result<Self, hyperscale_hbor::DecodeError> {
                Ok(Self::$from(decoder.read_array()?))
            }
        }

        impl<A, B> HborShape for $ty<A, B> {
            fn shape(_: &mut hyperscale_hbor::ShapeRegistry) -> hyperscale_hbor::TypeShape {
                hyperscale_hbor::TypeShape::ByteArray(32)
            }
        }
    };
}

rate_hbor!(Fixed, to_le_bytes, from_le_bytes);
rate_hbor!(SignedFixed, to_le_bytes, from_le_bytes);

/// A bounded configuration number: nothing to one, at `10^18`.
///
/// The type a stored fee, ratio or factor takes. Its range is checked
/// where the value *enters state*, not where the arithmetic later reads
/// it: a pool created with a fee above one is a pool that should not
/// exist, and refusing the swap instead leaves it created, bricked, and
/// holding funds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct UnitFixed(u128);

impl UnitFixed {
    /// Nothing.
    pub const ZERO: Self = Self(0);
    /// One.
    pub const ONE: Self = Self(UNIT_SCALE);

    /// The value `scaled` names, at `10^18`.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past one.
    pub const fn new(scaled: u128) -> Result<Self, NumError> {
        if scaled > UNIT_SCALE {
            return Err(NumError::OutOfRange);
        }
        Ok(Self(scaled))
    }

    /// `bps` basis points.
    ///
    /// Still how an author writes a fee. One bounded type covers both the
    /// literal thirty basis points and the loan-to-value that wants finer
    /// resolution than a basis point can spell.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past ten thousand.
    pub const fn bps(bps: u16) -> Result<Self, NumError> {
        if bps > 10_000 {
            return Err(NumError::OutOfRange);
        }
        Ok(Self(bps as u128 * (UNIT_SCALE / 10_000)))
    }

    /// `percent` per hundred.
    ///
    /// # Errors
    ///
    /// [`NumError::OutOfRange`] past a hundred.
    pub const fn percent(percent: u8) -> Result<Self, NumError> {
        if percent > 100 {
            return Err(NumError::OutOfRange);
        }
        Ok(Self(percent as u128 * (UNIT_SCALE / 100)))
    }

    /// The scaled value this carries.
    #[must_use]
    pub const fn scaled(self) -> u128 {
        self.0
    }

    /// This value as an exact fraction.
    ///
    /// Infallible: the denominator is the scale, which is not zero, and
    /// the range was checked when the value was made.
    #[must_use]
    pub const fn ratio(self) -> Ratio {
        Ratio {
            num: Wide::from_u128(self.0),
            den: Wide::from_u128(UNIT_SCALE),
        }
    }

    /// One minus this value.
    ///
    /// Infallible by construction, and the reason the type is bounded:
    /// the fee complement an author would otherwise write as
    /// `10_000 - fee_bps` — an unchecked subtraction on an unvalidated
    /// field, which is where this vocabulary started.
    #[must_use]
    pub const fn complement(self) -> Self {
        Self(UNIT_SCALE - self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FIXED_SCALE, Fixed, NumError, Quantity, Rate, Ratio, Rounding, Sign, SignedFixed,
        UnitFixed, Wide, arith,
    };

    /// A dimension, for the rates that need two of them.
    struct Up;
    /// The other one.
    struct Down;

    fn signed(scaled: u128, sign: Sign) -> SignedFixed<Up, Down> {
        Fixed::from_scaled(Wide::from_u128(scaled))
            .signed(sign)
            .expect("well inside the range")
    }

    fn q(n: u128) -> Quantity {
        Quantity::from_subunits(n)
    }

    #[test]
    fn a_swap_curve_holds_its_product_whole() {
        // The expression the pool could not write: reserves whose product
        // leaves the amount width, re-associated so the rate is the thing
        // bounded below one.
        let (x, y) = (q(u128::MAX / 2), q(u128::MAX / 2));
        let dx = q(u128::MAX / 4);
        let rate = dx.ratio_to(x + dx).expect("a funded pool");
        let out = y.scale(rate, Rounding::Down);
        assert!(out < y, "a swap cannot drain the side it buys");
        assert!(!out.is_zero());
    }

    #[test]
    fn an_empty_pool_declines_rather_than_trapping() {
        assert_eq!(
            q(5).ratio_to(Quantity::ZERO),
            Err(NumError::ZeroDenominator)
        );
    }

    #[test]
    fn a_partition_returns_what_it_did_not_take() {
        let total = q(1_000);
        let (part, rest) = total.divide(Ratio::bps(3_000).expect("in range"));
        assert_eq!(part, q(300));
        assert_eq!(rest, q(700));
        assert_eq!(part + rest, total);
    }

    #[test]
    fn a_partition_leaves_the_dust_with_the_remainder() {
        let total = q(10);
        let (part, rest) = total.divide(Ratio::of(1, 3).expect("non-zero"));
        assert_eq!(part, q(3));
        assert_eq!(rest, q(7));
        assert_eq!(
            part + rest,
            total,
            "a partition conserves whatever it rounds"
        );
    }

    #[test]
    fn scaling_states_its_direction() {
        let third = Ratio::of(1, 3).expect("non-zero");
        assert_eq!(q(10).scale(third, Rounding::Down), q(3));
        assert_eq!(q(10).scale(third, Rounding::Up), q(4));
    }

    #[test]
    fn a_fee_complement_needs_no_subtraction() {
        let fee = UnitFixed::bps(30).expect("in range");
        let paid = q(10_000);
        let (traded, taken) = paid.divide(fee.complement().ratio());
        assert_eq!(taken, q(30));
        assert_eq!(traded + taken, paid);
    }

    #[test]
    fn a_fee_out_of_range_cannot_be_constructed() {
        assert_eq!(UnitFixed::bps(20_000), Err(NumError::OutOfRange));
        assert_eq!(
            UnitFixed::new(super::UNIT_SCALE + 1),
            Err(NumError::OutOfRange)
        );
        assert_eq!(
            UnitFixed::bps(10_000).expect("one is in range"),
            UnitFixed::ONE
        );
    }

    #[test]
    fn composition_carries_the_cross_rate() {
        // Two rates at realistic balance scale, composed through a
        // numeraire: the depth `u128` terms could not carry.
        let a = q(10_u128.pow(24));
        let b = q(3 * 10_u128.pow(24));
        let c = q(7 * 10_u128.pow(24));
        let composed = a
            .ratio_to(b)
            .expect("funded")
            .compose(b.ratio_to(c).expect("funded"));
        assert_eq!(
            composed.cmp_with(a.ratio_to(c).expect("funded")),
            core::cmp::Ordering::Equal
        );
    }

    #[test]
    fn rates_compare_past_the_width_their_terms_fit() {
        let wide = q(u128::MAX);
        let one = wide.ratio_to(wide).expect("funded");
        assert_eq!(one.cmp_with(Ratio::ONE), core::cmp::Ordering::Equal);
        let smaller = q(u128::MAX - 1).ratio_to(wide).expect("funded");
        assert_eq!(smaller.cmp_with(one), core::cmp::Ordering::Less);
    }

    #[test]
    fn a_liquidity_mint_takes_the_root_of_a_product_that_does_not_fit() {
        let x = q(4 << 100);
        let y = q(1 << 100);
        assert_eq!(x.geometric_mean(y), q(2 << 100));
    }

    #[test]
    fn the_minimum_of_two_rates_is_what_a_deposit_mints_on() {
        let dx_over_x = Ratio::of(1, 4).expect("non-zero");
        let dy_over_y = Ratio::of(1, 5).expect("non-zero");
        assert_eq!(dx_over_x.min(dy_over_y), dy_over_y);
        assert_eq!(dx_over_x.max(dy_over_y), dx_over_x);
    }

    #[test]
    fn insufficient_funds_is_a_condition_rather_than_a_defect() {
        assert_eq!(q(3).try_sub(q(5)), None);
        assert_eq!(q(3).saturating_sub(q(5)), Quantity::ZERO);
        assert_eq!(q(5).try_sub(q(3)), Some(q(2)));
    }

    #[test]
    fn granularity_is_the_contracts_to_enforce() {
        let step = q(100);
        assert!(q(300).is_multiple_of(step));
        assert!(!q(350).is_multiple_of(step));
        assert_eq!(q(350).round_to_multiple(step, Rounding::Down), q(300));
        assert_eq!(q(350).round_to_multiple(step, Rounding::Up), q(400));
        assert_eq!(q(300).round_to_multiple(step, Rounding::Up), q(300));
        assert_eq!(
            q(350).round_to_multiple(Quantity::ZERO, Rounding::Up),
            q(350),
            "no step is no quantization"
        );
    }

    /// A stored rate converts back to the exact fraction it stands for,
    /// which is what makes every operation on one an operation on a
    /// transient fraction.
    #[test]
    fn a_stored_rate_is_the_fraction_it_quantized() {
        let rate: Rate<(), ()> = q(1).per(q(4)).expect("funded");
        let stored = rate.quantize(Rounding::Down);
        assert_eq!(
            stored
                .rate()
                .ratio()
                .cmp_with(Ratio::of(1, 4).expect("non-zero")),
            core::cmp::Ordering::Equal
        );
    }

    /// The bug this representation removes: a fixed-point rate inverted
    /// and multiplied back does not round-trip, so the inversion happens
    /// on the exact fraction where it is free.
    #[test]
    fn a_reciprocal_of_a_stored_rate_round_trips() {
        let stored: Fixed<(), ()> = q(1).per(q(3)).expect("funded").quantize(Rounding::Down);
        let there = stored.rate().ratio();
        let back = stored
            .recip_rate()
            .expect("non-zero")
            .ratio()
            .recip()
            .expect("non-zero");
        assert_eq!(there.cmp_with(back), core::cmp::Ordering::Equal);
    }

    /// The reason storage is fixed-point rather than scale-free:
    /// addition at one scale is exact, and an index is a thing bodies add
    /// to without bound. The control is the same total accumulated the
    /// way a body would if it materialized each increment as a quantity,
    /// which drifts by a subunit per operation in either direction.
    #[test]
    fn an_index_accumulates_without_drift() {
        let increment: Fixed<(), ()> = Ratio::of(1, 3)
            .expect("non-zero")
            .quantize_as::<(), ()>(Rounding::Down);
        let mut index = Fixed::<(), ()>::ZERO;
        for _ in 0..100_000 {
            index += increment;
        }
        // Exact: a hundred thousand additions of one quantized value is
        // that value's scaled integer times a hundred thousand, with no
        // term rounded on the way.
        let expected = arith::mul_div(
            increment.scaled(),
            Wide::from_u128(100_000),
            Wide::ONE,
            Rounding::Down,
        );
        assert_eq!(
            index.scaled(),
            expected,
            "an index drifted while accumulating"
        );

        // The control: materialize each increment against a pool and sum
        // the quantities, which is the shape that loses a subunit an
        // operation. It falls short, and by a lot more than one.
        let mut materialized = Quantity::ZERO;
        for _ in 0..100_000 {
            materialized += q(1_000).scale(Ratio::of(1, 3).expect("non-zero"), Rounding::Down);
        }
        let exact = q(1_000 * 100_000).scale(Ratio::of(1, 3).expect("non-zero"), Rounding::Down);
        assert!(
            materialized < exact,
            "the materialized control is meant to drift, and did not"
        );
    }

    #[test]
    fn stored_rates_order_by_their_scaled_value() {
        let third: Fixed<(), ()> = Ratio::of(1, 3)
            .expect("non-zero")
            .quantize_as(Rounding::Down);
        let half: Fixed<(), ()> = Ratio::of(1, 2)
            .expect("non-zero")
            .quantize_as(Rounding::Down);
        assert!(third < half);
        assert_eq!(
            Fixed::<(), ()>::ONE.rate().ratio().cmp_with(Ratio::ONE),
            core::cmp::Ordering::Equal
        );
    }

    #[test]
    fn compounding_a_stored_rate_squares_it() {
        let one_and_a_half: Fixed<(), ()> = Ratio::of(3, 2)
            .expect("non-zero")
            .quantize_as(Rounding::Down);
        let squared = one_and_a_half.pow_int(2, Rounding::Down);
        let expected: Fixed<(), ()> = Ratio::of(9, 4)
            .expect("non-zero")
            .quantize_as(Rounding::Down);
        assert_eq!(squared, expected);
        assert_eq!(one_and_a_half.pow_int(0, Rounding::Down), Fixed::ONE);
        assert_eq!(one_and_a_half.pow_int(1, Rounding::Down), one_and_a_half);
    }

    #[test]
    fn a_reciprocal_round_trips_because_it_is_exact() {
        let rate = q(3).ratio_to(q(7)).expect("funded");
        let back = rate.recip().expect("non-zero").recip().expect("non-zero");
        assert_eq!(rate.cmp_with(back), core::cmp::Ordering::Equal);
    }

    /// Every thirty-two byte string is one value and every value is one
    /// string, which is what a state root needs of a leaf.
    ///
    /// The pair a magnitude and a flag would spell two ways is the whole
    /// reason for the representation: there is no negative zero to
    /// normalize, so nothing has to remember to.
    #[test]
    fn a_signed_rate_has_one_spelling_for_every_value() {
        assert_eq!(signed(0, Sign::Positive), signed(0, Sign::Negative));
        assert_eq!(signed(0, Sign::Negative), SignedFixed::ZERO);
        assert!(!signed(0, Sign::Negative).is_negative(), "no negative zero");

        let there = signed(7, Sign::Negative);
        let back = SignedFixed::<Up, Down>::from_le_bytes(there.to_le_bytes());
        assert_eq!(there, back);
    }

    /// The magnitude comes back with the way it points, and goes back in
    /// the same way — which is the only route either direction.
    #[test]
    fn a_signed_rate_splits_into_a_magnitude_and_a_way_it_points() {
        for sign in [Sign::Positive, Sign::Negative] {
            let (magnitude, read) = signed(FIXED_SCALE, sign).split();
            assert_eq!(magnitude, Fixed::ONE);
            assert_eq!(read, sign);
            assert_eq!(
                magnitude.signed(sign).expect("in range"),
                signed(FIXED_SCALE, sign)
            );
        }
        // Zero points the one way a sign can, whichever way it was made.
        assert_eq!(SignedFixed::<Up, Down>::ZERO.split().1, Sign::Positive);
    }

    /// A negative sorts below a positive, and two of one sign sort by
    /// what they are — which two's complement gives without a branch per
    /// comparison.
    #[test]
    fn signed_rates_order_by_value_and_not_by_bits() {
        let ordered = [
            signed(FIXED_SCALE, Sign::Negative),
            signed(1, Sign::Negative),
            SignedFixed::ZERO,
            signed(1, Sign::Positive),
            signed(FIXED_SCALE, Sign::Positive),
        ];
        for pair in ordered.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} is not below {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    /// Addition and subtraction are exact and cross zero without a
    /// special case.
    #[test]
    fn a_signed_rate_crosses_zero_arithmetically() {
        let up = signed(3, Sign::Positive);
        let down = signed(5, Sign::Negative);
        assert_eq!(up + down, signed(2, Sign::Negative));
        assert_eq!(up - down, signed(8, Sign::Positive));
        assert_eq!(down - up, signed(8, Sign::Negative));
        assert_eq!(up + up.negate(), SignedFixed::ZERO);
    }

    /// The bottom of the range has no opposite, and subtracting it is
    /// still a difference — which is why subtraction is its own
    /// operation rather than the addition of a negation.
    #[test]
    fn the_bottom_of_the_range_has_no_opposite_and_can_still_be_subtracted() {
        let bottom = SignedFixed::<Up, Down>::from_bits(Wide::from_limbs([0, 0, 0, 1 << 63]));
        assert!(bottom.is_negative());
        let minus_one = SignedFixed::<Up, Down>::from_bits(Wide::from_limbs([u64::MAX; 4]));

        let difference = minus_one - bottom;
        assert!(!difference.is_negative());
        assert_eq!(
            difference.split().0.scaled(),
            bottom
                .split()
                .0
                .scaled()
                .checked_sub(Wide::ONE)
                .expect("the magnitude is not zero")
        );

        assert!(
            std::panic::catch_unwind(|| bottom.negate()).is_err(),
            "the bottom of the range negates to itself, which is not its opposite"
        );
    }

    /// A magnitude past half the width is not a signed value, and saying
    /// so is a refusal rather than a wrap.
    #[test]
    fn a_magnitude_past_the_signed_range_is_refused() {
        let half = Fixed::<Up, Down>::from_scaled(Wide::from_limbs([0, 0, 0, 1 << 63]));
        assert_eq!(half.signed(Sign::Positive), Err(NumError::OutOfRange));
        // Its negation is exactly the bottom of the range, so that one
        // fits — the asymmetry two's complement has and the reason the
        // range is stated as one value wider below than above.
        assert!(half.signed(Sign::Negative).is_ok());
    }
}
