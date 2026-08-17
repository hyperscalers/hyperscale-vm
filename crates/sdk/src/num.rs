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

// The arithmetic, from whichever side of the boundary this build is on.
// One alias rather than a branch per call site: the two modules expose
// the same five functions under the same names, because they stand for
// one implementation reached two ways.
#[cfg(target_arch = "wasm32")]
use crate::guest as arith;
#[cfg(not(target_arch = "wasm32"))]
use crate::host as arith;

/// The scale a stored rate is quantized to: `10^36`.
pub const FIXED_SCALE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// The largest value a [`UnitFixed`] may hold: one, at its own scale.
pub const UNIT_SCALE: u128 = 1_000_000_000_000_000_000;

/// Which way a lossy operation resolves a non-zero remainder.
///
/// Required wherever one happens. §"Dust" in the design notes states
/// which direction is correct where; the type only insists that a body
/// say which it took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    /// Toward zero.
    Down,
    /// Away from zero.
    Up,
}

/// Why a construction refused its inputs.
///
/// Constructors return; applications trap. A zero denominator or an
/// out-of-range configuration value is a state condition an author can
/// decline on, and a body that meets one knows what it means. A quotient
/// past the width on well-formed inputs is a defect, and there is nothing
/// for a caller to do with it but stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MathError {
    /// A fraction with a zero denominator: an empty pool, a rate against
    /// nothing.
    ZeroDenominator,
    /// A configuration value outside the range its type admits.
    OutOfRange,
}

/// A 256-bit unsigned value, as four limbs, least significant first.
///
/// Storage only. Every operation on one is the host's, so this carries no
/// arithmetic of its own — it is the shape a fraction's terms travel and
/// live in, wide enough that composing two quantity-derived rates does
/// not overflow at the depth a cross rate reaches.
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

    /// The value as a `u128`.
    ///
    /// # Panics
    ///
    /// Past the amount width. A quantity is `u128` subunits and a
    /// fraction's terms never leave the arithmetic, so a wider value has
    /// nowhere in the vocabulary to go.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
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
    /// Nothing on-chain consults a resource's divisibility, so a contract
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
    /// [`MathError::ZeroDenominator`] against nothing — an empty pool,
    /// which is a refusal an author can word rather than a trap.
    pub const fn ratio_to(self, other: Self) -> Result<Ratio, MathError> {
        Ratio::of(self.0, other.0)
    }

    /// This quantity over one of another resource, as a rate.
    ///
    /// # Errors
    ///
    /// [`MathError::ZeroDenominator`] against nothing.
    pub const fn per<A, B>(self, other: Self) -> Result<Rate<A, B>, MathError> {
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
    /// [`MathError::ZeroDenominator`] on a zero denominator.
    pub const fn of(num: u128, den: u128) -> Result<Self, MathError> {
        if den == 0 {
            return Err(MathError::ZeroDenominator);
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
    /// [`MathError::OutOfRange`] past ten thousand, which is one.
    pub const fn bps(bps: u16) -> Result<Self, MathError> {
        if bps > 10_000 {
            return Err(MathError::OutOfRange);
        }
        Self::of(bps as u128, 10_000)
    }

    /// `percent` per hundred.
    ///
    /// # Errors
    ///
    /// [`MathError::OutOfRange`] past a hundred.
    pub const fn percent(percent: u8) -> Result<Self, MathError> {
        if percent > 100 {
            return Err(MathError::OutOfRange);
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
    /// [`MathError::ZeroDenominator`] on zero, which has no reciprocal.
    pub fn recip(self) -> Result<Self, MathError> {
        if self.num.is_zero() {
            return Err(MathError::ZeroDenominator);
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
#[derive(Debug)]
pub struct Rate<A, B> {
    ratio: Ratio,
    dimension: PhantomData<(A, B)>,
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

    /// The rate the other way round: exact, because it is the same two
    /// terms swapped.
    ///
    /// What stops an author inverting a quantized rate and multiplying
    /// back, which does not round-trip. Here the inversion happens on the
    /// exact fraction, where it is free.
    ///
    /// # Errors
    ///
    /// [`MathError::ZeroDenominator`] on a zero rate.
    pub fn recip(self) -> Result<Rate<B, A>, MathError> {
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
#[derive(Debug)]
pub struct Fixed<A, B> {
    scaled: Wide,
    dimension: PhantomData<(A, B)>,
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
    /// [`MathError::ZeroDenominator`] on a zero rate.
    pub fn recip_rate(self) -> Result<Rate<B, A>, MathError> {
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
    /// [`MathError::OutOfRange`] past one.
    pub const fn new(scaled: u128) -> Result<Self, MathError> {
        if scaled > UNIT_SCALE {
            return Err(MathError::OutOfRange);
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
    /// [`MathError::OutOfRange`] past ten thousand.
    pub const fn bps(bps: u16) -> Result<Self, MathError> {
        if bps > 10_000 {
            return Err(MathError::OutOfRange);
        }
        Ok(Self(bps as u128 * (UNIT_SCALE / 10_000)))
    }

    /// `percent` per hundred.
    ///
    /// # Errors
    ///
    /// [`MathError::OutOfRange`] past a hundred.
    pub const fn percent(percent: u8) -> Result<Self, MathError> {
        if percent > 100 {
            return Err(MathError::OutOfRange);
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
    use super::{Fixed, MathError, Quantity, Rate, Ratio, Rounding, UnitFixed, Wide, arith};

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
            Err(MathError::ZeroDenominator)
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
        assert_eq!(UnitFixed::bps(20_000), Err(MathError::OutOfRange));
        assert_eq!(
            UnitFixed::new(super::UNIT_SCALE + 1),
            Err(MathError::OutOfRange)
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
}
