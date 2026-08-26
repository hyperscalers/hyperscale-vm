//! Wide integer arithmetic: the semantics behind the `math` interface.
//!
//! Beside the host surface rather than behind it. The kernel's own host
//! trait exists
//! because the kernel's operations reach state, and an engine has to ask
//! something that holds it; these reach nothing. Making them trait methods
//! would put a seam where the whole argument for host provision is that
//! there is one semantics — an embedder could implement the trait and
//! answer differently. Both engines call the functions below directly, so
//! the two runtimes do not agree on wide arithmetic, they share it.
//!
//! Every operation here is a pure function over [`U256`] with a 512-bit
//! intermediate, so a product that would not fit is carried rather than
//! wrapped and the quotient taken from the whole of it. That is the point
//! of the interface: a contract computing `y * dx / (x + dx)` gets one
//! rounding at full precision, where the same expression written as two
//! guest operations rounds twice and overflows on the first.
//!
//! The division is a binary long division — 512 shift-compare-subtract
//! steps, one per bit of the dividend. A limb-wise algorithm is several
//! times faster and considerably harder to be sure of, and this is
//! consensus arithmetic where the two engines have to agree bit for bit.
//! The trip count is fixed by the width rather than by the operands, so
//! there is no input-dependent timing and nothing to calibrate.
//!
//! Rounding is a required argument on every lossy operation, never a
//! default: [`Rounding::Down`] takes the floor and [`Rounding::Up`] adds
//! one wherever the remainder is non-zero.

use core::cmp::Ordering;

use crate::AbortReason;

/// Which way a lossy operation resolves a non-zero remainder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    /// Toward zero.
    Down,
    /// Away from zero.
    Up,
}

/// Why a wide computation rejected its inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MathError {
    /// A zero divisor, or a fraction with a zero denominator.
    #[error("division by zero")]
    DivideByZero,
    /// A result past 256 bits.
    #[error("wide arithmetic overflow")]
    Overflow,
}

impl From<MathError> for AbortReason {
    fn from(error: MathError) -> Self {
        match error {
            MathError::DivideByZero => Self::MathDivideByZero,
            MathError::Overflow => Self::MathOverflow,
        }
    }
}

/// The scale a stored rate is quantized to.
///
/// `10^36`, which is the whole of `u128` short of two digits and leaves a
/// 256-bit value a range of `1e-36` to roughly `1.16e41`. A rate between
/// subunits spans the two resources' decimal offsets before any market
/// price enters it, so the useful part of the range is the bottom.
pub const FIXED_SCALE: U256 = U256::from_u128(1_000_000_000_000_000_000_000_000_000_000_000_000);

/// A 256-bit unsigned integer, as four 64-bit limbs, least significant
/// first.
///
/// The limb order is the wire's, not the comparison's — [`Ord`] is
/// written rather than derived, because a derived one over the array
/// would compare the least significant limb first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct U256([u64; 4]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 4]);
    /// One.
    pub const ONE: Self = Self([1, 0, 0, 0]);
    /// The largest representable value.
    pub const MAX: Self = Self([u64::MAX; 4]);

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

    /// The value these limbs name, least significant first.
    #[must_use]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// The value as a `u128`, where it fits.
    #[must_use]
    pub const fn to_u128(self) -> Option<u128> {
        if self.0[2] == 0 && self.0[3] == 0 {
            Some((self.0[0] as u128) | ((self.0[1] as u128) << 64))
        } else {
            None
        }
    }

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    /// The sum, or `None` past the width.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        let (sum, carry) = add_limbs(self.0, other.0);
        if carry { None } else { Some(Self(sum)) }
    }

    /// The difference, or `None` below zero.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        let (difference, borrow) = sub_limbs(self.0, other.0);
        if borrow { None } else { Some(Self(difference)) }
    }

    /// The full 512-bit product.
    #[must_use]
    pub const fn widening_mul(self, other: Self) -> U512 {
        U512(mul_limbs(self.0, other.0))
    }

    /// The count of trailing zero bits; 256 for zero.
    #[must_use]
    pub const fn trailing_zeros(self) -> u32 {
        let mut i = 0u32;
        while i < 4 {
            let limb = self.0[i as usize];
            if limb != 0 {
                return i * 64 + limb.trailing_zeros();
            }
            i += 1;
        }
        256
    }

    /// The value shifted right by `bits`, which must be under 256.
    #[must_use]
    pub const fn shr(self, bits: u32) -> Self {
        Self(shr_limbs(self.0, bits))
    }
}

impl Ord for U256 {
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

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u128> for U256 {
    fn from(n: u128) -> Self {
        Self::from_u128(n)
    }
}

/// A 512-bit unsigned integer: the width a 256-bit product needs.
///
/// Never crosses the boundary and never reaches a cell. It exists so that
/// `a * b / c` can hold the whole of `a * b` before dividing, which is the
/// entire reason these operations are the host's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct U512([u64; 8]);

impl U512 {
    /// Zero.
    pub const ZERO: Self = Self([0; 8]);

    /// The value `n`, widened.
    #[must_use]
    pub const fn from_u256(n: U256) -> Self {
        let low = n.0;
        Self([low[0], low[1], low[2], low[3], 0, 0, 0, 0])
    }

    /// The low 256 bits, and whether the high half was non-zero.
    #[must_use]
    pub const fn split(self) -> (U256, bool) {
        let limbs = self.0;
        let high = limbs[4] | limbs[5] | limbs[6] | limbs[7];
        (U256([limbs[0], limbs[1], limbs[2], limbs[3]]), high != 0)
    }

    /// The value as a [`U256`], where it fits.
    #[must_use]
    pub const fn narrow(self) -> Option<U256> {
        match self.split() {
            (low, false) => Some(low),
            (_, true) => None,
        }
    }

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0; 8]
    }

    /// The bit at `index`, counting from the least significant.
    #[must_use]
    const fn bit(self, index: u32) -> bool {
        (self.0[(index / 64) as usize] >> (index % 64)) & 1 == 1
    }

    /// The quotient and remainder over a 256-bit divisor.
    ///
    /// Binary long division: one shift-compare-subtract per bit of the
    /// dividend, so the trip count is the width rather than anything the
    /// operands decide. The running remainder stays below the divisor, so
    /// it needs 256 bits plus the bit a shift carries out — which is what
    /// the `wide` flag tracks instead of a third integer width.
    ///
    /// # Panics
    ///
    /// On a zero divisor. Callers range-check first.
    #[must_use]
    fn div_rem(self, divisor: U256) -> (Self, U256) {
        assert!(!divisor.is_zero(), "division by zero");
        let mut quotient = [0u64; 8];
        let mut remainder = U256::ZERO;
        for index in (0..512).rev() {
            // The remainder stays below the divisor, so doubling it can
            // reach 2^256 but no further. The carried bit says so without
            // a third integer width: a value with it set exceeds every
            // 256-bit divisor, and subtracting wraps back into range.
            let carried = remainder.0[3] >> 63 == 1;
            remainder = U256(shl_one(remainder.0));
            if self.bit(index) {
                remainder.0[0] |= 1;
            }
            if carried || remainder >= divisor {
                remainder = U256(sub_limbs(remainder.0, divisor.0).0);
                quotient[(index / 64) as usize] |= 1 << (index % 64);
            }
        }
        (Self(quotient), remainder)
    }

    /// The integer square root: the largest `r` with `r * r <= self`.
    ///
    /// Digit-by-digit in base four — two bits of the radicand consumed
    /// per iteration, 256 iterations, no division. The root of a 512-bit
    /// value fits 256 bits, which is what makes this the shape
    /// `geometric-mean` wants.
    #[must_use]
    fn isqrt(self) -> U256 {
        let mut root = U256::ZERO;
        let mut remainder = Self::ZERO;
        for step in 0..256u32 {
            let shift = 510 - step * 2;
            remainder = Self(shl_one(shl_one(remainder.0)));
            remainder.0[0] |= u64::from(self.bit(shift + 1)) << 1;
            remainder.0[0] |= u64::from(self.bit(shift));
            // The root advances a binary digit first, and the trial
            // subtrahend is twice the advanced root plus one — the
            // difference between `(r+1)^2` and `r^2` at this digit.
            root = U256(shl_one(root.0));
            let mut trial = Self(shl_one(Self::from_u256(root).0));
            trial.0[0] |= 1;
            if remainder >= trial {
                remainder = Self(sub_limbs_wide(remainder.0, trial.0).0);
                root.0[0] |= 1;
            }
        }
        root
    }
}

impl Ord for U512 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..8).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U512 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `a * b / c`, with the product held whole and one rounding at the end.
///
/// # Errors
///
/// [`MathError::DivideByZero`] on a zero divisor, [`MathError::Overflow`]
/// on a quotient past 256 bits.
pub fn mul_div(a: U256, b: U256, c: U256, rounding: Rounding) -> Result<U256, MathError> {
    if c.is_zero() {
        return Err(MathError::DivideByZero);
    }
    let (quotient, remainder) = a.widening_mul(b).div_rem(c);
    let quotient = quotient.narrow().ok_or(MathError::Overflow)?;
    match rounding {
        Rounding::Down => Ok(quotient),
        Rounding::Up if remainder.is_zero() => Ok(quotient),
        Rounding::Up => quotient.checked_add(U256::ONE).ok_or(MathError::Overflow),
    }
}

/// `floor(sqrt(a * b))`, with the product held whole.
///
/// The square root a contract wants is `sqrt(a)`, which is this with `b`
/// at one; the two-argument form is what an initial liquidity mint needs,
/// where forming `a * b` first is exactly the overflow this interface
/// exists to prevent.
#[must_use]
pub fn geometric_mean(a: U256, b: U256) -> U256 {
    a.widening_mul(b).isqrt()
}

/// `(an/ad) * (bn/bd)`, as a fraction in the same width.
///
/// Multiplies across first and reduces only where the product does not
/// fit. Two integers drawn from a quantity quotient are coprime with
/// probability `6/pi^2`, so reduction is usually work with no result, and
/// paying for it on every composition would be paying for the uncommon
/// case.
///
/// # Errors
///
/// [`MathError::DivideByZero`] on a zero denominator,
/// [`MathError::Overflow`] where the product does not fit even reduced.
pub fn fraction_compose(an: U256, ad: U256, bn: U256, bd: U256) -> Result<(U256, U256), MathError> {
    if ad.is_zero() || bd.is_zero() {
        return Err(MathError::DivideByZero);
    }
    if let (Some(num), Some(den)) = (an.widening_mul(bn).narrow(), ad.widening_mul(bd).narrow()) {
        return Ok((num, den));
    }
    // Cross-reduce: each numerator against the other's denominator, which
    // is where a shared factor in a composition actually sits.
    let (an, bd) = reduce_pair(an, bd);
    let (bn, ad) = reduce_pair(bn, ad);
    let num = an.widening_mul(bn).narrow().ok_or(MathError::Overflow)?;
    let den = ad.widening_mul(bd).narrow().ok_or(MathError::Overflow)?;
    Ok((num, den))
}

/// `an/ad` against `bn/bd`, by cross-multiplication at full width.
///
/// # Errors
///
/// [`MathError::DivideByZero`] on a zero denominator.
pub fn fraction_cmp(an: U256, ad: U256, bn: U256, bd: U256) -> Result<Ordering, MathError> {
    if ad.is_zero() || bd.is_zero() {
        return Err(MathError::DivideByZero);
    }
    Ok(an.widening_mul(bd).cmp(&bn.widening_mul(ad)))
}

/// `base^exp` at [`FIXED_SCALE`], by squaring.
///
/// The rounding applies to each multiplication rather than to the result,
/// which is the most a fixed intermediate width allows: the error is
/// bounded by one unit in the last place per squaring step, so at most
/// `2 * log2(exp)` of them.
///
/// # Errors
///
/// [`MathError::Overflow`] where any intermediate leaves 256 bits.
pub fn fixed_pow(base: U256, exp: u32, rounding: Rounding) -> Result<U256, MathError> {
    let mut result = FIXED_SCALE;
    let mut factor = base;
    let mut remaining = exp;
    while remaining > 0 {
        if remaining & 1 == 1 {
            result = mul_div(result, factor, FIXED_SCALE, rounding)?;
        }
        remaining >>= 1;
        if remaining > 0 {
            factor = mul_div(factor, factor, FIXED_SCALE, rounding)?;
        }
    }
    Ok(result)
}

/// Both values divided by their greatest common divisor.
///
/// Binary GCD: shifts and subtractions, no division, and a trip count
/// bounded by the sum of the operands' bit lengths.
fn reduce_pair(a: U256, b: U256) -> (U256, U256) {
    let divisor = gcd(a, b);
    if divisor.is_zero() || divisor == U256::ONE {
        return (a, b);
    }
    let (a_reduced, _) = U512::from_u256(a).div_rem(divisor);
    let (b_reduced, _) = U512::from_u256(b).div_rem(divisor);
    (
        a_reduced.narrow().unwrap_or(a),
        b_reduced.narrow().unwrap_or(b),
    )
}

/// The greatest common divisor, by Stein's algorithm.
fn gcd(a: U256, b: U256) -> U256 {
    if a.is_zero() {
        return b;
    }
    if b.is_zero() {
        return a;
    }
    let shift = a.trailing_zeros().min(b.trailing_zeros());
    let mut a = a.shr(a.trailing_zeros());
    let mut b = b.shr(b.trailing_zeros());
    loop {
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }
        b = U256(sub_limbs(b.0, a.0).0);
        if b.is_zero() {
            break;
        }
        b = b.shr(b.trailing_zeros());
    }
    U256(shl_limbs(a.0, shift))
}

const fn add_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
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

const fn sub_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
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

const fn sub_limbs_wide(a: [u64; 8], b: [u64; 8]) -> ([u64; 8], bool) {
    let mut out = [0u64; 8];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 8 {
        let (partial, first) = a[i].overflowing_sub(b[i]);
        let (total, second) = partial.overflowing_sub(borrow);
        out[i] = total;
        borrow = if first || second { 1 } else { 0 };
        i += 1;
    }
    (out, borrow != 0)
}

#[allow(clippy::cast_possible_truncation)] // taking a limb off a 128-bit column is the truncation
const fn mul_limbs(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0u128;
        let mut j = 0;
        while j < 4 {
            let total = (a[i] as u128) * (b[j] as u128) + (out[i + j] as u128) + carry;
            out[i + j] = total as u64;
            carry = total >> 64;
            j += 1;
        }
        out[i + 4] = carry as u64;
        i += 1;
    }
    out
}

const fn shl_one<const N: usize>(limbs: [u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut carry = 0u64;
    let mut i = 0;
    while i < N {
        out[i] = (limbs[i] << 1) | carry;
        carry = limbs[i] >> 63;
        i += 1;
    }
    out
}

const fn shl_limbs(limbs: [u64; 4], bits: u32) -> [u64; 4] {
    if bits >= 256 {
        return [0; 4];
    }
    let whole = (bits / 64) as usize;
    let part = bits % 64;
    let mut out = [0u64; 4];
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if i < whole {
            continue;
        }
        let low = limbs[i - whole] << part;
        let high = if part == 0 || i == whole {
            0
        } else {
            limbs[i - whole - 1] >> (64 - part)
        };
        out[i] = low | high;
    }
    out
}

const fn shr_limbs(limbs: [u64; 4], bits: u32) -> [u64; 4] {
    if bits >= 256 {
        return [0; 4];
    }
    let whole = (bits / 64) as usize;
    let part = bits % 64;
    let mut out = [0u64; 4];
    let mut i = 0;
    while i + whole < 4 {
        let high = limbs[i + whole] >> part;
        let low = if part == 0 || i + whole + 1 >= 4 {
            0
        } else {
            limbs[i + whole + 1] << (64 - part)
        };
        out[i] = high | low;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        FIXED_SCALE, MathError, Ordering, Rounding, U256, U512, fixed_pow, fraction_cmp,
        fraction_compose, geometric_mean, mul_div,
    };

    /// A deterministic generator: the arithmetic under test is exact, so
    /// the corpus only has to be wide and reproducible.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A value with a uniformly chosen bit width, so small operands
        /// are as common as wide ones.
        fn next(&mut self) -> U256 {
            let bits = self.next_u64() % 257;
            if bits == 0 {
                return U256::ZERO;
            }
            let mut limbs = [0u64; 4];
            for limb in &mut limbs {
                *limb = self.next_u64();
            }
            U256::from_limbs(limbs).shr(256 - u32::try_from(bits).expect("bits under 257"))
        }
    }

    fn u(n: u128) -> U256 {
        U256::from_u128(n)
    }

    #[test]
    fn narrow_products_agree_with_native_arithmetic() {
        let mut rng = Rng(0x5eed_1234_abcd_0001);
        for _ in 0..2_000 {
            let a = u128::from(rng.next_u64());
            let b = u128::from(rng.next_u64());
            let c = u128::from(rng.next_u64()) | 1;
            let native = a * b / c;
            let wide = mul_div(u(a), u(b), u(c), Rounding::Down).expect("fits");
            assert_eq!(wide.to_u128(), Some(native));
        }
    }

    #[test]
    fn rounding_up_is_the_ceiling() {
        assert_eq!(mul_div(u(7), u(1), u(2), Rounding::Down), Ok(u(3)));
        assert_eq!(mul_div(u(7), u(1), u(2), Rounding::Up), Ok(u(4)));
        assert_eq!(mul_div(u(8), u(1), u(2), Rounding::Down), Ok(u(4)));
        assert_eq!(mul_div(u(8), u(1), u(2), Rounding::Up), Ok(u(4)));
    }

    #[test]
    fn the_product_is_held_whole() {
        // The expression the AMM could not write: both reserves near the
        // top of `u128`, whose product leaves the width entirely.
        let y = u(u128::MAX);
        let dx = u(u128::MAX / 3);
        let x_plus_dx = u(u128::MAX);
        let out = mul_div(y, dx, x_plus_dx, Rounding::Down).expect("the ratio is under one");
        assert_eq!(out, dx);
    }

    #[test]
    fn division_by_zero_is_declared() {
        assert_eq!(
            mul_div(u(1), u(1), U256::ZERO, Rounding::Down),
            Err(MathError::DivideByZero)
        );
        assert_eq!(
            fraction_cmp(u(1), U256::ZERO, u(1), u(1)),
            Err(MathError::DivideByZero)
        );
    }

    #[test]
    fn a_quotient_past_the_width_overflows() {
        assert_eq!(
            mul_div(U256::MAX, U256::MAX, U256::ONE, Rounding::Down),
            Err(MathError::Overflow)
        );
        assert_eq!(
            mul_div(U256::MAX, U256::MAX, u(2), Rounding::Up),
            Err(MathError::Overflow)
        );
        // A ceiling with nothing to round adds nothing, so the widest
        // exact quotient is not an overflow.
        assert_eq!(
            mul_div(U256::MAX, U256::ONE, U256::ONE, Rounding::Up),
            Ok(U256::MAX)
        );
    }

    #[test]
    fn mul_div_reconstructs_its_dividend() {
        let mut rng = Rng(0x5eed_1234_abcd_0002);
        for _ in 0..2_000 {
            let (a, b) = (rng.next(), rng.next());
            let c = {
                let candidate = rng.next();
                if candidate.is_zero() {
                    U256::ONE
                } else {
                    candidate
                }
            };
            let Ok(quotient) = mul_div(a, b, c, Rounding::Down) else {
                continue;
            };
            // `q * c <= a * b < (q + 1) * c`, checked at full width.
            let product = a.widening_mul(b);
            assert!(quotient.widening_mul(c) <= product);
            let next = quotient
                .checked_add(U256::ONE)
                .expect("a quotient that fits");
            assert!(next.widening_mul(c) > product);
        }
    }

    #[test]
    fn geometric_mean_brackets_the_root() {
        let mut rng = Rng(0x5eed_1234_abcd_0003);
        for _ in 0..2_000 {
            let (a, b) = (rng.next(), rng.next());
            let root = geometric_mean(a, b);
            let product = a.widening_mul(b);
            assert!(root.widening_mul(root) <= product);
            if let Some(next) = root.checked_add(U256::ONE) {
                assert!(next.widening_mul(next) > product);
            }
        }
    }

    #[test]
    fn geometric_mean_is_exact_on_perfect_squares() {
        for n in [
            0u128,
            1,
            2,
            3,
            4,
            255,
            256,
            257,
            1 << 63,
            u128::from(u64::MAX),
        ] {
            assert_eq!(geometric_mean(u(n), u(n)), u(n));
        }
        assert_eq!(geometric_mean(u(u128::MAX), u(u128::MAX)), u(u128::MAX));
        // The mint an AMM cannot write today: two reserves whose product
        // is past `u128` and whose root is not.
        assert_eq!(geometric_mean(u(4 << 100), u(1 << 100)), u(2 << 100));
    }

    #[test]
    fn a_square_root_is_a_geometric_mean_against_one() {
        for n in [0u128, 1, 15, 16, 17, 1_000_000, u128::MAX] {
            let root = geometric_mean(u(n), U256::ONE);
            let squared = root.to_u128().expect("a root of a u128 fits").pow(2);
            assert!(squared <= n);
        }
    }

    #[test]
    fn composition_reduces_only_where_it_must() {
        // Terms that fit: multiplied across, unreduced, so a caller can
        // see the fraction it composed.
        assert_eq!(fraction_compose(u(2), u(4), u(3), u(9)), Ok((u(6), u(36))));
        // Terms that do not: reduced, and equal to the unreduced value.
        let big = u(u128::MAX);
        let (num, den) = fraction_compose(U256::MAX, big, big, U256::MAX).expect("reducible");
        assert_eq!(
            fraction_cmp(num, den, U256::ONE, U256::ONE),
            Ok(Ordering::Equal)
        );
    }

    #[test]
    fn composition_holds_the_cross_rate() {
        // The depth-two composition `u128` terms could not carry: two
        // rates from quantity quotients at realistic balance scale.
        let a = u(10_u128.pow(24));
        let b = u(3 * 10_u128.pow(24));
        let c = u(7 * 10_u128.pow(24));
        let (num, den) = fraction_compose(a, b, b, c).expect("256-bit terms carry it");
        assert_eq!(fraction_cmp(num, den, a, c), Ok(Ordering::Equal));
    }

    #[test]
    fn composition_past_the_width_is_declared() {
        assert_eq!(
            fraction_compose(U256::MAX, U256::ONE, U256::MAX, U256::ONE),
            Err(MathError::Overflow)
        );
        assert_eq!(
            fraction_compose(U256::ONE, U256::ZERO, U256::ONE, U256::ONE),
            Err(MathError::DivideByZero)
        );
    }

    #[test]
    fn composition_preserves_value() {
        let mut rng = Rng(0x5eed_1234_abcd_0004);
        for _ in 0..2_000 {
            let nonzero = |candidate: U256| {
                if candidate.is_zero() {
                    U256::ONE
                } else {
                    candidate
                }
            };
            let (an, bn) = (rng.next(), rng.next());
            let (ad, bd) = (nonzero(rng.next()), nonzero(rng.next()));
            let Ok((num, den)) = fraction_compose(an, ad, bn, bd) else {
                continue;
            };
            // The composed fraction equals the unreduced one wherever
            // the unreduced one is representable, which is the only case
            // in which there is something to compare it against.
            if let (Some(unreduced_num), Some(unreduced_den)) =
                (an.widening_mul(bn).narrow(), ad.widening_mul(bd).narrow())
            {
                assert_eq!(
                    fraction_cmp(num, den, unreduced_num, unreduced_den),
                    Ok(Ordering::Equal)
                );
            }
        }
    }

    #[test]
    fn fraction_comparison_orders_by_value() {
        assert_eq!(fraction_cmp(u(1), u(3), u(2), u(6)), Ok(Ordering::Equal));
        assert_eq!(fraction_cmp(u(1), u(3), u(1), u(2)), Ok(Ordering::Less));
        assert_eq!(fraction_cmp(u(2), u(3), u(1), u(2)), Ok(Ordering::Greater));
        // Terms whose cross-products leave `u128`, which is the reason
        // the comparison is the host's.
        let wide = u(u128::MAX);
        assert_eq!(fraction_cmp(wide, wide, u(1), u(1)), Ok(Ordering::Equal));
    }

    #[test]
    fn a_power_of_zero_is_one() {
        assert_eq!(fixed_pow(u(0), 0, Rounding::Down), Ok(FIXED_SCALE));
        assert_eq!(fixed_pow(FIXED_SCALE, 0, Rounding::Down), Ok(FIXED_SCALE));
    }

    #[test]
    fn a_power_of_one_is_the_base() {
        let base = u(3 * 10_u128.pow(35));
        assert_eq!(fixed_pow(base, 1, Rounding::Down), Ok(base));
    }

    #[test]
    fn compounding_squares_the_scale() {
        // 1.5 at the fixed scale, squared, is 2.25.
        let one_and_a_half = u(15 * 10_u128.pow(35));
        let expected = u(225 * 10_u128.pow(34));
        assert_eq!(fixed_pow(one_and_a_half, 2, Rounding::Down), Ok(expected));
        // Ten periods of ten percent lands on 1.1^10 to the scale's last
        // digits, the truncation being one unit per squaring step.
        let ten_percent = u(11 * 10_u128.pow(35));
        let ten = fixed_pow(ten_percent, 10, Rounding::Down).expect("in range");
        let exact = u(25_937_424_601 * 10_u128.pow(26));
        assert!(ten <= exact);
        // Every squaring step truncates by under a unit in the last
        // place, and the steps carry each other's loss, so the whole is
        // bounded by the step count against a scale of 10^36.
        assert!(exact.checked_sub(ten).expect("under") <= u(100));
    }

    #[test]
    fn division_is_the_inverse_of_multiplication() {
        let mut rng = Rng(0x5eed_1234_abcd_0005);
        for _ in 0..2_000 {
            let a = rng.next();
            let b = {
                let candidate = rng.next();
                if candidate.is_zero() {
                    U256::ONE
                } else {
                    candidate
                }
            };
            let (quotient, remainder) = U512::from_u256(a).div_rem(b);
            let quotient = quotient.narrow().expect("a u256 over a u256 fits");
            assert!(remainder < b);
            let reconstructed = quotient
                .widening_mul(b)
                .narrow()
                .expect("the dividend fits")
                .checked_add(remainder)
                .expect("the dividend fits");
            assert_eq!(reconstructed, a);
        }
    }
}
