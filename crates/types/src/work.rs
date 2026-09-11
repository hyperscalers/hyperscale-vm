//! What a transaction declares it may consume, dimension by dimension,
//! and the table that prices the vector into a fee.
//!
//! Five dimensions, each in its own unit, because the resources are not
//! one resource: compute is fuel, reads and writes are bytes off and
//! onto the store, footprint is exclusion, retention is what every
//! validator stores and gossips for the horizon. They stay a vector
//! until the fee so a block can cap each on its own content — a block
//! of scan-heavy transactions saturates disk while compute idles, and
//! no scalar can see it — and the fee is the table-weighted sum.
//!
//! Every figure on the declared side is a pure function of signed
//! content and published metadata, so every participant of a
//! cross-shard transaction reaches one vector and one price before
//! anything runs. Nothing measured enters it.
//!
//! The attested side is one scalar still: what an execution consumed
//! under the engine's schedule, reported in the local receipt. An
//! aborted execution attests its footprint alone; `vm_kernel`'s receipt
//! constructor is where that rule is applied, because the outcome is
//! what selects it and the outcome lives there.
//!
//! Every weight is a placeholder: what one unit costs is set against
//! measured baselines rather than chosen here, and the table is a
//! consensus value the beacon moves once per epoch. Saturating
//! throughout, so a wrapped figure never reads as a shard that did
//! almost nothing.

use crate::amount::Quanta;
use crate::scheme::SchemeId;

/// Work units charged per unit of consumed fuel.
pub const FUEL_WEIGHT: u64 = 1;

/// Work units charged per unit of declared footprint.
pub const FOOTPRINT_WEIGHT: u64 = 1;

/// Fuel one ed25519-equivalent signature verification costs, the unit
/// [`verify_weight`](crate::SchemeSpec::verify_weight) counts in.
///
/// Verification is admission's compute, paid before an execution
/// exists, and it enters the compute dimension in fuel like the rest:
/// fifty microseconds of a core at the rate the limits derive from.
pub const VERIFY_WEIGHT: u64 = 100_000;

/// The work a single execution attests: its fuel and its footprint under
/// one schedule.
///
/// Pass `0` for `fuel` when the execution did not complete — see the
/// module docs for why that is a determinism requirement rather than a
/// pricing choice.
#[must_use]
pub const fn work_units(fuel: u64, footprint: u64) -> u64 {
    FUEL_WEIGHT
        .saturating_mul(fuel)
        .saturating_add(FOOTPRINT_WEIGHT.saturating_mul(footprint))
}

/// The compute verifying one signature under `scheme` costs, in fuel.
///
/// Read off the registry rather than off the material an envelope
/// carries, because the scheme is signed content and the key and
/// signature bytes are not: a quantity measured from the wire lengths
/// would be one a sender could move without signing for it.
///
/// A scheme nothing registers costs nothing, which is sound only because
/// it also verifies under nothing — no envelope reaches a fee carrying
/// one.
#[must_use]
pub const fn signature_compute(scheme: SchemeId) -> u64 {
    match scheme.spec() {
        Some(spec) => VERIFY_WEIGHT.saturating_mul(spec.verify_weight),
        None => 0,
    }
}

/// The bytes one signature under `scheme` carries: its key and the
/// signature over it, off the registry on [`signature_compute`]'s terms.
/// Retention, since every validator stores them for the horizon.
#[must_use]
pub const fn signature_bytes(scheme: SchemeId) -> u64 {
    match scheme.spec() {
        Some(spec) => (spec.key_len + spec.sig_len) as u64,
        None => 0,
    }
}

/// What a transaction declares it may consume, before it runs, in
/// five dimensions each in its own unit.
///
/// The declaration is the whole bound: a shard cannot consult another
/// before running a leg, so every resource a leg may consume is read off
/// the signed transaction alone, and what is declared is what is charged
/// on every outcome. A block caps each dimension on its own content and
/// a [`PriceTable`] weighs them into one fee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeclaredWork {
    /// Fuel: the sum of the per-node ceilings the composer signed, plus
    /// the verification of every signature the envelope binds.
    pub compute: u64,
    /// Bytes read off the store: `(cap + 1) × width` per declared range,
    /// `width` per declared point, and every distinct package's artifact
    /// once, since instantiating a node reads it.
    pub read_bytes: u64,
    /// Bytes written onto the store: `cap × width` per declared range,
    /// `width` per declared point, and the cells the kernel writes of
    /// its own accord at their fixed widths.
    pub write_bytes: u64,
    /// Exclusion and depth, on the effects schedule: what the
    /// declaration stops others doing and how far a body may walk.
    pub footprint: u64,
    /// Bytes every validator retains for the horizon: the envelope, the
    /// writes, the auth material, and the events a package may emit.
    pub retention: u64,
}

impl DeclaredWork {
    /// Nothing declared.
    pub const ZERO: Self = Self {
        compute: 0,
        read_bytes: 0,
        write_bytes: 0,
        footprint: 0,
        retention: 0,
    };

    /// The vector sum, saturating per dimension.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            compute: self.compute.saturating_add(other.compute),
            read_bytes: self.read_bytes.saturating_add(other.read_bytes),
            write_bytes: self.write_bytes.saturating_add(other.write_bytes),
            footprint: self.footprint.saturating_add(other.footprint),
            retention: self.retention.saturating_add(other.retention),
        }
    }

    /// Whether every dimension is at or under `caps`': the one reading of
    /// a cap, so a proposer filling a block and a validator judging it
    /// stop at the same place.
    #[must_use]
    pub const fn fits(&self, caps: &Self) -> bool {
        self.compute <= caps.compute
            && self.read_bytes <= caps.read_bytes
            && self.write_bytes <= caps.write_bytes
            && self.footprint <= caps.footprint
            && self.retention <= caps.retention
    }

    /// What one signature under `scheme` declares: its verification as
    /// compute and its material as retention.
    #[must_use]
    pub const fn signature(scheme: SchemeId) -> Self {
        Self {
            compute: signature_compute(scheme),
            retention: signature_bytes(scheme),
            ..Self::ZERO
        }
    }
}

/// A basis point's denominator: the unit a priority is stated in.
pub const BASIS_POINTS: u32 = 10_000;

/// Work units per quantum of the protocol resource: the rate a weighted
/// vector is settled at.
///
/// The one figure that turns the weighted sum into a fee, and a
/// placeholder like the weights it divides: what a unit of work costs
/// is set against measured baselines rather than chosen here. Sized so
/// that a transfer — two ceilings and a signature — prices in the tens
/// of quanta, inside the ceilings every fixture signs and the balances
/// it funds.
pub const WORK_PER_QUANTUM: u64 = 100_000;

/// The weight of each dimension, in fuel-equivalents per unit.
///
/// Only the ratios mean anything until calibration: compute is the unit,
/// and every other row says how many operators one of its units is
/// worth. One table for the whole network, never per shard — address
/// placement is the protocol's choice and reshape moves it, so a
/// per-shard price would bill a sender for a placement they did not
/// pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceTable {
    /// Per unit of fuel.
    pub compute: u64,
    /// Per byte read off the store.
    pub read_bytes: u64,
    /// Per byte written onto the store.
    pub write_bytes: u64,
    /// Per footprint unit.
    pub footprint: u64,
    /// Per byte retained.
    pub retention: u64,
}

impl PriceTable {
    /// The table the chain is born with: five nanoseconds a byte off disk
    /// against half a nanosecond an operator, a leaf write as tree nodes
    /// and a checkpoint rather than one byte, an exclusion unit pricing
    /// lock contention that no other row sees, and a retained byte held
    /// and gossiped by every validator for the horizon.
    pub const GENESIS: Self = Self {
        compute: 1,
        read_bytes: 10,
        write_bytes: 50,
        footprint: 1_000,
        retention: 20,
    };

    /// The vector under this table, in fuel-equivalents: the weighted
    /// sum, wide enough that no declared vector saturates it.
    #[must_use]
    pub const fn weighted(&self, work: &DeclaredWork) -> u128 {
        (self.compute as u128) * (work.compute as u128)
            + (self.read_bytes as u128) * (work.read_bytes as u128)
            + (self.write_bytes as u128) * (work.write_bytes as u128)
            + (self.footprint as u128) * (work.footprint as u128)
            + (self.retention as u128) * (work.retention as u128)
    }

    /// What `work` costs in quanta at `priority_bp` over the table
    /// price, rounded up once so no transaction that declares anything
    /// is carried for nothing.
    ///
    /// A pure function of the work and the table, both pure functions of
    /// signed content and the anchor — so every shard names one price for
    /// one transaction before anything runs, and a participant that
    /// measures only its own legs bills the same as one that ran the
    /// whole.
    #[must_use]
    pub const fn price(&self, work: &DeclaredWork, priority_bp: u32) -> Quanta {
        let raised = self
            .weighted(work)
            .saturating_mul((BASIS_POINTS as u128) + (priority_bp as u128));
        raised.div_ceil((WORK_PER_QUANTUM as u128) * (BASIS_POINTS as u128))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASIS_POINTS, DeclaredWork, FOOTPRINT_WEIGHT, FUEL_WEIGHT, PriceTable, SchemeId,
        VERIFY_WEIGHT, WORK_PER_QUANTUM, signature_bytes, signature_compute, work_units,
    };

    const fn only(compute: u64) -> DeclaredWork {
        DeclaredWork {
            compute,
            ..DeclaredWork::ZERO
        }
    }

    /// A price is never zero for work that is not, rounds up at the
    /// rate, and never falls as the work rises.
    #[test]
    fn a_price_rounds_up_and_is_monotone() {
        let table = PriceTable::GENESIS;
        assert_eq!(table.price(&DeclaredWork::ZERO, 0), 0);
        assert_eq!(table.price(&only(1), 0), 1);
        assert_eq!(table.price(&only(WORK_PER_QUANTUM), 0), 1);
        assert_eq!(table.price(&only(WORK_PER_QUANTUM + 1), 0), 2);
        for work in [0, 1, 999, 1_000_000, u64::from(u32::MAX)] {
            assert!(table.price(&only(work + 1), 0) >= table.price(&only(work), 0));
        }
    }

    /// Every dimension moves the price on its own, at its own row.
    #[test]
    fn every_dimension_is_priced_at_its_row() {
        let table = PriceTable::GENESIS;
        let rows = [
            (
                DeclaredWork {
                    read_bytes: 1,
                    ..DeclaredWork::ZERO
                },
                table.read_bytes,
            ),
            (
                DeclaredWork {
                    write_bytes: 1,
                    ..DeclaredWork::ZERO
                },
                table.write_bytes,
            ),
            (
                DeclaredWork {
                    footprint: 1,
                    ..DeclaredWork::ZERO
                },
                table.footprint,
            ),
            (
                DeclaredWork {
                    retention: 1,
                    ..DeclaredWork::ZERO
                },
                table.retention,
            ),
            (only(1), table.compute),
        ];
        for (unit, weight) in rows {
            assert!(weight > 0, "a zero row makes a dimension free");
            assert_eq!(table.weighted(&unit), u128::from(weight));
        }
    }

    /// The priority raises the price by its basis points, rounded once
    /// with the rate rather than twice.
    #[test]
    fn a_priority_raises_the_price_proportionally() {
        let table = PriceTable::GENESIS;
        let work = only(10 * WORK_PER_QUANTUM);
        assert_eq!(table.price(&work, 0), 10);
        assert_eq!(table.price(&work, BASIS_POINTS), 20);
        assert_eq!(table.price(&work, BASIS_POINTS / 2), 15);
        assert_eq!(table.price(&work, 1), 11, "any priority at all rounds up");
        assert_eq!(table.price(&DeclaredWork::ZERO, BASIS_POINTS), 0);
    }

    /// The weighted sum is wide: the whole of every dimension at the
    /// genesis rows fits without wrapping.
    #[test]
    fn the_weighted_sum_does_not_wrap_at_the_ceiling() {
        let everything = DeclaredWork {
            compute: u64::MAX,
            read_bytes: u64::MAX,
            write_bytes: u64::MAX,
            footprint: u64::MAX,
            retention: u64::MAX,
        };
        let table = PriceTable::GENESIS;
        let sum = u128::from(
            table.compute
                + table.read_bytes
                + table.write_bytes
                + table.footprint
                + table.retention,
        ) * u128::from(u64::MAX);
        assert_eq!(table.weighted(&everything), sum);
    }

    #[test]
    fn the_vector_sums_and_fits_per_dimension() {
        let a = DeclaredWork {
            compute: 1,
            read_bytes: 2,
            write_bytes: 3,
            footprint: 4,
            retention: 5,
        };
        let b = DeclaredWork {
            compute: u64::MAX,
            read_bytes: 20,
            write_bytes: 30,
            footprint: 40,
            retention: 50,
        };
        let sum = a.saturating_add(b);
        assert_eq!(sum.compute, u64::MAX, "saturating per dimension");
        assert_eq!(sum.read_bytes, 22);
        assert!(a.fits(&b));
        assert!(!b.fits(&a));
        assert!(a.fits(&a), "a cap admits its own figure");
        let mut over = a;
        over.retention += 1;
        assert!(!over.fits(&a), "one dimension over is over");
    }

    /// A wider scheme declares more on both of its axes, which is the
    /// whole reason the terms are read off the registry: a kilobyte
    /// signature is a fee fact rather than free bandwidth.
    #[test]
    fn a_wider_scheme_declares_more() {
        let ed = DeclaredWork::signature(SchemeId::ED25519);
        let secp = DeclaredWork::signature(SchemeId::SECP256K1);
        assert!(ed.compute > 0 && ed.retention > 0);
        assert!(
            secp.compute > ed.compute && secp.retention > ed.retention,
            "secp256k1 carries a wider key and verifies slower"
        );
        assert_eq!(ed.read_bytes + ed.write_bytes + ed.footprint, 0);
    }

    #[test]
    fn a_signature_prices_its_verification_in_fuel() {
        const { assert!(VERIFY_WEIGHT > 0) };
        let spec = SchemeId::ED25519.spec().expect("ed25519 is registered");
        assert_eq!(
            signature_compute(SchemeId::ED25519),
            VERIFY_WEIGHT * spec.verify_weight
        );
        assert_eq!(
            signature_bytes(SchemeId::ED25519),
            (spec.key_len + spec.sig_len) as u64
        );
    }

    /// Material no scheme claims prices at nothing, which is sound only
    /// because it verifies under nothing either.
    #[test]
    fn an_unregistered_scheme_prices_at_nothing() {
        assert_eq!(DeclaredWork::signature(SchemeId::NONE), DeclaredWork::ZERO);
        assert_eq!(
            DeclaredWork::signature(SchemeId(u16::MAX)),
            DeclaredWork::ZERO
        );
    }

    #[test]
    fn both_attested_components_are_priced() {
        // Neither term is silently dropped: moving either one alone moves
        // the total. A weight set to zero would make one half of the
        // quantity unobservable, which is the failure the components on
        // the receipt exist to make visible.
        assert!(work_units(1, 0) > work_units(0, 0));
        assert!(work_units(0, 1) > work_units(0, 0));
    }

    #[test]
    fn attested_work_is_monotone_in_both_components() {
        for fuel in [0, 1, 1_000, u64::from(u32::MAX)] {
            for footprint in [0, 1, 1_000, u64::from(u32::MAX)] {
                assert!(work_units(fuel + 1, footprint) >= work_units(fuel, footprint));
                assert!(work_units(fuel, footprint + 1) >= work_units(fuel, footprint));
            }
        }
    }

    #[test]
    fn an_aborts_work_is_its_footprint_alone() {
        // The shape the kernel's abort rule depends on: dropping the fuel
        // term leaves the footprint term intact rather than zeroing the
        // quantity.
        let footprint = 640;
        assert_eq!(
            work_units(0, footprint),
            FOOTPRINT_WEIGHT.saturating_mul(footprint)
        );
        assert!(work_units(0, footprint) > 0);
    }

    #[test]
    fn the_attested_ceiling_reads_as_the_ceiling() {
        // Never wraps: at the top the total pins rather than restarting
        // near zero, so a saturated shard cannot read as an idle one.
        assert_eq!(work_units(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(work_units(u64::MAX, 1), u64::MAX);
        assert_eq!(FUEL_WEIGHT.saturating_mul(u64::MAX), u64::MAX);
    }
}
