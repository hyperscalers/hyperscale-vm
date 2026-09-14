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
//! Every figure is a pure function of signed content and published
//! metadata, so every participant of a cross-shard transaction reaches
//! one vector and one price before anything runs. Nothing measured
//! enters it: what an execution consumed is reported in its receipt and
//! prices nothing, since a figure an engine measured about itself is one
//! a shard could inflate to raise its own emission weight.
//!
//! Every weight is a placeholder: what one unit costs is set against
//! measured baselines rather than chosen here, and the table is a
//! consensus value the beacon moves once per epoch. Saturating
//! throughout, so a wrapped figure never reads as a shard that did
//! almost nothing.

use hyperscale_hbor::Hbor;

use crate::amount::Quanta;
use crate::scheme::SchemeId;

/// Fuel one ed25519-equivalent signature verification costs, the unit
/// [`verify_weight`](crate::SchemeSpec::verify_weight) counts in.
///
/// Verification is admission's compute, paid before an execution
/// exists, and it enters the compute dimension in fuel like the rest:
/// fifty microseconds of a core at the rate the limits derive from.
pub const VERIFY_WEIGHT: u64 = 100_000;

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
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

/// The resolution every row of a [`PriceTable`] is stated in: thousandths
/// of a fuel-equivalent.
///
/// The rows are ratios, and the controller moves them by eighths — so a
/// row stated as a small integer could not move at all. An eighth of one
/// is nothing, and compute is the row the ratios are taken against, so
/// without this the one dimension the table calls its unit would be the
/// one price governance could never retune. Nothing costs more for it:
/// [`WORK_PER_QUANTUM`] carries the same factor.
pub const PRICE_RESOLUTION: u64 = 1_000;

/// Work units per quantum of the protocol resource: the rate a weighted
/// vector is settled at.
///
/// The one figure that turns the weighted sum into a fee, and a
/// placeholder like the weights it divides: what a unit of work costs
/// is set against measured baselines rather than chosen here. Sized so
/// that a transfer — two ceilings and a signature — prices in the tens
/// of quanta, inside the ceilings every fixture signs and the balances
/// it funds.
pub const WORK_PER_QUANTUM: u64 = 100_000 * PRICE_RESOLUTION;

/// The weight of each dimension, in fuel-equivalents per unit.
///
/// Only the ratios mean anything until calibration: compute is the unit,
/// and every other row says how many operators one of its units is
/// worth. One table for the whole network, never per shard — address
/// placement is the protocol's choice and reshape moves it, so a
/// per-shard price would bill a sender for a placement they did not
/// pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
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
        compute: PRICE_RESOLUTION,
        read_bytes: 10 * PRICE_RESOLUTION,
        write_bytes: 50 * PRICE_RESOLUTION,
        footprint: 1_000 * PRICE_RESOLUTION,
        retention: 20 * PRICE_RESOLUTION,
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

/// The floor and ceiling each row of a [`PriceTable`] moves between.
///
/// Governance's half of the price: pools vote the bounds as they vote
/// any other parameter, and the level inside them is the controller's,
/// moved once per epoch by what the network actually declared. So a
/// vote decides how far a price may ever travel and demand decides
/// where inside that it sits — neither alone can price a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct PriceBounds {
    /// The lowest each row may reach.
    pub floor: PriceTable,
    /// The highest each row may reach.
    pub ceiling: PriceTable,
}

impl PriceBounds {
    /// The bounds the chain is born with: the genesis table on both
    /// sides, so every row starts pinned where it is.
    ///
    /// A degenerate interval rather than a wide one, because every
    /// weight in the table is a placeholder until calibration and a
    /// controller turned loose on uncalibrated weights would walk a
    /// price somewhere nobody chose. Widening a row is a governance act
    /// — the same vote that would retune the weight it prices — and the
    /// controller is what takes over inside whatever interval that vote
    /// opens. Until one does, the price is what genesis fixed, which is
    /// what a network with nothing measured yet should charge.
    pub const GENESIS: Self = Self::band(BASIS_POINTS, BASIS_POINTS);

    /// The genesis table scaled by `floor_bp` and `ceiling_bp` basis
    /// points: the interval a vote opens, stated as a band around the
    /// reference rather than as ten absolute figures.
    ///
    /// Per row in storage and a band on the wire, because the two
    /// answer different questions. What the rows are worth relative to
    /// each other is calibration, settled by measurement; how far any of
    /// them may travel from that is policy, and a voter can say "between
    /// an eighth and eight times" where they could not meaningfully name
    /// a fuel-equivalent for retention. A later vote form can set a row
    /// on its own without moving anything stored.
    #[must_use]
    pub const fn band(floor_bp: u32, ceiling_bp: u32) -> Self {
        Self {
            floor: scaled(floor_bp),
            ceiling: scaled(ceiling_bp),
        }
    }

    /// Whether every row admits a level at all: a positive floor, since
    /// a free dimension is one nothing bounds, and a ceiling no lower
    /// than it.
    #[must_use]
    pub const fn well_formed(&self) -> bool {
        self.floor.compute > 0
            && self.floor.read_bytes > 0
            && self.floor.write_bytes > 0
            && self.floor.footprint > 0
            && self.floor.retention > 0
            && self.ceiling.compute >= self.floor.compute
            && self.ceiling.read_bytes >= self.floor.read_bytes
            && self.ceiling.write_bytes >= self.floor.write_bytes
            && self.ceiling.footprint >= self.floor.footprint
            && self.ceiling.retention >= self.floor.retention
    }

    /// The basis points these bounds were opened at, if a band can
    /// still state them.
    ///
    /// The inverse [`Self::band`] needs and does not otherwise have:
    /// storage is ten rows and the vote is two figures, so a voter
    /// moving some *other* governed parameter has to restate the band,
    /// and without this there is nothing to restate it from — every
    /// such vote would reset the price interval to whatever the caller
    /// guessed.
    ///
    /// Read off the footprint row, which is the one that inverts
    /// exactly: at a thousand fuel-equivalents it scales to `100 × bp`
    /// for every `bp`, where compute at one loses the low digit. The
    /// candidate is then reconstructed and compared whole, so bounds no
    /// band could produce — a later per-row vote form's, or a retuned
    /// reference table that breaks the exact row — answer `None` rather
    /// than a figure that would move four rows to restate one.
    #[must_use]
    pub fn as_band(&self) -> Option<(u32, u32)> {
        let floor_bp = band_of(self.floor)?;
        let ceiling_bp = band_of(self.ceiling)?;
        (Self::band(floor_bp, ceiling_bp) == *self).then_some((floor_bp, ceiling_bp))
    }

    /// `table` with every row brought inside these bounds.
    ///
    /// Named for what it produces rather than `clamp`, which on an
    /// `Ord` type is the standard library's and takes the receiver by
    /// value — so the inherent one would be shadowed at every call.
    ///
    /// What a vote that narrows the bounds does to a level already
    /// outside them: the level moves at the next fold rather than the
    /// vote, so the two rails stay independent.
    #[must_use]
    pub const fn inside(&self, table: PriceTable) -> PriceTable {
        PriceTable {
            compute: clamp_row(table.compute, self.floor.compute, self.ceiling.compute),
            read_bytes: clamp_row(
                table.read_bytes,
                self.floor.read_bytes,
                self.ceiling.read_bytes,
            ),
            write_bytes: clamp_row(
                table.write_bytes,
                self.floor.write_bytes,
                self.ceiling.write_bytes,
            ),
            footprint: clamp_row(
                table.footprint,
                self.floor.footprint,
                self.ceiling.footprint,
            ),
            retention: clamp_row(
                table.retention,
                self.floor.retention,
                self.ceiling.retention,
            ),
        }
    }
}

/// The genesis table at `bp` basis points of itself, saturating: a row
/// that would overflow pins rather than wrapping into a free dimension.
const fn scaled(bp: u32) -> PriceTable {
    const fn row(level: u64, bp: u32) -> u64 {
        let scaled = (level as u128) * (bp as u128) / (BASIS_POINTS as u128);
        if scaled > u64::MAX as u128 {
            u64::MAX
        } else {
            #[allow(clippy::cast_possible_truncation)] // guarded on the line above
            {
                scaled as u64
            }
        }
    }
    PriceTable {
        compute: row(PriceTable::GENESIS.compute, bp),
        read_bytes: row(PriceTable::GENESIS.read_bytes, bp),
        write_bytes: row(PriceTable::GENESIS.write_bytes, bp),
        footprint: row(PriceTable::GENESIS.footprint, bp),
        retention: row(PriceTable::GENESIS.retention, bp),
    }
}

/// The basis points `table` reads as, taken off the footprint row.
///
/// Partial inverse of [`scaled`], which truncates per row: footprint is
/// the row that survives it, since a thousand fuel-equivalents scale to
/// exactly `100 × bp`. A candidate only — the caller reconstructs and
/// compares, which is what makes a table no band produced answer with
/// nothing.
fn band_of(table: PriceTable) -> Option<u32> {
    const PER_BP: u64 = PriceTable::GENESIS.footprint / BASIS_POINTS as u64;
    if !table.footprint.is_multiple_of(PER_BP) {
        return None;
    }
    u32::try_from(table.footprint / PER_BP).ok()
}

/// One row inside its own bounds. The ceiling wins a pair that crosses,
/// which `well_formed` refuses at the vote and this cannot assume.
const fn clamp_row(level: u64, floor: u64, ceiling: u64) -> u64 {
    if level < floor {
        floor
    } else if level > ceiling {
        ceiling
    } else {
        level
    }
}

/// What one dimension's blocks declared against what they could have.
///
/// A ratio kept as a pair rather than divided, so the controller stays
/// in integers: `used` is the sum of the declared shares the epoch's
/// blocks reserved, `capacity` the per-block cap times every block they
/// committed. Every block and not only the ones carrying something: a
/// block that declared nothing is a block's worth of capacity nobody
/// wanted, which is the reading an idle network should give.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Utilization {
    /// What the epoch's blocks declared in this dimension.
    pub used: u128,
    /// What they could have declared: the cap times the block count.
    pub capacity: u128,
}

impl PriceTable {
    /// This table one epoch on, under `utilization` and inside `bounds`.
    ///
    /// Each row moves by its own dimension's use and by nothing else:
    /// `next = prev × (1 + (u − ½) / 4)`, so a saturated epoch raises a
    /// row by an eighth and an idle one lowers it by the same, with the
    /// half-full point standing still. The quarter and the half are
    /// placeholders like the weights.
    ///
    /// Rounding goes away from `prev`, so a row the eighth would move by
    /// less than a whole unit still moves and no row is a fixed point
    /// against its own reading. The half-full point divides exactly, so
    /// a row at rest cannot ratchet on integer division alone, and a
    /// dimension whose epoch had no capacity at all — no shard reserved
    /// anything — holds where it is rather than reading as idle.
    #[must_use]
    pub const fn stepped(&self, utilization: &FiveWay, bounds: &PriceBounds) -> Self {
        bounds.inside(Self {
            compute: stepped_row(self.compute, utilization.compute),
            read_bytes: stepped_row(self.read_bytes, utilization.read_bytes),
            write_bytes: stepped_row(self.write_bytes, utilization.write_bytes),
            footprint: stepped_row(self.footprint, utilization.footprint),
            retention: stepped_row(self.retention, utilization.retention),
        })
    }
}

/// One [`Utilization`] per dimension: an epoch's reading of the network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FiveWay {
    /// Fuel declared against fuel available.
    pub compute: Utilization,
    /// Read bytes declared against read bytes available.
    pub read_bytes: Utilization,
    /// Write bytes declared against write bytes available.
    pub write_bytes: Utilization,
    /// Footprint declared against footprint available.
    pub footprint: Utilization,
    /// Retained bytes declared against retained bytes available.
    pub retention: Utilization,
}

/// One row stepped: `prev × (7 × capacity + 2 × used) / (8 × capacity)`,
/// which is `prev × (1 + (u − ½) / 4)` cleared of its fractions.
///
/// An epoch with no capacity holds the row where it is: there was no
/// reading, and treating one as idle would walk every price down through
/// a network's quiet spell.
const fn stepped_row(prev: u64, utilization: Utilization) -> u64 {
    let Utilization { used, capacity } = utilization;
    if capacity == 0 {
        return prev;
    }
    // Saturating at the cap: a block cannot declare past its own budget,
    // so a figure that does is a defect rather than a reading, and the
    // controller answers it as full rather than as unbounded demand.
    let used = if used > capacity { capacity } else { used };
    let numerator = (prev as u128).saturating_mul(
        capacity
            .saturating_mul(7)
            .saturating_add(used.saturating_mul(2)),
    );
    let denominator = capacity.saturating_mul(8);
    // Away from `prev`: a row moving up takes the ceiling and a row
    // moving down truncates, so a move the eighth rounds to under a
    // whole unit still lands. Rounding toward `prev` instead freezes
    // every row at or below seven in both directions — `9v/8` and
    // `7v/8` both round back to `v` there — so a band whose floor
    // reaches that low pins its row at the floor whatever the network
    // declares. The half-full point divides exactly, so a row at rest
    // still cannot ratchet on the division alone.
    let next = if used.saturating_mul(2) >= capacity {
        numerator.div_ceil(denominator)
    } else {
        numerator / denominator
    };
    // A row is bounded far below this, so the pin is unreachable — but
    // the arithmetic above widens to `u128` and a narrowing cast that
    // wrapped would read a saturated row as a free one.
    if next > u64::MAX as u128 {
        u64::MAX
    } else {
        #[allow(clippy::cast_possible_truncation)] // guarded on the line above
        {
            next as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASIS_POINTS, DeclaredWork, FiveWay, PriceBounds, PriceTable, SchemeId, Utilization,
        VERIFY_WEIGHT, WORK_PER_QUANTUM, signature_bytes, signature_compute,
    };

    const fn only(compute: u64) -> DeclaredWork {
        DeclaredWork {
            compute,
            ..DeclaredWork::ZERO
        }
    }

    /// A vector whose weighted sum under `table` is `units` work units,
    /// stated in the one dimension the ratios are taken against.
    ///
    /// Written through the table rather than as a fuel figure, because
    /// the compute row is a price like any other: a test that assumed
    /// one unit of fuel weighed one work unit would be pinning the row's
    /// current value rather than the arithmetic around it.
    fn worth(table: &PriceTable, units: u64) -> DeclaredWork {
        assert_eq!(units % table.compute, 0, "a whole number of fuel units");
        only(units / table.compute)
    }

    /// A price is never zero for work that is not, rounds up at the
    /// rate, and never falls as the work rises.
    #[test]
    fn a_price_rounds_up_and_is_monotone() {
        let table = PriceTable::GENESIS;
        assert_eq!(table.price(&DeclaredWork::ZERO, 0), 0);
        assert_eq!(table.price(&only(1), 0), 1, "anything at all costs one");
        assert_eq!(table.price(&worth(&table, WORK_PER_QUANTUM), 0), 1);
        assert_eq!(
            table.price(&worth(&table, WORK_PER_QUANTUM + table.compute), 0),
            2
        );
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
        let work = worth(&table, 10 * WORK_PER_QUANTUM);
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

    /// A saturated epoch raises a row by an eighth, an idle one lowers
    /// it by the same, and a half-full one leaves it alone. Each row
    /// reads its own dimension and no other.
    #[test]
    fn the_controller_steps_a_row_by_its_own_dimension() {
        let bounds = PriceBounds {
            floor: PriceTable {
                compute: 1,
                read_bytes: 1,
                write_bytes: 1,
                footprint: 1,
                retention: 1,
            },
            ceiling: PriceTable {
                compute: u64::MAX,
                read_bytes: u64::MAX,
                write_bytes: u64::MAX,
                footprint: u64::MAX,
                retention: u64::MAX,
            },
        };
        let level = PriceTable {
            compute: 800,
            read_bytes: 800,
            write_bytes: 800,
            footprint: 800,
            retention: 800,
        };
        let only_compute = |used, capacity| FiveWay {
            compute: Utilization { used, capacity },
            ..FiveWay::default()
        };

        let full = level.stepped(&only_compute(100, 100), &bounds);
        assert_eq!(full.compute, 900, "a saturated row rises by an eighth");
        assert_eq!(
            (
                full.read_bytes,
                full.write_bytes,
                full.footprint,
                full.retention
            ),
            (800, 800, 800, 800),
            "a dimension with no reading holds where it is"
        );

        let idle = level.stepped(&only_compute(0, 100), &bounds);
        assert_eq!(idle.compute, 700, "an idle row falls by an eighth");

        let half = level.stepped(&only_compute(50, 100), &bounds);
        assert_eq!(half.compute, 800, "the half-full point stands still");
    }

    /// A row at rest stays at rest however many epochs pass: the
    /// half-full point divides exactly, so there is no rounding for
    /// integer division to walk a price on.
    #[test]
    fn a_row_at_the_target_does_not_drift() {
        let bounds = widened();
        let mut level = PriceTable::GENESIS;
        let steady = |cap: u64| Utilization {
            used: u128::from(cap) / 2,
            capacity: u128::from(cap),
        };
        let reading = FiveWay {
            compute: steady(1_000),
            read_bytes: steady(1_000),
            write_bytes: steady(1_000),
            footprint: steady(1_000),
            retention: steady(1_000),
        };
        for _ in 0..64 {
            level = level.stepped(&reading, &bounds);
        }
        assert_eq!(level, PriceTable::GENESIS);
    }

    /// No row is a fixed point against its own reading, however low the
    /// band a vote opened reaches.
    ///
    /// An eighth of a row under eight rounds to nothing, so rounding
    /// toward the previous level made every row at or below seven a
    /// fixed point in both directions. A floor is a basis-point scale of
    /// the reference table and compute is the smallest row there is, so
    /// a floor voted at 50 bp lands inside that range and `well_formed`
    /// accepts it — and the row would then sit at its floor forever, at
    /// any saturation, until another vote moved it.
    #[test]
    fn a_row_at_the_bottom_of_a_band_still_rises() {
        let bounds = PriceBounds::band(50, 80_000);
        assert!(bounds.well_formed(), "a floor this low is votable");
        assert!(
            bounds.floor.compute <= 7,
            "and lands where an eighth rounds to nothing: {}",
            bounds.floor.compute
        );

        let saturated = FiveWay {
            compute: Utilization {
                used: 1,
                capacity: 1,
            },
            ..FiveWay::default()
        };
        let mut level = PriceTable {
            compute: bounds.floor.compute,
            ..PriceTable::GENESIS
        };
        for _ in 0..64 {
            level = level.stepped(&saturated, &bounds);
        }
        assert!(
            level.compute > bounds.floor.compute,
            "a saturated network lifts the row off its floor, and it sat at {}",
            level.compute
        );
    }

    /// A row walks to its bound and stops there, whichever way it is
    /// driven, and never leaves the interval a vote fixed.
    #[test]
    fn a_row_stops_at_the_bound_it_reaches() {
        let bounds = widened();
        let saturated = FiveWay {
            compute: Utilization {
                used: 1,
                capacity: 1,
            },
            ..FiveWay::default()
        };
        let idle = FiveWay {
            compute: Utilization {
                used: 0,
                capacity: 1,
            },
            ..FiveWay::default()
        };
        let mut up = PriceTable::GENESIS;
        let mut down = PriceTable::GENESIS;
        for _ in 0..256 {
            up = up.stepped(&saturated, &bounds);
            down = down.stepped(&idle, &bounds);
        }
        assert_eq!(up.compute, bounds.ceiling.compute);
        assert_eq!(down.compute, bounds.floor.compute);
        assert_eq!(
            up.stepped(&saturated, &bounds).compute,
            bounds.ceiling.compute,
            "a row at its bound stays"
        );
    }

    /// An interval a vote opened, an eighth of the genesis table to
    /// eight times it: what the controller is given room to move in.
    const fn widened() -> PriceBounds {
        PriceBounds::band(BASIS_POINTS / 8, BASIS_POINTS * 8)
    }

    /// The chain is born with the controller pinned: every row's
    /// interval is a point, so no utilization moves a price until a vote
    /// opens one.
    #[test]
    fn the_genesis_bounds_hold_every_row_where_it_is() {
        let saturated = FiveWay {
            compute: Utilization {
                used: 1,
                capacity: 1,
            },
            ..FiveWay::default()
        };
        assert_eq!(
            PriceTable::GENESIS.stepped(&saturated, &PriceBounds::GENESIS),
            PriceTable::GENESIS
        );
        assert!(
            PriceTable::GENESIS.stepped(&saturated, &widened()).compute
                > PriceTable::GENESIS.compute,
            "a widened interval is what lets the controller move"
        );
    }

    /// A band is the interval a vote states, and the reference point is
    /// the genesis table: an even band pins every row, and a wider one
    /// opens every row by the same proportion.
    #[test]
    fn a_band_opens_every_row_around_the_reference() {
        assert_eq!(
            PriceBounds::band(BASIS_POINTS, BASIS_POINTS),
            PriceBounds::GENESIS
        );
        let open = PriceBounds::band(BASIS_POINTS / 2, BASIS_POINTS * 2);
        assert_eq!(open.floor.compute, PriceTable::GENESIS.compute / 2);
        assert_eq!(open.ceiling.retention, PriceTable::GENESIS.retention * 2);
        assert!(open.well_formed());
        assert!(
            !PriceBounds::band(0, BASIS_POINTS).well_formed(),
            "a band reaching zero prices a dimension at nothing"
        );
        assert!(
            !PriceBounds::band(BASIS_POINTS * 2, BASIS_POINTS).well_formed(),
            "a band whose ends cross names no level"
        );
    }

    /// Every band states itself back, so a voter moving some other row
    /// can restate the price interval instead of guessing at it.
    ///
    /// Over the figures that lose a digit on the way in as well as the
    /// round ones: compute at a thousand scales to `bp / 10`, so 1,255
    /// and 1,250 store the same compute row — and it is footprint, not
    /// compute, that has to decide the reading for both to come back.
    ///
    /// Representation and not policy, which is why the sweep starts at a
    /// band no vote could cast: one basis point floors compute at
    /// nothing, so `well_formed` refuses it and the governed parameters
    /// never carry it. It is still a band, and a reading that could not
    /// state it back would be answering a question about validity it was
    /// not asked.
    #[test]
    fn a_band_states_itself_back() {
        for bp in [1, 7, 1_250, 1_255, BASIS_POINTS, 79_999, BASIS_POINTS * 8] {
            let bounds = PriceBounds::band(bp, bp * 2);
            assert_eq!(
                bounds.as_band(),
                Some((bp, bp * 2)),
                "a band at {bp} bp must read back as the figures that opened it"
            );
        }
        assert_eq!(
            PriceBounds::GENESIS.as_band(),
            Some((BASIS_POINTS, BASIS_POINTS))
        );
    }

    /// Bounds no band could have produced answer with nothing, rather
    /// than with a figure that would move four rows to restate one.
    #[test]
    fn bounds_off_the_band_state_nothing_back() {
        let mut uneven = PriceBounds::band(BASIS_POINTS, BASIS_POINTS);
        uneven.ceiling.retention += 1;
        assert_eq!(
            uneven.as_band(),
            None,
            "a row moved off the band is not a band"
        );
        let mut unreadable = PriceBounds::GENESIS;
        unreadable.floor.footprint += 1;
        assert_eq!(
            unreadable.as_band(),
            None,
            "a footprint row between two basis points names neither"
        );
    }

    /// The bounds are what a vote decides, and a level outside them is
    /// brought in at the next fold rather than at the vote.
    #[test]
    fn the_bounds_admit_a_level_and_clamp_one_outside_them() {
        assert!(PriceBounds::GENESIS.well_formed());
        assert!(
            PriceBounds::GENESIS.inside(PriceTable::GENESIS) == PriceTable::GENESIS,
            "the genesis level sits inside the genesis bounds"
        );
        let free = PriceBounds {
            floor: PriceTable {
                compute: 0,
                ..PriceTable::GENESIS
            },
            ceiling: widened().ceiling,
        };
        assert!(
            !free.well_formed(),
            "a free dimension is bounded by nothing"
        );
        let crossed = PriceBounds {
            floor: widened().ceiling,
            ceiling: widened().floor,
        };
        assert!(!crossed.well_formed());
    }
}
