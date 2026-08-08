//! What a transaction costs, priced into a single scalar — before it runs
//! from what it declared, and after it runs from what it did.
//!
//! Fuel already folds heterogeneous costs — instructions, memory, calls —
//! into one number by a fixed schedule. Declaration footprint is another
//! priced dimension of the same kind, so the combine belongs beside the
//! rest of the schedule rather than at the consumer. The weight relating
//! the two only means anything against the weights inside fuel itself, and
//! splitting it from the schedule that set them would let the two drift
//! with nothing to catch it.
//!
//! Both sides of that quantity are priced here for the same reason. An
//! embedder admits a transaction against what it *declares* — a footprint
//! it computed and a fuel ceiling its sender signed — and settles it
//! against what the execution *attested*. Those two numbers bound each
//! other, so they have to be read off one set of weights: a declared
//! figure computed at the consumer would answer a fuel-weight change by
//! staying where it was.
//!
//! Fuel is not always the right term to pass. A declaration is admitted,
//! routed, and locked in full whatever the verdict, but fuel is
//! outcome-dependent — and worse, engine-defined at a core trap, where
//! wasmtime's in-register counter never flushes and `vm-ref` charges every
//! executed operator. An aborted execution therefore attests its footprint
//! alone; `vm_kernel`'s receipt constructor is where that rule is applied,
//! because the outcome is what selects it and the outcome lives there.
//!
//! Placeholder weights, on the same terms as [`crate::footprint`]'s: what
//! one unit costs is set against measured baselines rather than chosen
//! here. Which end of the ratio fails is worth knowing before calibrating —
//! fuel runs at engine-schedule magnitude while footprint peaks in the low
//! hundreds per effect, so at an even weighting fuel dominates and
//! footprint is visible mainly where fuel is near zero. That is the
//! cross-shard counterpart case this quantity exists to price, so an even
//! weighting is not useless — but it is the wrong way round if declaration
//! cost is meant to lead.
//!
//! Saturating throughout. The consumer accumulates these into a per-chain
//! running total, where a wrapped value reads as a shard that did almost
//! nothing — the one failure mode that looks like ordinary data rather
//! than like an error.

/// Work units charged per unit of consumed fuel.
pub const FUEL_WEIGHT: u64 = 1;

/// Work units charged per unit of declared footprint.
pub const FOOTPRINT_WEIGHT: u64 = 1;

/// Work units charged for carrying one transaction at all, before
/// anything it declares.
///
/// The two weights above price what a transaction asks for, and both
/// terms can be near zero: a minimal declaration prices at almost
/// nothing and a signed fuel ceiling may be zero outright. What such a
/// transaction still costs is a place in every structure that tracks it
/// one-per-transaction, and that cost scales with the count rather than
/// with the ask. Without this term a budget over work would bound weight
/// while the number ran free, which is the direction a flood of trivial
/// envelopes takes.
///
/// Sized against [`FUEL_WEIGHT`] and the largest ceiling an embedder
/// admits, not chosen apart from them: it is what keeps the count and
/// the weight a bounded factor from each other, so an embedder's own
/// ceiling has to be picked against this value. A placeholder like the
/// weights beside it.
pub const TX_UNITS: u64 = 1_000_000;

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

/// The work a transaction declares before it runs: the fixed carry
/// charge, the footprint it claims, and the fuel ceiling it signed.
///
/// The ceiling enters at [`FUEL_WEIGHT`] because that is what the fuel
/// it stands for will cost — so this bounds the [`work_units`] the same
/// transaction can go on to attest, which is what lets an embedder hold
/// a reservation against it and release the reservation later without
/// the two figures being measured differently.
///
/// `gas_limit` is the sender's own number and is bounded by the
/// embedder, not here; a ceiling large enough to saturate this is one
/// the embedder should already have refused.
#[must_use]
pub const fn declared_work(footprint: u64, gas_limit: u64) -> u64 {
    TX_UNITS
        .saturating_add(FOOTPRINT_WEIGHT.saturating_mul(footprint))
        .saturating_add(FUEL_WEIGHT.saturating_mul(gas_limit))
}

#[cfg(test)]
mod tests {
    use super::{FOOTPRINT_WEIGHT, FUEL_WEIGHT, TX_UNITS, declared_work, work_units};

    #[test]
    fn a_declaration_costs_something_whatever_it_asks_for() {
        // The term the count bound rests on: a transaction declaring
        // nothing and signing a zero ceiling still costs a place in every
        // structure that holds one entry per transaction.
        assert_eq!(declared_work(0, 0), TX_UNITS);
        assert!(declared_work(0, 0) > 0);
    }

    #[test]
    fn declared_work_is_monotone_in_both_asks() {
        // Asking for more never declares less, so no sender lowers what
        // it reserved by widening what it claims.
        for footprint in [0, 1, 1_000, u64::from(u32::MAX)] {
            for gas in [0, 1, 1_000, u64::from(u32::MAX)] {
                assert!(declared_work(footprint + 1, gas) >= declared_work(footprint, gas));
                assert!(declared_work(footprint, gas + 1) >= declared_work(footprint, gas));
            }
        }
    }

    #[test]
    fn a_declaration_covers_the_work_its_execution_can_attest() {
        // The property an embedder's reserve-then-release depends on:
        // whatever the execution goes on to attest, the figure taken at
        // admission was at least that — so the release cannot exceed the
        // reservation and a running total cannot drift below zero. Fuel
        // is capped by the signed ceiling and footprint is the same
        // declaration on both sides.
        for footprint in [0, 1, 640, 100_000] {
            for gas in [0, 1, 50_000, 1_000_000] {
                for burned in [0, gas / 2, gas] {
                    assert!(
                        declared_work(footprint, gas) >= work_units(burned, footprint),
                        "declared {} < attested {} at footprint {footprint}, gas {gas}",
                        declared_work(footprint, gas),
                        work_units(burned, footprint),
                    );
                }
            }
        }
    }

    #[test]
    fn the_declared_ceiling_reads_as_the_ceiling() {
        // Saturating like its counterpart: a declaration at the top pins
        // rather than wrapping to something an embedder would admit.
        assert_eq!(declared_work(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(declared_work(u64::MAX, 0), u64::MAX);
    }

    #[test]
    fn both_components_are_priced() {
        // Neither term is silently dropped: moving either one alone moves
        // the total. A weight set to zero would make one half of the
        // quantity unobservable, which is the failure the components on
        // the receipt exist to make visible.
        assert!(work_units(1, 0) > work_units(0, 0));
        assert!(work_units(0, 1) > work_units(0, 0));
    }

    #[test]
    fn work_is_monotone_in_both_components() {
        // Doing more never attests less, on either axis independently.
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
        // quantity, which is the whole point of R1.
        let footprint = 640;
        assert_eq!(
            work_units(0, footprint),
            FOOTPRINT_WEIGHT.saturating_mul(footprint)
        );
        assert!(work_units(0, footprint) > 0);
    }

    #[test]
    fn the_ceiling_reads_as_the_ceiling() {
        // Never wraps: at the top the total pins rather than restarting
        // near zero, so a saturated shard cannot read as an idle one.
        assert_eq!(work_units(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(work_units(u64::MAX, 1), u64::MAX);
        assert_eq!(FUEL_WEIGHT.saturating_mul(u64::MAX), u64::MAX);
    }
}
