//! What one execution attests it did: consumed fuel and declared
//! footprint, priced into a single scalar.
//!
//! Fuel already folds heterogeneous costs — instructions, memory, calls —
//! into one number by a fixed schedule. Declaration footprint is another
//! priced dimension of the same kind, so the combine belongs beside the
//! rest of the schedule rather than at the consumer. The weight relating
//! the two only means anything against the weights inside fuel itself, and
//! splitting it from the schedule that set them would let the two drift
//! with nothing to catch it.
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

#[cfg(test)]
mod tests {
    use super::{FOOTPRINT_WEIGHT, FUEL_WEIGHT, work_units};

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
