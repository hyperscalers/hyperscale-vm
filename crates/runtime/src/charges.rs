//! The derived instantiation charge sequence.
//!
//! Instantiating a module is metered work: under the blessed config the
//! engine compiles an init function where the module needs one — any
//! active data segment forces it, as do element segments applying to an
//! imported table — and that function meters like guest code: entry one
//! fuel, each active data segment one plus one per byte, element writes
//! free. The consensus fuel schedule cannot be an engine's internal
//! behavior, so the same arithmetic is derived here from the artifact's
//! bytes — content-addressed, so every node derives the identical
//! sequence — and a blessed embedder replays the sequence against the
//! budget instead of metering the work. vm-ref keeps charging
//! incrementally as it applies segments, so the differential fuel lanes
//! check this derivation against an independently maintained model.

use wasmparser::{DataKind, ElementKind, Parser, Payload};
#[cfg(feature = "engine")]
use wasmtime::{Result, Store, Trap};

use crate::validator::ProfileError;

/// The ordered charges instantiating an artifact costs, derived from its
/// bytes alone.
///
/// An entry charge of one iff the module has init work, then one plus the
/// byte length per active data segment, in section order. Replayed
/// charge-then-check against a budget, the arithmetic is bit-identical to
/// metering the work — the residue of a budget that dies
/// mid-instantiation included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstantiationCharges {
    charges: Vec<u64>,
}

impl InstantiationCharges {
    /// The ordered charge list.
    #[must_use]
    pub fn charges(&self) -> &[u64] {
        &self.charges
    }

    /// The whole sequence as one number: what instantiating the artifact
    /// costs an ample budget.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.charges.iter().sum()
    }
}

/// Derives the instantiation charges of a module.
///
/// # Errors
///
/// [`ProfileError`] if the bytes do not parse; verdicts are deterministic
/// functions of the bytes.
pub fn instantiation_charges(bytes: &[u8]) -> Result<InstantiationCharges, ProfileError> {
    let facts = segment_facts(bytes)?;
    let inits_imported_table = facts.has_active_elements && !facts.declares_table;
    let mut charges = Vec::new();
    if !facts.data_lens.is_empty() || inits_imported_table {
        charges.push(1);
    }
    for len in &facts.data_lens {
        charges.push(1 + len);
    }
    Ok(InstantiationCharges { charges })
}

/// Instantiates a module charging the derived sequence in place of the
/// engine's own accounting.
///
/// The charge list is replayed charge-then-check against `budget` first —
/// the order both engines charge in — so an under-budget call refuses
/// before any instantiation work happens, with exactly the residue
/// metering the work would have left: an exhaustion trap reports nothing
/// remaining, so the whole budget is spent. The instantiation itself then
/// runs under sentinel fuel, making the engine's internal accounting
/// invisible, and the store is left holding `budget` minus the replayed
/// charges for the call that follows.
///
/// # Errors
///
/// [`Trap::OutOfFuel`] when the budget dies in the replay; otherwise
/// whatever `instantiate` itself returns.
#[cfg(feature = "engine")]
pub fn instantiate_charged<T, I, F>(
    store: &mut Store<T>,
    budget: u64,
    charges: &InstantiationCharges,
    instantiate: F,
) -> Result<I>
where
    F: FnOnce(&mut Store<T>) -> Result<I>,
{
    let mut spent = 0u64;
    for &charge in charges.charges() {
        spent = spent.saturating_add(charge);
        if spent >= budget {
            store.set_fuel(0)?;
            return Err(Trap::OutOfFuel.into());
        }
    }
    store.set_fuel(u64::MAX)?;
    let instance = instantiate(store)?;
    store.set_fuel(budget - spent)?;
    Ok(instance)
}

/// What the derivation reads off a module.
#[derive(Default)]
struct SegmentFacts {
    /// Whether the module declares its own table; a local table's element
    /// segments are precomputed host-side, so they cost nothing.
    declares_table: bool,
    /// Whether any active element segment exists.
    has_active_elements: bool,
    /// Active data segment byte lengths, in section order.
    data_lens: Vec<u64>,
}

fn segment_facts(bytes: &[u8]) -> Result<SegmentFacts, ProfileError> {
    let mut facts = SegmentFacts::default();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::TableSection(reader) => {
                facts.declares_table = facts.declares_table || reader.count() > 0;
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    let element = element.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if matches!(element.kind, ElementKind::Active { .. }) {
                        facts.has_active_elements = true;
                    }
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if matches!(data.kind, DataKind::Active { .. }) {
                        facts.data_lens.push(data.data.len() as u64);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(facts)
}
