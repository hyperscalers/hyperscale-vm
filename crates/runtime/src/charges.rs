//! The derived instantiation charge sequence.
//!
//! Instantiating a component is metered work: under the blessed config the
//! engine compiles one init function per core module that needs one — any
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

use crate::frames::{InstanceDef, instance_def};
use crate::validator::ProfileError;

/// The ordered charges instantiating an artifact costs, derived from its
/// bytes alone.
///
/// Per instantiated core module, in the component's core-instantiation
/// order (a multiply-instantiated module counted each time, a
/// never-instantiated one not at all): an entry charge of one iff the
/// module has init work, then one plus the byte length per active data
/// segment, in section order. Replayed charge-then-check against a
/// budget, the arithmetic is bit-identical to metering the work — the
/// residue of a budget that dies mid-instantiation included.
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

/// Derives the instantiation charges of a component artifact.
///
/// # Errors
///
/// [`ProfileError`] if the bytes do not parse; verdicts are deterministic
/// functions of the bytes.
pub fn instantiation_charges(bytes: &[u8]) -> Result<InstantiationCharges, ProfileError> {
    let mut modules: Vec<SegmentFacts> = Vec::new();
    let mut charges = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| ProfileError::Feature(e.to_string()))?;
        match payload {
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                modules.push(segment_facts(&bytes[unchecked_range])?);
            }
            Payload::InstanceSection(reader) => {
                for instance in reader {
                    let instance = instance.map_err(|e| ProfileError::Feature(e.to_string()))?;
                    if let InstanceDef::Instantiate { module, .. } = instance_def(&instance)? {
                        let facts = modules.get(module as usize).ok_or_else(|| {
                            ProfileError::Structural(
                                "core instance names an undefined module".to_string(),
                            )
                        })?;
                        push_module_charges(facts, &mut charges);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(InstantiationCharges { charges })
}

/// Derives the instantiation charges of one bare core module: the
/// one-instance case of [`instantiation_charges`], which is what the
/// differential lanes drive.
///
/// # Errors
///
/// [`ProfileError`] if the bytes do not parse.
pub fn module_instantiation_charges(bytes: &[u8]) -> Result<InstantiationCharges, ProfileError> {
    let facts = segment_facts(bytes)?;
    let mut charges = Vec::new();
    push_module_charges(&facts, &mut charges);
    Ok(InstantiationCharges { charges })
}

/// What the derivation reads off one core module.
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

/// One module's charges: the init-function entry iff the module has any,
/// then each data segment's application.
fn push_module_charges(facts: &SegmentFacts, charges: &mut Vec<u64>) {
    let inits_imported_table = facts.has_active_elements && !facts.declares_table;
    if !facts.data_lens.is_empty() || inits_imported_table {
        charges.push(1);
    }
    for len in &facts.data_lens {
        charges.push(1 + len);
    }
}
