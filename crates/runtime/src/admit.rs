//! Admission: the one sequence that turns an author's bytes into the
//! module a node runs.
//!
//! Profile validation over the author's bytes, the meter's pass, and the
//! stack bound over what the pass produced — in that order, once, for
//! every caller. The gate calls it to judge, both engines call it to
//! load, and what they hold afterwards is the same instrumented module
//! byte for byte, because the pass is a function of its input.
//!
//! The bound counts the code that runs. The pass adds a local and two
//! operand slots to a function, and a walk over the author's bytes would
//! be trusting a margin to absorb them; the walk here judges the
//! instrumented module. The author's bytes are still walked first, as
//! part of the profile verdict, so a refusal names the author's chain
//! rather than one the pass made heavier.

use hyperscale_vm_meter::{PassError, instrument};

use crate::frames::check_stack_bounds;
use crate::validator::{ProfileError, validate_core_module, validate_module};

/// Admit a module the kernel calls directly, answering the bytes to run.
///
/// # Errors
///
/// [`ProfileError`]: the author's bytes are outside the profile or the
/// boundary convention, or the instrumented module does not fit the
/// stack bound.
pub fn admit(bytes: &[u8]) -> Result<Vec<u8>, ProfileError> {
    validate_module(bytes)?;
    metered(bytes)
}

/// Admit a bare core module — no boundary convention, imports and
/// exports as the author likes — answering the bytes to run.
///
/// What the differential lanes run their hand and generated corpora
/// through: the same pass and the same bound, over modules that never
/// meet the kernel.
///
/// # Errors
///
/// [`ProfileError`]: the author's bytes are outside the profile, or the
/// instrumented module does not fit the stack bound.
pub fn admit_core_module(bytes: &[u8]) -> Result<Vec<u8>, ProfileError> {
    validate_core_module(bytes)?;
    metered(bytes)
}

fn metered(bytes: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let instrumented = instrument(bytes).map_err(|error| match error {
        PassError::Malformed(what) => ProfileError::Feature(what),
        PassError::Reserved(what) => ProfileError::Structural(format!("the module {what}")),
    })?;
    check_stack_bounds(&instrumented)?;
    Ok(instrumented)
}
