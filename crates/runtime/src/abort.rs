//! The blessed engine's failures as the protocol's abort classes.
//!
//! An invocation can fail four ways: the guest traps, the boundary
//! refuses, a host operation returns its own refusal, or the call itself
//! does not fit the export convention. Each arrives as a
//! [`wasmtime::Error`], and [`classify`] is the one place they become an
//! [`AbortReason`] — so an embedder never words a failure and every
//! embedder classifies one the same way. Exhaustion is a host refusal
//! like any other: the meter's `exhaust` and a boundary charge the
//! counter cannot cover both answer out of gas, and no engine trap
//! means it.
//!
//! The reference interpreter's [`abort_reason`](hyperscale_vm_types) arms
//! must agree with these one for one. Nothing here checks that; the
//! differential lanes do, by comparing whole outcomes.

use hyperscale_vm_embed::meter::MeterError;
use hyperscale_vm_types::AbortReason;
use wasmtime::{Error, Trap};

/// A kernel refusal in flight through the engine.
///
/// The class rides the error rather than its text: [`classify`] downcasts
/// it back out, so nothing on the path from the kernel's verdict to the
/// receipt's abort record passes through prose.
#[derive(Debug, thiserror::Error)]
#[error("kernel refusal: {0:?}")]
pub struct HostRefusal(pub AbortReason);

/// A host refusal as an engine trap, with its class recoverable.
pub(crate) fn host_trap(reason: AbortReason) -> Error {
    Error::new(HostRefusal(reason))
}

/// A metered failure as an engine error, its class recoverable.
pub(crate) fn fault(error: MeterError) -> Error {
    match error {
        MeterError::Exhausted => host_trap(AbortReason::OutOfGas),
        MeterError::Refused(reason) => host_trap(reason),
    }
}

/// An invocation the export convention does not admit.
///
/// Not a guest trap: the module answered, and what came back is not
/// what a package's own ABI binding says its exports produce.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The module exports no function of the invoked name.
    #[error("module exports no function `{0}`")]
    ExportMissing(String),
    /// A result outside the call convention: a method ends with the
    /// edges it produced, a declined code, or nothing.
    #[error("`{export}` returned {found}, not edges or a decline")]
    BadReturnShape {
        /// The invoked export.
        export: String,
        /// What it returned instead, for the log.
        found: String,
    },
}

impl CallError {
    /// This failure as the protocol's abort class.
    #[must_use]
    pub const fn abort_reason(&self) -> AbortReason {
        match self {
            Self::ExportMissing(_) => AbortReason::ExportMissing,
            Self::BadReturnShape { .. } => AbortReason::BadReturnShape,
        }
    }
}

/// A wasm trap as the protocol's abort class.
///
/// The profile validator admits a subset in which the arms below are the
/// reachable traps; everything else is a defect in the profile rather
/// than a guest's, and [`AbortReason::TrapOutsideProfile`] keeps the
/// classification total without reopening a free-form one.
#[must_use]
pub const fn trap_reason(trap: Trap) -> AbortReason {
    match trap {
        Trap::UnreachableCodeReached => AbortReason::Unreachable,
        Trap::IntegerDivisionByZero => AbortReason::IntegerDivideByZero,
        Trap::IntegerOverflow => AbortReason::IntegerOverflow,
        Trap::MemoryOutOfBounds => AbortReason::MemoryOutOfBounds,
        Trap::TableOutOfBounds => AbortReason::TableOutOfBounds,
        Trap::IndirectCallToNull => AbortReason::IndirectCallToNull,
        Trap::BadSignature => AbortReason::IndirectCallSignature,
        Trap::StackOverflow => AbortReason::StackExhausted,
        _ => AbortReason::TrapOutsideProfile,
    }
}

/// An engine error as the protocol's abort class.
///
/// A host refusal carries its own class and keeps it. A trap maps through
/// [`trap_reason`]. A convention failure maps through [`CallError`].
/// What is left is the engine refusing a call outside the boundary —
/// an argument list the export's type does not take — which the
/// interpreter reports the same way.
#[must_use]
pub fn classify(error: &Error) -> AbortReason {
    if let Some(refusal) = error.downcast_ref::<HostRefusal>() {
        return refusal.0;
    }
    if let Some(trap) = error.downcast_ref::<Trap>() {
        return trap_reason(*trap);
    }
    if let Some(call) = error.downcast_ref::<CallError>() {
        return call.abort_reason();
    }
    AbortReason::AbiViolation
}
