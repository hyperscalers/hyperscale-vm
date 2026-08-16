//! The blessed engine's failures as the protocol's abort classes.
//!
//! An invocation can fail four ways: the guest traps, the canonical ABI
//! refuses, a host operation returns its own refusal, or the call itself
//! does not fit the export convention. Each arrives as a
//! [`wasmtime::Error`], and [`classify`] is the one place they become an
//! [`AbortReason`] — so an embedder never words a failure and every
//! embedder classifies one the same way.
//!
//! The reference interpreter's [`abort_reason`](hyperscale_vm_types) arms
//! must agree with these one for one. Nothing here checks that; the
//! differential lanes do, by comparing whole outcomes.

use hyperscale_vm_types::AbortReason;
use wasmtime::{Error, Trap};

use crate::world::HostRefusal;

/// An invocation the export convention does not admit.
///
/// Not a guest trap: the component answered, and what came back is not
/// what a package's own ABI binding says its exports produce.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The component exports no function of the invoked name.
    #[error("component exports no function `{0}`")]
    ExportMissing(String),
    /// A result that is not the single byte list the convention fixes.
    #[error("`{export}` returned {found}, not a byte list")]
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
        Trap::OutOfFuel => AbortReason::OutOfGas,
        Trap::CannotEnterComponent => AbortReason::AbiViolation,
        _ => AbortReason::TrapOutsideProfile,
    }
}

/// An engine error as the protocol's abort class.
///
/// A host refusal carries its own class and keeps it. A trap maps through
/// [`trap_reason`]. A convention failure maps through [`CallError`].
/// What is left is the canonical ABI refusing at the component boundary
/// without resolving to a trap kind, which the interpreter reports the
/// same way and which is why [`AbortReason::AbiViolation`] is one variant
/// rather than four.
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

/// Whether an engine error is fuel exhaustion.
///
/// Read from the engine's own classification rather than inferred from
/// the fuel left: a trap that happens to land on an exhausted counter is
/// a different outcome from one caused by it, and two runtimes
/// disagreeing here is two nodes disagreeing on what a transaction pays.
#[must_use]
pub fn exhausted(error: &Error) -> bool {
    matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel))
}
