//! Decode errors and execution traps.

use hyperscale_vm_types::AbortReason;
use thiserror::Error;

/// A module the interpreter cannot decode. The profile validator admits a
/// strict subset of wasm; anything outside it is rejected here as defense in
/// depth, deterministically.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Malformed binary.
    #[error("malformed module: {0}")]
    Malformed(String),
    /// An operator outside the profile subset.
    #[error("operator outside the profile subset: {0}")]
    UnsupportedOp(String),
    /// A type outside the profile subset (floats, vectors, references in
    /// value position).
    #[error("type outside the profile subset")]
    UnsupportedType,
    /// A structure the interpreter does not model (imports in a bare core
    /// module, multiple memories, passive segments).
    #[error("unsupported structure: {0}")]
    Unsupported(String),
    /// The named export does not exist or is not a function.
    #[error("no such function export: {0}")]
    NoSuchExport(String),
    /// Invocation arguments do not match the function's parameters.
    #[error("argument mismatch")]
    ArgumentMismatch,
}

/// Why a component did not instantiate: the artifact would not decode,
/// or core instantiation trapped — an out-of-bounds active segment, or
/// a budget that died while segments were applied.
///
/// The trap arm is what makes exhaustion recognizable at this seam: an
/// embedder maps [`Trap::OutOfFuel`] here to the sender's own
/// deterministic abort, and everything else to a refused artifact.
#[derive(Debug, Error)]
pub enum InstantiateError {
    /// The artifact would not decode.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// Core instantiation trapped.
    #[error("instantiation trapped: {0}")]
    Trap(Trap),
}

/// An execution trap. Variants mirror the trap kinds the blessed engine
/// reports, so the differential harness compares them directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Trap {
    /// `unreachable` executed.
    #[error("unreachable")]
    Unreachable,
    /// Integer division or remainder by zero.
    #[error("integer divide by zero")]
    IntegerDivisionByZero,
    /// `INT_MIN / -1` style overflow.
    #[error("integer overflow")]
    IntegerOverflow,
    /// Out-of-bounds linear memory access.
    #[error("out of bounds memory access")]
    MemoryOutOfBounds,
    /// Out-of-bounds table access.
    #[error("out of bounds table access")]
    TableOutOfBounds,
    /// `call_indirect` through a null table entry.
    #[error("indirect call to null")]
    IndirectCallToNull,
    /// `call_indirect` signature mismatch.
    #[error("indirect call signature mismatch")]
    BadSignature,
    /// The interpreter's own call-depth bound.
    ///
    /// Unreachable for an artifact the profile admits: the deploy-time
    /// frame bound caps the deepest admissible chain at half this counter,
    /// and a `vm-harness` assertion holds the two in that order. Recursion
    /// through the canonical-ABI boundary is out of reach separately — the
    /// ABI's re-entrance rule refuses it here, and the profile refuses the
    /// shape that expresses it. The differential lanes treat reaching this
    /// counter as a failure of those bounds rather than as a divergence to
    /// excuse.
    #[error("call depth exhausted")]
    CallDepthExhausted,
    /// The fuel budget ran out. Charged on the spec schedule and tested
    /// at the three points the engine tests its own — function entry,
    /// loop header, and the bulk-op byte charge — so the verdict is
    /// shared rather than engine-defined.
    #[error("all fuel consumed by WebAssembly")]
    OutOfFuel,
    /// The optional step budget ran out — a harness safety valve for
    /// generated corpora, never a consensus verdict.
    #[error("step budget exhausted")]
    StepBudgetExhausted,
}

impl Trap {
    /// This trap as the protocol's abort class.
    ///
    /// The blessed engine's own mapping must agree arm for arm; the
    /// differential lanes compare the resulting outcomes rather than the
    /// trap kinds, which is what checks that it does.
    ///
    /// # Panics
    ///
    /// On [`Trap::StepBudgetExhausted`], which is a harness valve rather
    /// than an execution verdict and reaches no receipt.
    #[must_use]
    pub const fn abort_reason(self) -> AbortReason {
        match self {
            Self::Unreachable => AbortReason::Unreachable,
            Self::IntegerDivisionByZero => AbortReason::IntegerDivideByZero,
            Self::IntegerOverflow => AbortReason::IntegerOverflow,
            Self::MemoryOutOfBounds => AbortReason::MemoryOutOfBounds,
            Self::TableOutOfBounds => AbortReason::TableOutOfBounds,
            Self::IndirectCallToNull => AbortReason::IndirectCallToNull,
            Self::BadSignature => AbortReason::IndirectCallSignature,
            Self::CallDepthExhausted => AbortReason::StackExhausted,
            Self::OutOfFuel => AbortReason::OutOfGas,
            Self::StepBudgetExhausted => {
                panic!("the step budget is a harness valve, never an execution verdict")
            }
        }
    }
}
