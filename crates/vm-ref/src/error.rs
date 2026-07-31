//! Decode errors and execution traps.

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
    /// frame bound proves the heaviest call chain fits the native stack,
    /// and this counter sits far above it. The differential lanes treat
    /// reaching it as a failure of that bound rather than as a divergence
    /// to excuse.
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
